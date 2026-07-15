import { once } from "node:events"
import { AddressInfo } from "node:net"
import Client from "../../src/Client.js"
import ClientSessionChannel from "../../src/channels/ClientSessionChannel.js"
import ClientForwardedTCPIPChannel from "../../src/channels/ClientForwardedTCPIPChannel.js"
import SessionChannel from "../../src/channels/SessionChannel.js"
import { SSHAuthenticationMethods } from "../../src/constants.js"
import Server from "../../src/Server.js"
import type ServerClient from "../../src/ServerClient.js"
import ChannelOpen from "../../src/packets/ChannelOpen.js"
import ChannelOpenConfirmation from "../../src/packets/ChannelOpenConfirmation.js"
import ChannelOpenFailure, {
    ChannelOpenError,
    ChannelOpenFailureReasonCodes,
} from "../../src/packets/ChannelOpenFailure.js"
import ChannelWindowAdjust from "../../src/packets/ChannelWindowAdjust.js"
import { DisconnectReason, type PeerDisconnectInfo } from "../../src/packets/Disconnect.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

async function createConnectedPeers(
    options: {
        serverMaxPendingChannelOpens?: number
        clientMaxPendingChannelOpens?: number
        serverMaxChannels?: number
        clientMaxChannels?: number
    } = {},
): Promise<{
    server: Server
    peer: ServerClient
    client: Client
}> {
    const hostKey = await PrivateKey.generate("ssh-ed25519")
    const server = new Server({
        hostKeys: [hostKey],
        sendAllHostKeys: false,
        maxPendingChannelOpens: options.serverMaxPendingChannelOpens,
        maxChannels: options.serverMaxChannels,
    })
    server.hooker.hook("noneAuthentication", async (_hook, _context, controller) => {
        controller.allowLogin = true
    })
    let peer: ServerClient | undefined
    server.on("connection", (connection) => {
        peer = connection
        connection.on("error", () => undefined)
    })
    server.listen({ host: "127.0.0.1", port: 0 })
    await new Promise<void>((resolve) => server.server!.once("listening", resolve))

    const client = new Client({
        hostname: "127.0.0.1",
        port: (server.address() as AddressInfo).port,
        username: "channel-identifier-test",
        authenticationMethodsOrder: [SSHAuthenticationMethods.None],
        maxPendingChannelOpens: options.clientMaxPendingChannelOpens,
        maxChannels: options.clientMaxChannels,
    })
    client.hooker.hook("hostKey", async (_hook, controller) => {
        controller.allowHostKey = true
    })
    await client.connect()
    return { server, peer: peer!, client }
}

async function closePeers(server: Server, client: Client): Promise<void> {
    client.destroy()
    for (const peer of server.clients) peer.terminate()
    await server.close()
}

function nextDisconnect(peer: Client | ServerClient): Promise<Readonly<PeerDisconnectInfo>> {
    return new Promise((resolve) => peer.once("disconnect", resolve))
}

describe("RFC 4254 channel identifiers", () => {
    test("validates application-created channel rejection metadata", () => {
        expect(() => new ChannelOpenError(-1, "invalid reason")).toThrow(
            "SSH channel-open failure reason must be a uint32",
        )
        expect(() => new ChannelOpenError(1, "\ud800")).toThrow(
            "SSH channel-open description is not valid UTF-8 text",
        )
        expect(() => new ChannelOpenError(1, "maintenance", "en_US")).toThrow(
            "SSH channel-open language tag is not valid RFC 3066",
        )
    })

    test("publishes a localized private-use channel rejection from async policy", async () => {
        const { server, peer, client } = await createConnectedPeers()
        server.hooker.hook("channelOpenRequest", async (_hook, _channel, controller) => {
            await Promise.resolve()
            controller.rejection = new ChannelOpenError(0xfe00_0001, "canal indisponible", "fr")
        })

        try {
            await expect(client.openSession()).rejects.toMatchObject({
                name: "ChannelOpenError",
                reasonCode: 0xfe00_0001,
                reason_code: 0xfe00_0001,
                message: "canal indisponible",
                languageTag: "fr",
            })
            expect(client.isConnected).toBe(true)
        } finally {
            await closePeers(server, client)
            peer.terminate()
        }
    }, 15_000)

    test("does not confirm a server channel aborted during admission policy", async () => {
        const { server, peer, client } = await createConnectedPeers()
        let published = false
        peer.on("channel", () => {
            published = true
        })
        server.hooker.hook("channelOpenRequest", async (_hook, channel) => {
            await Promise.resolve()
            channel.abort()
        })
        server.hooker.hook("channelOpenRequest", (_hook, _channel, controller) => {
            controller.allowOpen = true
        })

        try {
            await expect(client.openSession()).rejects.toMatchObject({
                reasonCode: ChannelOpenFailureReasonCodes.SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
                message: "Opening channel type not allowed by the server.",
            })
            expect(published).toBe(false)
            expect(client.isConnected).toBe(true)
        } finally {
            await closePeers(server, client)
            peer.terminate()
        }
    }, 15_000)

    async function openSession(server: Server, peer: ServerClient, client: Client) {
        server.hooker.hook("channelOpenRequest", async (_hook, _channel, controller) => {
            controller.allowOpen = true
        })
        peer.on("channel", (channel) => {
            if (!(channel instanceof SessionChannel)) return
            channel.hooker.hook("execRequest", async (_hook, _context, controller) => {
                controller.success = true
            })
        })
        return client.exec("flow-control-test")
    }

    test("allows an identifier to be reused after both channel closes", async () => {
        const { server, peer, client } = await createConnectedPeers()
        server.hooker.hook("channelOpenRequest", async (_hook, _channel, controller) => {
            controller.allowOpen = true
        })
        peer.on("channel", (channel) => {
            if (!(channel instanceof SessionChannel)) return
            channel.hooker.hook("execRequest", async (_hook, _context, controller) => {
                controller.success = true
            })
        })

        try {
            const first = await client.exec("first")
            const reusedId = first.localId
            const firstClosed = new Promise<void>((resolve) => first.once("close", resolve))
            first.close()
            await firstClosed

            client.localChannelIndex = reusedId
            const second = await client.exec("second")
            expect(second.localId).toBe(reusedId)
            const secondClosed = new Promise<void>((resolve) => second.once("close", resolve))
            second.close()
            await secondClosed
        } finally {
            await closePeers(server, client)
        }
    }, 15_000)

    test("bounds server channel-open policy waits without closing the connection", async () => {
        const { server, peer, client } = await createConnectedPeers({
            serverMaxPendingChannelOpens: 1,
        })
        let releasePolicy!: () => void
        const policyReleased = new Promise<void>((resolve) => {
            releasePolicy = resolve
        })
        let reportPolicy!: () => void
        const policyStarted = new Promise<void>((resolve) => {
            reportPolicy = resolve
        })
        let policyCalls = 0
        server.hooker.hook("channelOpenRequest", async (_hook, _channel, controller) => {
            policyCalls++
            reportPolicy()
            await policyReleased
            controller.allowOpen = true
        })

        try {
            const first = client.openSession()
            await policyStarted
            await expect(client.openSession()).rejects.toMatchObject({
                reason_code: ChannelOpenFailureReasonCodes.SSH_OPEN_RESOURCE_SHORTAGE,
                message: "Too many SSH channel opens are awaiting decisions",
            })
            expect(policyCalls).toBe(1)
            expect(client.isConnected).toBe(true)

            releasePolicy()
            const channel = await first
            const closed = once(channel, "close")
            channel.close()
            await closed
        } finally {
            releasePolicy()
            await closePeers(server, client)
            peer.terminate()
        }
    }, 15_000)

    test("validates pending channel-open limits in both roles", () => {
        for (const maxPendingChannelOpens of [
            -1,
            0.5,
            Number.NaN,
            Number.POSITIVE_INFINITY,
            Number.MAX_SAFE_INTEGER + 1,
        ]) {
            expect(() => new Client({ maxPendingChannelOpens })).toThrow(
                "SSH maximum pending channel opens must be a non-negative safe integer",
            )
            expect(() => new Server({ maxPendingChannelOpens })).toThrow(
                "SSH maximum pending channel opens must be a non-negative safe integer",
            )
        }
    })

    test("validates simultaneous channel limits in both roles", () => {
        for (const maxChannels of [
            -1,
            0.5,
            Number.NaN,
            Number.POSITIVE_INFINITY,
            Number.MAX_SAFE_INTEGER + 1,
        ]) {
            expect(() => new Client({ maxChannels })).toThrow(
                "SSH maximum simultaneous channels must be a non-negative safe integer",
            )
            expect(() => new Server({ maxChannels })).toThrow(
                "SSH maximum simultaneous channels must be a non-negative safe integer",
            )
        }
    })

    test("client rejects a local open at capacity before invoking server policy", async () => {
        const { server, peer, client } = await createConnectedPeers({ clientMaxChannels: 1 })
        let policyCalls = 0
        server.hooker.hook("channelOpenRequest", (_hook, channel, controller) => {
            policyCalls++
            controller.allowOpen = channel instanceof SessionChannel
        })

        try {
            const first = await client.openSession()
            expect(policyCalls).toBe(1)
            await expect(client.openSession()).rejects.toMatchObject({
                name: "ChannelOpenError",
                reasonCode: ChannelOpenFailureReasonCodes.SSH_OPEN_RESOURCE_SHORTAGE,
                message: "SSH simultaneous channel limit of 1 reached",
            })
            expect(policyCalls).toBe(1)

            const closed = once(first, "close")
            first.close()
            await closed
        } finally {
            await closePeers(server, client)
            peer.terminate()
        }
    }, 15_000)

    test("server rejects a local open at capacity before invoking client policy", async () => {
        const { server, peer, client } = await createConnectedPeers({ serverMaxChannels: 1 })
        server.hooker.hook("tcpipForward", (_hook, _context, controller) => {
            controller.allow = true
        })
        const accepted: ClientForwardedTCPIPChannel[] = []
        client.hooker.hook("tcpConnection", (_hook, channel, controller) => {
            accepted.push(channel)
            controller.allowOpen = true
        })

        try {
            const port = await client.forwardIn("127.0.0.1", 0)
            await peer.forwardOut("127.0.0.1", port, "127.0.0.1", 41_000)
            expect(accepted).toHaveLength(1)
            await expect(
                peer.forwardOut("127.0.0.1", port, "127.0.0.1", 41_001),
            ).rejects.toMatchObject({
                name: "ChannelOpenError",
                reasonCode: ChannelOpenFailureReasonCodes.SSH_OPEN_RESOURCE_SHORTAGE,
                message: "SSH simultaneous channel limit of 1 reached",
            })
            expect(accepted).toHaveLength(1)

            const closed = once(accepted[0]!, "close")
            accepted[0]!.close()
            await closed
        } finally {
            await closePeers(server, client)
        }
    }, 15_000)

    test("server channel capacity rejects excess opens and recovers after close", async () => {
        const { server, peer, client } = await createConnectedPeers({ serverMaxChannels: 1 })
        const accepted: SessionChannel[] = []
        server.hooker.hook("channelOpenRequest", (_hook, channel, controller) => {
            controller.allowOpen = channel instanceof SessionChannel
        })
        peer.on("channel", (channel) => {
            if (channel instanceof SessionChannel) accepted.push(channel)
        })

        try {
            const first = await client.openSession()
            expect(accepted).toHaveLength(1)
            await expect(client.openSession()).rejects.toMatchObject({
                name: "ChannelOpenError",
                reasonCode: ChannelOpenFailureReasonCodes.SSH_OPEN_RESOURCE_SHORTAGE,
                message: "SSH simultaneous channel limit of 1 reached",
            })
            expect(client.isConnected).toBe(true)

            const clientClosed = once(first, "close")
            first.close()
            await clientClosed

            const replacement = await client.openSession()
            expect(accepted).toHaveLength(2)
            replacement.close()
        } finally {
            await closePeers(server, client)
        }
    }, 15_000)

    test("client channel capacity rejects excess server opens and recovers after close", async () => {
        const { server, peer, client } = await createConnectedPeers({ clientMaxChannels: 1 })
        server.hooker.hook("tcpipForward", (_hook, _context, controller) => {
            controller.allow = true
        })
        const accepted: ClientForwardedTCPIPChannel[] = []
        let policyCalls = 0
        client.hooker.hook("tcpConnection", (_hook, channel, controller) => {
            policyCalls++
            controller.allowOpen = true
            accepted.push(channel)
        })

        try {
            const port = await client.forwardIn("127.0.0.1", 0)
            await peer.forwardOut("127.0.0.1", port, "127.0.0.1", 40_000)
            expect(accepted).toHaveLength(1)
            await expect(
                peer.forwardOut("127.0.0.1", port, "127.0.0.1", 40_001),
            ).rejects.toMatchObject({
                name: "ChannelOpenError",
                reasonCode: ChannelOpenFailureReasonCodes.SSH_OPEN_RESOURCE_SHORTAGE,
                message: "SSH simultaneous channel limit of 1 reached",
            })
            expect(policyCalls).toBe(1)
            expect(client.isConnected).toBe(true)

            const clientClosed = once(accepted[0]!, "close")
            accepted[0]!.close()
            await clientClosed

            const replacement = await peer.forwardOut("127.0.0.1", port, "127.0.0.1", 40_002)
            expect(policyCalls).toBe(2)
            replacement.close()
        } finally {
            await closePeers(server, client)
        }
    }, 15_000)

    test("wraps client channel identifiers at the uint32 boundary and skips active ids", async () => {
        const { server, peer, client } = await createConnectedPeers()
        server.hooker.hook("channelOpenRequest", async (_hook, _channel, controller) => {
            controller.allowOpen = true
        })
        peer.on("channel", (channel) => {
            if (!(channel instanceof SessionChannel)) return
            channel.hooker.hook("execRequest", async (_hook, _context, controller) => {
                controller.success = true
            })
        })

        try {
            client.localChannelIndex = 0xffff_ffff
            const highest = await client.exec("highest")
            expect(highest.localId).toBe(0xffff_ffff)
            expect(client.localChannelIndex).toBe(0)

            client.localChannelIndex = 0xffff_ffff
            const wrapped = await client.exec("wrapped")
            expect(wrapped.localId).toBe(0)
            expect(client.localChannelIndex).toBe(1)

            const closes = [highest, wrapped].map(async (channel) => {
                const closed = new Promise<void>((resolve) => channel.once("close", resolve))
                channel.close()
                await closed
            })
            await Promise.all(closes)
        } finally {
            await closePeers(server, client)
        }
    }, 15_000)

    test("wraps server channel identifiers at the uint32 boundary and skips active ids", async () => {
        const { server, peer, client } = await createConnectedPeers()
        const serverChannels: SessionChannel[] = []
        server.hooker.hook("channelOpenRequest", async (_hook, _channel, controller) => {
            controller.allowOpen = true
        })
        peer.on("channel", (channel) => {
            if (!(channel instanceof SessionChannel)) return
            serverChannels.push(channel)
            channel.hooker.hook("execRequest", async (_hook, _context, controller) => {
                controller.success = true
            })
        })

        try {
            peer.localChannelIndex = 0xffff_ffff
            const highest = await client.exec("highest-server-id")
            expect(serverChannels.at(-1)?.localId).toBe(0xffff_ffff)
            expect(peer.localChannelIndex).toBe(0)

            peer.localChannelIndex = 0xffff_ffff
            const wrapped = await client.exec("wrapped-server-id")
            expect(serverChannels.at(-1)?.localId).toBe(0)
            expect(peer.localChannelIndex).toBe(1)

            const closes = [highest, wrapped].map(async (channel) => {
                const closed = new Promise<void>((resolve) => channel.once("close", resolve))
                channel.close()
                await closed
            })
            await Promise.all(closes)
        } finally {
            await closePeers(server, client)
        }
    }, 15_000)

    test("disconnects a client that reuses an identifier while its first open is pending", async () => {
        const { server, peer, client } = await createConnectedPeers()
        let releasePolicy!: () => void
        const policyBlocked = new Promise<void>((resolve) => {
            releasePolicy = resolve
        })
        server.hooker.hook("channelOpenRequest", async () => policyBlocked)
        const disconnect = nextDisconnect(client)
        const open = new ChannelOpen({
            channel_type: "session",
            sender_channel_id: 0xf00d,
            initial_window_size: 1024,
            maximum_packet_size: 1024,
            args: Buffer.alloc(0),
        })

        try {
            client.sendPacket(open)
            client.sendPacket(open)
            await expect(disconnect).resolves.toEqual({
                reasonCode: DisconnectReason.SSH_DISCONNECT_PROTOCOL_ERROR,
                description: "SSH peer reused active channel identifier 61453",
                languageTag: "",
            })
        } finally {
            releasePolicy()
            await closePeers(server, client)
            peer.terminate()
        }
    }, 15_000)

    test("disconnects a server that duplicates identifiers in open confirmations", async () => {
        const { server, peer, client } = await createConnectedPeers()
        const first = new ClientSessionChannel(client)
        const second = new ClientSessionChannel(client)
        client.channels.set(first.localId, first)
        client.channels.set(second.localId, second)
        void second.waitUntilOpen().catch(() => undefined)
        const disconnect = nextDisconnect(peer)

        try {
            for (const channel of [first, second]) {
                peer.sendPacket(
                    new ChannelOpenConfirmation({
                        recipient_channel_id: channel.localId,
                        sender_channel_id: 77,
                        initial_window_size: 1024,
                        maximum_packet_size: 1024,
                        args: Buffer.alloc(0),
                    }),
                )
            }
            await expect(disconnect).resolves.toEqual({
                reasonCode: DisconnectReason.SSH_DISCONNECT_PROTOCOL_ERROR,
                description: "SSH peer reused active channel identifier 77",
                languageTag: "",
            })
        } finally {
            await closePeers(server, client)
        }
    }, 15_000)

    test.each(["client", "server"] as const)(
        "rejects contradictory channel-open outcomes sent by the %s",
        async (sender) => {
            const { server, peer, client } = await createConnectedPeers()
            const channel =
                sender === "server"
                    ? new ClientSessionChannel(client)
                    : new SessionChannel(peer, "session")
            const packetSender = sender === "server" ? peer : client
            if (channel instanceof ClientSessionChannel) {
                client.channels.set(channel.localId, channel)
            } else {
                peer.channels.set(channel.localId, channel)
            }
            const disconnect = nextDisconnect(packetSender)

            try {
                packetSender.sendPacket(
                    new ChannelOpenConfirmation({
                        recipient_channel_id: channel.localId,
                        sender_channel_id: 91,
                        initial_window_size: 1024,
                        maximum_packet_size: 1024,
                        args: Buffer.alloc(0),
                    }),
                )
                await channel.waitUntilOpen()
                packetSender.sendPacket(
                    new ChannelOpenFailure({
                        recipient_channel_id: channel.localId,
                        reason_code:
                            ChannelOpenFailureReasonCodes.SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
                        description: "contradictory outcome",
                        language_tag: "",
                    }),
                )
                await expect(disconnect).resolves.toMatchObject({
                    reasonCode: DisconnectReason.SSH_DISCONNECT_PROTOCOL_ERROR,
                    description: `SSH channel ${channel.localId} open was settled twice`,
                })
            } finally {
                await closePeers(server, client)
            }
        },
        15_000,
    )

    test("sends protocol-error disconnects for channel window overflow in both roles", async () => {
        {
            const { server, peer, client } = await createConnectedPeers()
            const session = await openSession(server, peer, client)
            const disconnect = nextDisconnect(client)
            try {
                client.sendPacket(
                    new ChannelWindowAdjust({
                        recipient_channel_id: session.remoteId!,
                        bytes_to_add: 0xffff_ffff,
                    }),
                )
                await expect(disconnect).resolves.toMatchObject({
                    reasonCode: DisconnectReason.SSH_DISCONNECT_PROTOCOL_ERROR,
                    description: expect.stringContaining("window adjustment exceeds uint32"),
                })
            } finally {
                await closePeers(server, client)
            }
        }

        {
            const { server, peer, client } = await createConnectedPeers()
            const session = await openSession(server, peer, client)
            const disconnect = nextDisconnect(peer)
            try {
                peer.sendPacket(
                    new ChannelWindowAdjust({
                        recipient_channel_id: session.localId,
                        bytes_to_add: 0xffff_ffff,
                    }),
                )
                await expect(disconnect).resolves.toMatchObject({
                    reasonCode: DisconnectReason.SSH_DISCONNECT_PROTOCOL_ERROR,
                    description: expect.stringContaining("window adjustment exceeds uint32"),
                })
            } finally {
                await closePeers(server, client)
            }
        }
    }, 15_000)
})
