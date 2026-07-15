import { AddressInfo } from "node:net"
import Client from "../../src/Client.js"
import ClientSessionChannel from "../../src/channels/ClientSessionChannel.js"
import SessionChannel from "../../src/channels/SessionChannel.js"
import { SSHAuthenticationMethods } from "../../src/constants.js"
import Server from "../../src/Server.js"
import type ServerClient from "../../src/ServerClient.js"
import ChannelOpen from "../../src/packets/ChannelOpen.js"
import ChannelOpenConfirmation from "../../src/packets/ChannelOpenConfirmation.js"
import ChannelOpenFailure, {
    ChannelOpenFailureReasonCodes,
} from "../../src/packets/ChannelOpenFailure.js"
import ChannelWindowAdjust from "../../src/packets/ChannelWindowAdjust.js"
import { DisconnectReason, type PeerDisconnectInfo } from "../../src/packets/Disconnect.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

async function createConnectedPeers(): Promise<{
    server: Server
    peer: ServerClient
    client: Client
}> {
    const hostKey = await PrivateKey.generate("ssh-ed25519")
    const server = new Server({ hostKeys: [hostKey], sendAllHostKeys: false })
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
