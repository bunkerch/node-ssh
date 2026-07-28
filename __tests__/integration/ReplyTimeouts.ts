import { once } from "node:events"
import type { AddressInfo } from "node:net"
import type { Duplex } from "node:stream"
import Client from "../../src/Client.js"
import { SSHAuthenticationMethods } from "../../src/constants.js"
import Packet from "../../src/packet.js"
import KexInit from "../../src/packets/KexInit.js"
import ChannelOpenFailure from "../../src/packets/ChannelOpenFailure.js"
import Pong from "../../src/packets/Pong.js"
import RequestFailure from "../../src/packets/RequestFailure.js"
import Unimplemented from "../../src/packets/Unimplemented.js"
import Server from "../../src/Server.js"
import type ServerClient from "../../src/ServerClient.js"
import SessionChannel from "../../src/channels/SessionChannel.js"
import Agent, { AgentType } from "../../src/publickey/Agent.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

interface ConnectedPeers {
    client: Client
    peer: ServerClient
    server: Server
}

function neverSettles<T>(): Promise<T> {
    return new Promise<T>(() => undefined)
}

async function connectedPeers(options: {
    clientReplyTimeout?: number
    serverReplyTimeout?: number
    agent?: Agent
    configureServer?(server: Server): void
    configureClient?(client: Client): void
}): Promise<ConnectedPeers> {
    const server = new Server({
        hostKeys: [await PrivateKey.generate("ssh-ed25519")],
        sendAllHostKeys: false,
        replyTimeout: options.serverReplyTimeout ?? 1_000,
    })
    server.hooker.hook("noneAuthentication", (_hook, _context, decision) => {
        decision.allowLogin = true
    })
    options.configureServer?.(server)
    let peer!: ServerClient
    server.on("connection", (connection) => {
        peer = connection
    })
    server.listen({ host: "127.0.0.1", port: 0 })
    await once(server, "listening")

    const client = new Client({
        hostname: "127.0.0.1",
        port: (server.address() as AddressInfo).port,
        username: "reply-timeout-test",
        agent: options.agent,
        replyTimeout: options.clientReplyTimeout ?? 40,
        authenticationMethodsOrder: [SSHAuthenticationMethods.None],
    })
    client.hooker.hook("hostKey", (_hook, decision) => {
        decision.allowHostKey = true
    })
    options.configureClient?.(client)
    await client.connect()
    return { client, peer, server }
}

async function closePeers({ client, peer, server }: ConnectedPeers): Promise<void> {
    client.destroy()
    peer.terminate()
    await server.close()
}

describe("ordered SSH reply deadlines", () => {
    test("validates positive client and server reply deadlines", () => {
        for (const replyTimeout of [0, -1, Number.NaN, Number.POSITIVE_INFINITY]) {
            expect(() => new Client({ replyTimeout })).toThrow(
                "SSH reply timeout must be a positive number",
            )
            expect(() => new Server({ replyTimeout })).toThrow(
                "SSH reply timeout must be a positive number",
            )
        }
    })

    test("closes after an unanswered transport ping", async () => {
        const peers = await connectedPeers({})
        const sendPacket = peers.peer.sendPacket.bind(peers.peer)
        peers.peer.sendPacket = (packet: Packet) =>
            packet instanceof Pong ? -1 : sendPacket(packet)

        try {
            const closed = once(peers.client, "close")
            await expect(peers.client.ping(Buffer.from("no-pong"))).rejects.toThrow(
                "Timed out waiting for SSH transport ping reply",
            )
            await closed
        } finally {
            await closePeers(peers)
        }
    })

    test("rejects an unimplemented transport ping immediately without closing", async () => {
        const peers = await connectedPeers({ clientReplyTimeout: 1_000 })
        let pingSequence: number | undefined
        peers.peer.on("packet", (metadata) => {
            if (metadata.name === "SSH_MSG_PING") pingSequence = metadata.sequenceNumber
        })
        const sendPacket = peers.peer.sendPacket.bind(peers.peer)
        peers.peer.sendPacket = (packet: Packet) =>
            packet instanceof Pong && pingSequence !== undefined
                ? sendPacket(new Unimplemented({ sequence_number: pingSequence }))
                : sendPacket(packet)

        try {
            await expect(peers.client.ping(Buffer.from("unsupported"))).rejects.toThrow(
                "SSH peer did not implement transport ping",
            )
            expect(peers.client.isConnected).toBe(true)
        } finally {
            await closePeers(peers)
        }
    })

    test("rejects an unimplemented client global request without disturbing reply order", async () => {
        const peers = await connectedPeers({ clientReplyTimeout: 1_000 })
        let requestSequence: number | undefined
        peers.peer.on("packet", (metadata) => {
            if (metadata.name === "SSH_MSG_GLOBAL_REQUEST") {
                requestSequence = metadata.sequenceNumber
            }
        })
        const sendPacket = peers.peer.sendPacket.bind(peers.peer)
        peers.peer.sendPacket = (packet: Packet) =>
            packet instanceof RequestFailure && requestSequence !== undefined
                ? sendPacket(new Unimplemented({ sequence_number: requestSequence }))
                : sendPacket(packet)

        try {
            await expect(peers.client.globalRequest("unsupported@example.test")).rejects.toThrow(
                "outbound packet sequence",
            )
            peers.peer.sendPacket = sendPacket
            await expect(peers.client.globalRequest("denied@example.test")).rejects.toThrow(
                "SSH global request denied@example.test failed",
            )
            expect(peers.client.isConnected).toBe(true)
        } finally {
            await closePeers(peers)
        }
    })

    test("rejects an unimplemented server global request without disturbing reply order", async () => {
        const peers = await connectedPeers({
            clientReplyTimeout: 1_000,
            serverReplyTimeout: 1_000,
        })
        let requestSequence: number | undefined
        peers.client.on("packet", (metadata) => {
            if (metadata.name === "SSH_MSG_GLOBAL_REQUEST") {
                requestSequence = metadata.sequenceNumber
            }
        })
        const sendPacket = peers.client.sendPacket.bind(peers.client)
        peers.client.sendPacket = (packet: Packet) =>
            packet instanceof RequestFailure && requestSequence !== undefined
                ? sendPacket(new Unimplemented({ sequence_number: requestSequence }))
                : sendPacket(packet)

        try {
            await expect(peers.peer.globalRequest("unsupported@example.test")).rejects.toThrow(
                "outbound packet sequence",
            )
            peers.client.sendPacket = sendPacket
            await expect(peers.peer.globalRequest("denied@example.test")).rejects.toThrow(
                "SSH global request denied@example.test failed",
            )
            expect(peers.peer.isConnected).toBe(true)
        } finally {
            await closePeers(peers)
        }
    })

    test("closes after an unanswered client global request", async () => {
        const never = neverSettles<void>()
        const peers = await connectedPeers({
            configureServer(server) {
                server.hooker.hook("globalRequest", async () => never)
            },
        })

        try {
            const closed = once(peers.client, "close")
            await expect(peers.client.globalRequest("unanswered@example.test")).rejects.toThrow(
                "Timed out waiting for SSH global request unanswered@example.test reply",
            )
            await closed
        } finally {
            await closePeers(peers)
        }
    })

    test("closes after an unanswered server global request", async () => {
        const never = neverSettles<void>()
        const peers = await connectedPeers({
            serverReplyTimeout: 40,
            clientReplyTimeout: 1_000,
            configureClient(client) {
                client.hooker.hook("globalRequest", async () => never)
            },
        })

        try {
            const closed = once(peers.peer, "close")
            await expect(peers.peer.globalRequest("unanswered@example.test")).rejects.toThrow(
                "Timed out waiting for SSH global request unanswered@example.test reply",
            )
            await closed
        } finally {
            await closePeers(peers)
        }
    })

    test("closes after an unanswered channel open", async () => {
        const never = neverSettles<void>()
        const peers = await connectedPeers({
            configureServer(server) {
                server.hooker.hook("channelOpenRequest", async () => never)
            },
        })

        try {
            const closed = once(peers.client, "close")
            await expect(peers.client.openSession()).rejects.toThrow(
                "Timed out waiting for SSH channel 0 open",
            )
            await closed
        } finally {
            await closePeers(peers)
        }
    })

    test("rejects an unimplemented channel open immediately without closing", async () => {
        const peers = await connectedPeers({ clientReplyTimeout: 1_000 })
        let openSequence: number | undefined
        peers.peer.on("packet", (metadata) => {
            if (metadata.name === "SSH_MSG_CHANNEL_OPEN") {
                openSequence = metadata.sequenceNumber
            }
        })
        const sendPacket = peers.peer.sendPacket.bind(peers.peer)
        peers.peer.sendPacket = (packet: Packet) =>
            packet instanceof ChannelOpenFailure && openSequence !== undefined
                ? sendPacket(new Unimplemented({ sequence_number: openSequence }))
                : sendPacket(packet)

        try {
            await expect(peers.client.openSession()).rejects.toThrow(
                "SSH peer did not implement channel 0 open",
            )
            expect(peers.client.isConnected).toBe(true)
        } finally {
            await closePeers(peers)
        }
    })

    test("closes after an unanswered channel request", async () => {
        const never = neverSettles<void>()
        const peers = await connectedPeers({
            configureServer(server) {
                server.hooker.hook("channelOpenRequest", (_hook, channel, decision) => {
                    decision.allowOpen = channel instanceof SessionChannel
                })
                server.on("connection", (connection) => {
                    connection.on("channel", (channel) => {
                        if (!(channel instanceof SessionChannel)) return
                        channel.hooker.hook("execRequest", async () => never)
                    })
                })
            },
        })

        try {
            const channel = await peers.client.openSession()
            const closed = once(peers.client, "close")
            await expect(channel.exec("never-reply")).rejects.toThrow(
                `Timed out waiting for SSH channel ${channel.localId} request exec reply`,
            )
            await closed
        } finally {
            await closePeers(peers)
        }
    })

    test("bounds a server channel request with the same reply deadline", async () => {
        const never = neverSettles<void>()
        let serverChannel!: SessionChannel
        let markChannelReady!: () => void
        const channelReady = new Promise<void>((resolve) => {
            markChannelReady = resolve
        })
        const peers = await connectedPeers({
            serverReplyTimeout: 40,
            clientReplyTimeout: 1_000,
            configureServer(server) {
                server.hooker.hook("channelOpenRequest", (_hook, channel, decision) => {
                    decision.allowOpen = channel instanceof SessionChannel
                })
                server.on("connection", (connection) => {
                    connection.on("channel", (channel) => {
                        if (!(channel instanceof SessionChannel)) return
                        serverChannel = channel
                        markChannelReady()
                    })
                })
            },
        })

        try {
            const clientChannel = await peers.client.openSession()
            await channelReady
            clientChannel.hooker.hook("request", async () => never)
            const closed = once(peers.peer, "close")
            await expect(serverChannel.request("never-reply@example.test")).rejects.toThrow(
                `Timed out waiting for SSH channel ${serverChannel.localId} request never-reply@example.test reply`,
            )
            await closed
        } finally {
            await closePeers(peers)
        }
    })

    test("bounds a server-initiated channel open", async () => {
        const never = neverSettles<Duplex>()
        const agent: Agent<string> = {
            type: AgentType.NonInteractive,
            async getPublicKeys() {
                return []
            },
            async getPublicKey() {
                throw new Error("No fixture identity")
            },
            async sign() {
                throw new Error("No fixture identity")
            },
            getStream() {
                return never
            },
        }
        const peers = await connectedPeers({
            agent,
            serverReplyTimeout: 40,
            clientReplyTimeout: 1_000,
            configureServer(server) {
                server.hooker.hook("channelOpenRequest", (_hook, channel, decision) => {
                    decision.allowOpen = channel instanceof SessionChannel
                })
                server.on("connection", (connection) => {
                    connection.on("channel", (channel) => {
                        if (!(channel instanceof SessionChannel)) return
                        channel.hooker.hook("agentForwardRequest", (_hook, decision) => {
                            decision.success = true
                        })
                    })
                })
            },
        })

        try {
            const session = await peers.client.openSession()
            await session.forwardAgent()
            const closed = once(peers.peer, "close")
            await expect(peers.peer.forwardAgent()).rejects.toThrow(
                "Timed out waiting for SSH channel 1 open",
            )
            await closed
        } finally {
            await closePeers(peers)
        }
    })

    test("closes after an unanswered key re-exchange", async () => {
        const peers = await connectedPeers({})
        const sendPacket = peers.peer.sendPacket.bind(peers.peer)
        peers.peer.sendPacket = (packet: Packet) =>
            packet instanceof KexInit ? -1 : sendPacket(packet)

        try {
            const closed = once(peers.client, "close")
            await expect(peers.client.rekey()).rejects.toThrow(
                "Timed out waiting for SSH key exchange",
            )
            await closed
        } finally {
            await closePeers(peers)
        }
    })
})
