import { AddressInfo } from "node:net"
import { once } from "node:events"
import { Duplex, PassThrough } from "node:stream"
import Client from "../../src/Client.js"
import { SSHAuthenticationMethods } from "../../src/constants.js"
import Packet from "../../src/packet.js"
import ChannelOpenConfirmation from "../../src/packets/ChannelOpenConfirmation.js"
import ChannelOpenFailure from "../../src/packets/ChannelOpenFailure.js"
import Server from "../../src/Server.js"
import type ServerClient from "../../src/ServerClient.js"
import SessionChannel from "../../src/channels/SessionChannel.js"
import Agent, { AgentType } from "../../src/publickey/Agent.js"
import {
    SSHAgentProtocolClient,
    SSHAgentProtocolServer,
} from "../../src/publickey/SSHAgentProtocol.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

function streamPair(): [Duplex, Duplex] {
    class MemoryDuplex extends Duplex {
        peer!: MemoryDuplex

        _read(): void {
            // The peer drives readable data through push().
        }

        _write(
            chunk: Buffer,
            _encoding: BufferEncoding,
            callback: (error?: Error | null) => void,
        ): void {
            this.peer.push(Buffer.from(chunk))
            callback()
        }

        _final(callback: (error?: Error | null) => void): void {
            this.peer.push(null)
            callback()
        }

        _destroy(error: Error | null, callback: (error?: Error | null) => void): void {
            this.peer.push(null)
            callback(error)
        }
    }
    const left = new MemoryDuplex()
    const right = new MemoryDuplex()
    left.peer = right
    right.peer = left
    return [left, right]
}

function within<T>(operation: Promise<T>, label: string): Promise<T> {
    let timer: NodeJS.Timeout | undefined
    const timeout = new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => reject(new Error(`Timed out waiting for ${label}`)), 5_000)
    })
    return Promise.race([operation, timeout]).finally(() => {
        if (timer !== undefined) clearTimeout(timer)
    })
}

const forwardableAgent: Agent<string> = {
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
    async getStream(): Promise<Duplex> {
        throw new Error("The server must not open an agent channel in this test")
    },
}

class ChannelReplyObservingClient extends Client {
    lateChannelReplies = 0

    sendPacket(packet: Packet): number {
        if (
            !this.isConnected &&
            (packet instanceof ChannelOpenConfirmation || packet instanceof ChannelOpenFailure)
        ) {
            this.lateChannelReplies++
        }
        return super.sendPacket(packet)
    }
}

describe("client agent-forwarding defaults", () => {
    test("negotiates the RFC 9987 request and channel names", async () => {
        const streams: Duplex[] = []
        const protocolTasks: Promise<void>[] = []
        const identity = PrivateKey.generateSync("ssh-ed25519")
        const protocolServer = new SSHAgentProtocolServer()
        protocolServer.hooker.hook("identities", async (_hook, decision) => {
            await Promise.resolve()
            decision.identities = [
                { publicKey: identity.data.publicKey, comment: "forwarded-fixture" },
            ]
        })
        protocolServer.hooker.hook("sign", async (_hook, context, decision) => {
            await Promise.resolve()
            decision.signature = identity.sign(context.data, context.algorithm)
        })
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
            async getStream() {
                const [forwardedStream, agentStream] = streamPair()
                streams.push(forwardedStream, agentStream)
                protocolTasks.push(protocolServer.serve(agentStream))
                return forwardedStream
            },
        }
        const server = new Server({
            hostKeys: [await PrivateKey.generate("ssh-ed25519")],
            sendAllHostKeys: false,
        })
        server.hooker.hook("noneAuthentication", (_hook, _context, decision) => {
            decision.allowLogin = true
        })
        server.hooker.hook("channelOpenRequest", (_hook, channel, decision) => {
            decision.allowOpen = channel instanceof SessionChannel
        })
        let connection: ServerClient | undefined
        server.on("connection", (peer) => {
            connection = peer
            peer.on("channel", (channel) => {
                if (!(channel instanceof SessionChannel)) return
                channel.hooker.hook("agentForwardRequest", (_hook, decision) => {
                    decision.success = true
                })
                channel.hooker.hook("execRequest", (_hook, _context, decision) => {
                    decision.success = true
                })
            })
        })
        server.listen({ host: "127.0.0.1", port: 0 })
        await once(server, "listening")

        const client = new Client({
            hostname: "127.0.0.1",
            port: (server.address() as AddressInfo).port,
            username: "rfc9987-forwarding",
            agent,
            authenticationMethodsOrder: [SSHAuthenticationMethods.None],
        })
        client.hooker.hook("hostKey", (_hook, decision) => {
            decision.allowHostKey = true
        })

        try {
            await client.connect()
            expect(client.rfc9987AgentForwarding).toBe(true)
            const session = await client.openSession()
            await session.forwardAgent()
            await session.exec("agent-forwarding")
            const forwarded = await connection!.forwardAgent()
            expect(forwarded.channel_type).toBe("agent-connect")
            const protocolClient = new SSHAgentProtocolClient(forwarded.stream)
            const identities = await protocolClient.getPublicKeys()
            expect(identities).toHaveLength(1)
            expect(identities[0][1].data.comment).toBe("forwarded-fixture")
            const message = Buffer.from("signed through an SSH forwarding channel")
            const signature = await protocolClient.sign(identities[0][0], message)
            expect(identities[0][1].verifySignature(message, signature)).toBeTrue()
            expect(streams).toHaveLength(2)
            protocolClient.destroy()
            forwarded.close()
            session.close()
        } finally {
            client.destroy()
            for (const peer of server.clients) peer.terminate()
            for (const stream of streams) stream.destroy()
            await Promise.all(protocolTasks)
            await server.close()
        }
    }, 15_000)

    test("awaits the connection default before the program request and honors a session opt-out", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({ hostKeys: [hostKey], sendAllHostKeys: false })
        const requests: string[] = []
        server.hooker.hook("noneAuthentication", (_hook, _context, decision) => {
            decision.allowLogin = true
        })
        server.hooker.hook("channelOpenRequest", (_hook, channel, decision) => {
            decision.allowOpen = channel instanceof SessionChannel
        })
        server.on("connection", (connection) => {
            connection.on("channel", (channel) => {
                if (!(channel instanceof SessionChannel)) return
                channel.hooker.hook("agentForwardRequest", async (_hook, decision) => {
                    await Promise.resolve()
                    requests.push("agent")
                    decision.success = true
                })
                channel.hooker.hook("execRequest", (_hook, context, decision) => {
                    requests.push(`exec:${context.command}`)
                    decision.success = true
                })
            })
        })
        server.listen({ host: "127.0.0.1", port: 0 })
        await once(server.server!, "listening")

        const client = new Client({
            hostname: "127.0.0.1",
            port: (server.server!.address() as AddressInfo).port,
            username: "forwarding-default",
            agent: forwardableAgent,
            agentForward: true,
            authenticationMethodsOrder: [SSHAuthenticationMethods.None],
        })
        client.hooker.hook("hostKey", (_hook, decision) => {
            decision.allowHostKey = true
        })
        let optInClient: Client | undefined

        try {
            await client.connect()
            const forwarded = await client.exec("forwarded")
            const isolated = await client.exec("isolated", { agentForward: false })
            expect(requests).toEqual(["agent", "exec:forwarded", "exec:isolated"])
            forwarded.close()
            isolated.close()

            optInClient = new Client({
                hostname: "127.0.0.1",
                port: (server.server!.address() as AddressInfo).port,
                username: "forwarding-opt-in",
                agent: forwardableAgent,
                authenticationMethodsOrder: [SSHAuthenticationMethods.None],
            })
            optInClient.hooker.hook("hostKey", (_hook, decision) => {
                decision.allowHostKey = true
            })
            await optInClient.connect()
            const explicit = await optInClient.exec("explicit", { agentForward: true })
            expect(requests).toEqual([
                "agent",
                "exec:forwarded",
                "exec:isolated",
                "agent",
                "exec:explicit",
            ])
            explicit.close()
        } finally {
            client.destroy()
            optInClient?.destroy()
            for (const connection of server.clients) connection.terminate()
            await server.close()
        }
    }, 15_000)

    test("keeps the connection default disabled", () => {
        expect("options" in new Client({})).toBe(false)
    })

    test("discards an agent stream resolved after transport teardown", async () => {
        const server = new Server({
            hostKeys: [await PrivateKey.generate("ssh-ed25519")],
            sendAllHostKeys: false,
        })
        server.hooker.hook("noneAuthentication", (_hook, _context, decision) => {
            decision.allowLogin = true
        })
        server.hooker.hook("channelOpenRequest", (_hook, channel, decision) => {
            decision.allowOpen = channel instanceof SessionChannel
        })
        let connection!: ServerClient
        server.on("connection", (peer) => {
            connection = peer
            peer.on("channel", (channel) => {
                if (!(channel instanceof SessionChannel)) return
                channel.hooker.hook("agentForwardRequest", (_hook, decision) => {
                    decision.success = true
                })
            })
        })
        server.listen({ host: "127.0.0.1", port: 0 })
        await once(server, "listening")

        let resolveAgentStream!: (stream: Duplex) => void
        let markStreamRequested!: () => void
        const streamRequested = new Promise<void>((resolve) => {
            markStreamRequested = resolve
        })
        const agent: Agent<string> = {
            ...forwardableAgent,
            getStream() {
                markStreamRequested()
                return new Promise<Duplex>((resolve) => {
                    resolveAgentStream = resolve
                })
            },
        }
        const client = new ChannelReplyObservingClient({
            hostname: "127.0.0.1",
            port: (server.address() as AddressInfo).port,
            username: "late-agent-stream",
            agent,
            authenticationMethodsOrder: [SSHAuthenticationMethods.None],
        })
        client.hooker.hook("hostKey", (_hook, decision) => {
            decision.allowHostKey = true
        })
        const forwardedStream = new PassThrough()

        try {
            await client.connect()
            const session = await client.openSession()
            await session.forwardAgent()
            const opening = connection.forwardAgent()
            const openingResult = opening.then(
                () => undefined,
                (error: unknown) => error,
            )
            await within(streamRequested, "the agent stream request")

            const clientClosed = once(client, "close")
            client.destroy()
            await within(clientClosed, "the client transport to close")
            const openingError = await within(openingResult, "the server channel open to fail")
            expect(openingError).toBeInstanceOf(Error)
            expect((openingError as Error).message).toContain("SSH connection closed")

            const streamClosed = once(forwardedStream, "close")
            resolveAgentStream(forwardedStream)
            await within(streamClosed, "the late agent stream to close")
            await new Promise<void>((resolve) => setImmediate(resolve))

            expect(client.lateChannelReplies).toBe(0)
            expect(forwardedStream.destroyed).toBe(true)
        } finally {
            client.destroy()
            connection?.terminate()
            forwardedStream.destroy()
            await within(server.close(), "the forwarding test server to close")
        }
    }, 15_000)
})
