import { AddressInfo } from "node:net"
import Client from "../../src/Client.js"
import { SSHAuthenticationMethods } from "../../src/constants.js"
import Disconnect, { DisconnectReason } from "../../src/packets/Disconnect.js"
import Server from "../../src/Server.js"
import type ServerClient from "../../src/ServerClient.js"
import PrivateKey from "../../src/utils/PrivateKey.js"
import PublicKey from "../../src/utils/PublicKey.js"
import EncodedSignature from "../../src/utils/Signature.js"
import Agent, { AgentType } from "../../src/publickey/Agent.js"
import Packet from "../../src/packet.js"
import UserAuthRequest from "../../src/packets/UserAuthRequest.js"
import { HostboundPublicKeyAuthMethod } from "../../src/auth/publickey.js"
import ExtInfo from "../../src/packets/ExtInfo.js"

class PrivateKeyAgent extends Agent<number> {
    readonly type = AgentType.NonInteractive

    constructor(private readonly key: PrivateKey) {
        super()
    }

    async getPublicKeys(): Promise<[number, PublicKey][]> {
        return [[0, this.key.data.publicKey]]
    }

    async getPublicKey(): Promise<PublicKey> {
        return this.key.data.publicKey
    }

    async sign(_id: number, data: Buffer, algorithm?: string): Promise<EncodedSignature> {
        return this.key.sign(data, algorithm)
    }
}

describe("RFC 4252 multi-method authentication", () => {
    test.each(["client", "server"] as const)(
        "rejects %s EXT_INFO outside the negotiated message position",
        async (sender) => {
            const hostKey = await PrivateKey.generate("ssh-ed25519")
            const server = new Server({ hostKeys: [hostKey], sendAllHostKeys: false })
            server.hooker.hook("noneAuthentication", (_hook, _context, decision) => {
                decision.allowLogin = true
            })
            let connection: ServerClient | undefined
            server.on("connection", (peer) => {
                connection = peer
            })
            server.listen({ host: "127.0.0.1", port: 0 })
            await new Promise<void>((resolve) => server.server!.once("listening", resolve))
            const client = new Client({
                hostname: "127.0.0.1",
                port: (server.server!.address() as AddressInfo).port,
                username: "extension-user",
                authenticationMethodsOrder: [SSHAuthenticationMethods.None],
            })
            client.hooker.hook("hostKey", (_hook, decision) => {
                decision.allowHostKey = true
            })

            try {
                await client.connect()
                const target = sender === "client" ? connection! : client
                const protocolError = new Promise<Error>((resolve) => target.once("error", resolve))
                const packet = new ExtInfo({
                    extensions: [{ name: "late@example.test", value: Buffer.from("too late") }],
                })
                if (sender === "client") client.sendPacket(packet)
                else connection!.sendPacket(packet)
                expect((await protocolError).message).toContain(
                    `${sender === "client" ? "Client" : "Server"} EXT_INFO arrived outside`,
                )
            } finally {
                client.destroy()
                for (const peer of server.clients) peer.terminate()
                await new Promise<void>((resolve, reject) => {
                    server.server!.close((error) => (error ? reject(error) : resolve()))
                })
            }
        },
        15_000,
    )

    test("replaces pre-authentication extension information immediately before success", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({ hostKeys: [hostKey], sendAllHostKeys: false })
        server.hooker.hook("noneAuthentication", (_hook, _context, decision, connection) => {
            connection.sendPacket(
                new ExtInfo({
                    extensions: [
                        {
                            name: "authenticated@example.test",
                            value: Buffer.from([0x00, 0xff, 0x41]),
                        },
                    ],
                }),
            )
            decision.allowLogin = true
        })
        server.listen({ host: "127.0.0.1", port: 0 })
        await new Promise<void>((resolve) => server.server!.once("listening", resolve))
        const client = new Client({
            hostname: "127.0.0.1",
            port: (server.server!.address() as AddressInfo).port,
            username: "extension-user",
            authenticationMethodsOrder: [SSHAuthenticationMethods.None],
        })
        const extensionSets: string[][] = []
        client.on("serverExtensions", (extensions) => {
            extensionSets.push(extensions.map(({ name }) => name))
        })
        client.hooker.hook("hostKey", (_hook, decision) => {
            decision.allowHostKey = true
        })

        try {
            await client.connect()
            expect(extensionSets).toEqual([
                ["server-sig-algs", "ping@openssh.com"],
                ["authenticated@example.test"],
            ])
            expect(client.serverExtensions).toEqual([
                {
                    name: "authenticated@example.test",
                    value: Buffer.from([0x00, 0xff, 0x41]),
                },
            ])
            await expect(client.ping()).rejects.toThrow(
                "SSH server did not advertise transport ping support",
            )
        } finally {
            client.destroy()
            for (const connection of server.clients) connection.terminate()
            await new Promise<void>((resolve, reject) => {
                server.server!.close((error) => (error ? reject(error) : resolve()))
            })
        }
    }, 15_000)

    test("binds public-key authentication to the negotiated server host key", async () => {
        const serverHostKey = await PrivateKey.generate("ssh-ed25519")
        const userKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({ hostKeys: [serverHostKey], sendAllHostKeys: false })
        const contexts: unknown[] = []
        const errors: Error[] = []
        server.hooker.hook("publicKeyAuthentication", (_hook, context, decision) => {
            contexts.push(context)
            if (!context.publicKey.equals(userKey.data.publicKey)) return
            if (!context.signature) {
                decision.requestSignature = true
                return
            }
            decision.allowLogin = context.publicKey.verifySignature(
                context.signatureMessage,
                context.signature,
            )
        })
        server.on("connection", (connection) =>
            connection.on("error", (error) => errors.push(error)),
        )
        server.listen({ host: "127.0.0.1", port: 0 })
        await new Promise<void>((resolve) => server.server!.once("listening", resolve))
        const port = (server.server!.address() as AddressInfo).port
        const client = new Client({
            hostname: "127.0.0.1",
            port,
            username: "bound-user",
            agent: new PrivateKeyAgent(userKey),
            authenticationMethodsOrder: [SSHAuthenticationMethods.PublicKey],
        })
        client.on("error", (error) => errors.push(error))
        client.hooker.hook("hostKey", (_hook, decision) => {
            decision.allowHostKey = true
        })

        try {
            await client.connect()
            expect(client.hostboundPublicKeyAuthentication).toBe(true)
            expect(contexts).toHaveLength(1)
            const context = contexts[0] as {
                hostbound?: boolean
                serverHostKey?: PublicKey
                signatureMessage: Buffer
            }
            expect(context.hostbound).toBe(true)
            expect(context.serverHostKey?.equals(serverHostKey.data.publicKey)).toBe(true)
            expect(context.signatureMessage.includes(Buffer.from("publickey-hostbound-v00"))).toBe(
                true,
            )
            expect(errors).toEqual([])
        } finally {
            client.destroy()
            for (const connection of server.clients) connection.terminate()
            await new Promise<void>((resolve, reject) => {
                server.server!.close((error) => (error ? reject(error) : resolve()))
            })
        }
    }, 15_000)

    test("rejects a host-bound request for a different server key before policy", async () => {
        const serverHostKey = await PrivateKey.generate("ssh-ed25519")
        const otherHostKey = await PrivateKey.generate("ssh-ed25519")
        const userKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({ hostKeys: [serverHostKey], sendAllHostKeys: false })
        let policyCalls = 0
        server.hooker.hook("publicKeyAuthentication", () => {
            policyCalls++
        })
        server.listen({ host: "127.0.0.1", port: 0 })
        await new Promise<void>((resolve) => server.server!.once("listening", resolve))
        const port = (server.server!.address() as AddressInfo).port

        class MismatchedHostKeyClient extends Client {
            override sendPacket(packet: Packet): number {
                if (
                    packet instanceof UserAuthRequest &&
                    packet.data.method instanceof HostboundPublicKeyAuthMethod
                ) {
                    packet.data.method.data.serverHostKey = otherHostKey.data.publicKey.serialize()
                }
                return super.sendPacket(packet)
            }
        }
        const client = new MismatchedHostKeyClient({
            hostname: "127.0.0.1",
            port,
            username: "bound-user",
            agent: new PrivateKeyAgent(userKey),
            authenticationMethodsOrder: [SSHAuthenticationMethods.PublicKey],
        })
        client.hooker.hook("hostKey", (_hook, decision) => {
            decision.allowHostKey = true
        })

        try {
            await expect(client.connect()).rejects.toThrow("All authentication methods failed")
            expect(policyCalls).toBe(0)
        } finally {
            client.destroy()
            for (const connection of server.clients) connection.terminate()
            await new Promise<void>((resolve, reject) => {
                server.server!.close((error) => (error ? reject(error) : resolve()))
            })
        }
    }, 15_000)

    test("emits only host keys whose ownership the server proves", async () => {
        const hostKeys = await Promise.all([
            PrivateKey.generate("ssh-ed25519"),
            PrivateKey.generate("ecdsa-sha2-nistp256"),
        ])
        const server = new Server({ hostKeys, sendAllHostKeys: true })
        server.hooker.hook("noneAuthentication", (_hook, context, decision) => {
            decision.allowLogin = context.username === "rotation"
        })
        server.listen({ host: "127.0.0.1", port: 0 })
        await new Promise<void>((resolve) => server.server!.once("listening", resolve))
        const port = (server.server!.address() as AddressInfo).port
        const client = new Client({
            hostname: "127.0.0.1",
            port,
            username: "rotation",
            authenticationMethodsOrder: [SSHAuthenticationMethods.None],
        })
        client.hooker.hook("hostKey", (_hook, decision) => {
            decision.allowHostKey = true
        })
        const announced = new Promise<readonly PublicKey[]>((resolve) => {
            client.once("hostKeys", resolve)
        })

        try {
            await client.connect()
            const verified = await announced
            expect(verified).toHaveLength(2)
            expect(
                verified.every((publicKey) =>
                    hostKeys.some((privateKey) => privateKey.data.publicKey.equals(publicKey)),
                ),
            ).toBe(true)
        } finally {
            client.destroy()
            for (const connection of server.clients) connection.terminate()
            await new Promise<void>((resolve, reject) => {
                server.server!.close((error) => (error ? reject(error) : resolve()))
            })
        }
    }, 15_000)

    test("authenticates a client host through an awaited server policy hook", async () => {
        const serverHostKey = await PrivateKey.generate("ssh-ed25519")
        const clientHostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({ hostKeys: [serverHostKey], sendAllHostKeys: false })
        const contexts: unknown[] = []
        const errors: Error[] = []
        server.hooker.hook("hostbasedAuthentication", async (_hook, context, decision) => {
            await Promise.resolve()
            contexts.push(context)
            decision.allowLogin =
                context.username === "remote" &&
                context.clientHostname === "client.example" &&
                context.clientUsername === "alice" &&
                context.publicKey.equals(clientHostKey.data.publicKey) &&
                context.publicKey.verifySignature(context.signatureMessage, context.signature)
        })
        server.on("connection", (connection) =>
            connection.on("error", (error) => errors.push(error)),
        )
        server.listen({ host: "127.0.0.1", port: 0 })
        await new Promise<void>((resolve) => server.server!.once("listening", resolve))
        const port = (server.server!.address() as AddressInfo).port

        const client = new Client({
            hostname: "127.0.0.1",
            port,
            username: "remote",
            hostbased: {
                key: clientHostKey,
                localHostname: "client.example",
                localUsername: "alice",
            },
            authenticationMethodsOrder: [
                SSHAuthenticationMethods.None,
                SSHAuthenticationMethods.Hostbased,
            ],
        })
        client.on("error", (error) => errors.push(error))
        client.hooker.hook("hostKey", (_hook, decision) => {
            decision.allowHostKey = true
        })

        try {
            await client.connect()
            expect(client.isConnected).toBe(true)
            expect(contexts).toHaveLength(1)
            expect((contexts[0] as { remoteAddress?: string }).remoteAddress).toBe("127.0.0.1")
            expect(errors).toEqual([])
        } finally {
            client.destroy()
            for (const connection of server.clients) connection.terminate()
            await new Promise<void>((resolve, reject) => {
                server.server!.close((error) => (error ? reject(error) : resolve()))
            })
        }
    }, 15_000)

    test("rejects an invalid hostbased signature before invoking application policy", async () => {
        const serverHostKey = await PrivateKey.generate("ssh-ed25519")
        const clientHostKey = await PrivateKey.generate("ssh-ed25519")
        clientHostKey.sign = (_data, algorithm = "ssh-ed25519") =>
            new EncodedSignature({ alg: algorithm, data: Buffer.alloc(64) })
        const server = new Server({ hostKeys: [serverHostKey], sendAllHostKeys: false })
        let policyCalls = 0
        server.hooker.hook("hostbasedAuthentication", () => {
            policyCalls++
        })
        server.listen({ host: "127.0.0.1", port: 0 })
        await new Promise<void>((resolve) => server.server!.once("listening", resolve))
        const port = (server.server!.address() as AddressInfo).port
        const client = new Client({
            hostname: "127.0.0.1",
            port,
            username: "remote",
            hostbased: {
                key: clientHostKey,
                localHostname: "client.example",
                localUsername: "alice",
            },
            authenticationMethodsOrder: [
                SSHAuthenticationMethods.None,
                SSHAuthenticationMethods.Hostbased,
            ],
        })
        client.hooker.hook("hostKey", (_hook, decision) => {
            decision.allowHostKey = true
        })

        try {
            await expect(client.connect()).rejects.toThrow("All authentication methods failed")
            expect(policyCalls).toBe(0)
        } finally {
            client.destroy()
            for (const connection of server.clients) connection.terminate()
            await new Promise<void>((resolve, reject) => {
                server.server!.close((error) => (error ? reject(error) : resolve()))
            })
        }
    }, 15_000)

    test("restarts advertised method selection after partial success", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({
            hostKeys: [hostKey],
            sendAllHostKeys: false,
            maxAuthenticationAttempts: 2,
        })
        const passwordCompleted = new WeakSet<ServerClient>()
        const attempts: string[] = []
        const errors: Error[] = []
        const debugOutput: unknown[] = []

        server.hooker.hook("passwordAuthentication", (_hook, context, decision, connection) => {
            attempts.push("password")
            if (context.password !== "first-factor") return
            passwordCompleted.add(connection)
            decision.partialSuccess = true
            decision.authenticationMethods = [SSHAuthenticationMethods.KeyboardInteractive]
        })
        server.hooker.hook(
            "keyboardInteractiveAuthentication",
            (_hook, context, decision, connection) => {
                attempts.push(`keyboard:${context.round}`)
                if (!passwordCompleted.has(connection)) return
                if (context.round === 0) {
                    decision.prompts = [{ prompt: "Second factor: ", echo: false }]
                } else {
                    decision.allowLogin = context.responses?.[0] === "654321"
                }
            },
        )
        server.on("connection", (connection) =>
            connection.on("error", (error) => errors.push(error)),
        )
        server.on("debug", (...message) => debugOutput.push(message))
        server.listen({ host: "127.0.0.1", port: 0 })
        await new Promise<void>((resolve) => server.server!.once("listening", resolve))
        const port = (server.server!.address() as AddressInfo).port

        const client = new Client({
            hostname: "127.0.0.1",
            port,
            username: "interop",
            password: "first-factor",
            authenticationMethodsOrder: [
                SSHAuthenticationMethods.None,
                SSHAuthenticationMethods.KeyboardInteractive,
                SSHAuthenticationMethods.Password,
            ],
        })
        client.on("error", (error) => errors.push(error))
        client.on("debug", (...message) => debugOutput.push(message))
        client.hooker.hook("hostKey", (_hook, decision) => {
            decision.allowHostKey = true
        })
        client.hooker.hook("keyboardInteractive", (_hook, context, decision) => {
            decision.responses = context.prompts.map(() => "654321")
        })

        try {
            await client.connect()
            expect(client.isConnected).toBe(true)
            expect([...client.authenticationMethodsRemaining!]).toEqual([
                SSHAuthenticationMethods.KeyboardInteractive,
            ])
            expect(client.partialAuthenticationSuccess).toBe(true)
            expect(attempts).toEqual(["keyboard:0", "password", "keyboard:0", "keyboard:1"])
            expect(errors).toEqual([])
            const serializedDebug = JSON.stringify(debugOutput)
            expect(serializedDebug).not.toContain("first-factor")
            expect(serializedDebug).not.toContain("654321")
            expect(serializedDebug).not.toContain("sharedSecret")
            expect(serializedDebug).not.toContain("encryptionKeyClientToServer")
        } finally {
            client.destroy()
            for (const connection of server.clients) connection.terminate()
            await new Promise<void>((resolve, reject) => {
                server.server!.close((error) => (error ? reject(error) : resolve()))
            })
        }
    }, 15_000)

    test("disconnects after the configured number of rejected attempts", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({
            hostKeys: [hostKey],
            sendAllHostKeys: false,
            maxAuthenticationAttempts: 1,
        })
        let passwordAttempts = 0
        server.hooker.hook("passwordAuthentication", async () => {
            await Promise.resolve()
            passwordAttempts++
        })
        server.listen({ host: "127.0.0.1", port: 0 })
        await new Promise<void>((resolve) => server.server!.once("listening", resolve))
        const port = (server.server!.address() as AddressInfo).port
        const client = new Client({
            hostname: "127.0.0.1",
            port,
            username: "limited",
            password: "incorrect",
            authenticationMethodsOrder: [
                SSHAuthenticationMethods.None,
                SSHAuthenticationMethods.Password,
            ],
        })
        const disconnects: Disconnect[] = []
        client.on("packet", (packet) => {
            if (packet instanceof Disconnect) disconnects.push(packet)
        })
        client.hooker.hook("hostKey", (_hook, decision) => {
            decision.allowHostKey = true
        })

        try {
            await expect(client.connect()).rejects.toThrow()
            expect(passwordAttempts).toBe(1)
            expect(disconnects).toHaveLength(1)
            expect(disconnects[0].data).toEqual({
                reason_code: DisconnectReason.SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE,
                description: "Too many authentication failures",
                language_tag: "",
            })
        } finally {
            client.destroy()
            for (const connection of server.clients) connection.terminate()
            await new Promise<void>((resolve, reject) => {
                server.server!.close((error) => (error ? reject(error) : resolve()))
            })
        }
    }, 15_000)

    test("expires an awaited authentication hook without accepting its late decision", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({
            hostKeys: [hostKey],
            sendAllHostKeys: false,
            authenticationTimeout: 50,
        })
        let releasePolicy!: () => void
        const policyRelease = new Promise<void>((resolve) => {
            releasePolicy = resolve
        })
        let policyStarted!: () => void
        const started = new Promise<void>((resolve) => {
            policyStarted = resolve
        })
        server.hooker.hook("passwordAuthentication", async (_hook, _context, decision) => {
            policyStarted()
            await policyRelease
            decision.allowLogin = true
        })
        server.listen({ host: "127.0.0.1", port: 0 })
        await new Promise<void>((resolve) => server.server!.once("listening", resolve))
        const port = (server.server!.address() as AddressInfo).port
        const client = new Client({
            hostname: "127.0.0.1",
            port,
            username: "slow-policy",
            password: "correct",
            authenticationMethodsOrder: [SSHAuthenticationMethods.Password],
        })
        const disconnects: Disconnect[] = []
        client.on("packet", (packet) => {
            if (packet instanceof Disconnect) disconnects.push(packet)
        })
        client.hooker.hook("hostKey", (_hook, decision) => {
            decision.allowHostKey = true
        })

        try {
            const connection = client.connect()
            await started
            await expect(connection).rejects.toThrow()
            expect(disconnects).toHaveLength(1)
            expect(disconnects[0].data.reason_code).toBe(
                DisconnectReason.SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE,
            )
            expect(disconnects[0].data.description).toBe("Authentication timed out")
            releasePolicy()
            await new Promise<void>((resolve) => setImmediate(resolve))
            expect(client.isConnected).toBe(false)
            expect([...server.clients].every((peer) => !peer.hasAuthenticated)).toBe(true)
        } finally {
            releasePolicy()
            client.destroy()
            for (const connection of server.clients) connection.terminate()
            await new Promise<void>((resolve, reject) => {
                server.server!.close((error) => (error ? reject(error) : resolve()))
            })
        }
    }, 15_000)
})
