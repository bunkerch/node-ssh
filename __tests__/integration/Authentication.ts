import { AddressInfo } from "node:net"
import { once } from "node:events"
import Client from "../../src/Client.js"
import { SSHAuthenticationMethods } from "../../src/constants.js"
import { DisconnectReason, type PeerDisconnectInfo } from "../../src/packets/Disconnect.js"
import Server from "../../src/Server.js"
import type ServerClient from "../../src/ServerClient.js"
import PrivateKey from "../../src/utils/PrivateKey.js"
import PublicKey from "../../src/utils/PublicKey.js"
import EncodedSignature from "../../src/utils/Signature.js"
import PrivateKeyAgent from "../../src/publickey/PrivateKeyAgent.js"
import Packet from "../../src/packet.js"
import UserAuthRequest from "../../src/packets/UserAuthRequest.js"
import { HostboundPublicKeyAuthMethod } from "../../src/auth/publickey.js"
import ExtInfo from "../../src/packets/ExtInfo.js"
import type { ProtocolPacketMetadata } from "../../src/packet.js"

describe("RFC 4252 multi-method authentication", () => {
    test("rejects malformed authentication method orders during construction", () => {
        expect(() => new Client({ authenticationMethodsOrder: [] })).toThrow(
            "SSH authentication method order must contain at least one method",
        )
        expect(
            () =>
                new Client({
                    authenticationMethodsOrder: [
                        SSHAuthenticationMethods.None,
                        SSHAuthenticationMethods.None,
                    ],
                }),
        ).toThrow("SSH authentication method order contains duplicate method: none")
        expect(
            () =>
                new Client({
                    authenticationMethodsOrder: ["future-auth" as SSHAuthenticationMethods],
                }),
        ).toThrow("SSH authentication method order contains an unsupported method: future-auth")
    })

    test("owns the configured authentication method order before connecting", async () => {
        const server = new Server({
            hostKeys: [await PrivateKey.generate("ssh-ed25519")],
            sendAllHostKeys: false,
        })
        let noneAttempts = 0
        server.hooker.hook("noneAuthentication", (_hook, _context, decision) => {
            noneAttempts++
            decision.allowLogin = true
        })
        server.listen({ host: "127.0.0.1", port: 0 })
        await once(server, "listening")

        const authenticationMethodsOrder = [SSHAuthenticationMethods.None]
        const client = new Client({
            hostname: "127.0.0.1",
            port: (server.address() as AddressInfo).port,
            username: "owned-method-order",
            authenticationMethodsOrder,
        })
        client.hooker.hook("hostKey", (_hook, decision) => {
            decision.allowHostKey = true
        })
        authenticationMethodsOrder[0] = SSHAuthenticationMethods.Password

        try {
            await client.connect()
            expect(client.isConnected).toBe(true)
            expect(noneAttempts).toBe(1)
        } finally {
            client.destroy()
            for (const connection of server.clients) connection.terminate()
            await server.close()
        }
    }, 15_000)

    test("exposes authenticated identity without retaining the successful credential packet", async () => {
        const server = new Server({
            hostKeys: [await PrivateKey.generate("ssh-ed25519")],
            sendAllHostKeys: false,
        })
        let connection: ServerClient | undefined
        const observedPackets: Readonly<ProtocolPacketMetadata>[] = []
        server.hooker.hook("passwordAuthentication", (_hook, context, decision) => {
            decision.allowLogin =
                context.username === "credential-owner" && context.password === "secret"
        })
        server.on("connection", (peer) => {
            connection = peer
            expect(peer.username).toBeUndefined()
            expect(peer.authenticationMethod).toBeUndefined()
            peer.on("packet", (metadata) => observedPackets.push(metadata))
        })
        server.listen({ host: "127.0.0.1", port: 0 })
        await once(server, "listening")

        const client = new Client({
            hostname: "127.0.0.1",
            port: (server.address() as AddressInfo).port,
            username: "credential-owner",
            password: "secret",
            authenticationMethodsOrder: [SSHAuthenticationMethods.Password],
        })
        client.hooker.hook("hostKey", (_hook, decision) => {
            decision.allowHostKey = true
        })

        try {
            await client.connect()
            expect(connection?.username).toBe("credential-owner")
            expect(connection?.authenticationMethod).toBe(SSHAuthenticationMethods.Password)
            expect("credentials" in connection!).toBe(false)
            expect(connection!.eventNames().some((event) => typeof event === "symbol")).toBe(false)
            const authenticationPacket = observedPackets.find(
                ({ name }) => name === "SSH_MSG_USERAUTH_REQUEST",
            )
            expect(authenticationPacket).toBeDefined()
            expect(Object.isFrozen(authenticationPacket)).toBe(true)
            expect(Object.keys(authenticationPacket!).sort()).toEqual([
                "name",
                "sequenceNumber",
                "type",
            ])
            expect(JSON.stringify(authenticationPacket)).not.toContain("secret")
        } finally {
            client.destroy()
            for (const peer of server.clients) peer.terminate()
            await server.close()
        }
    }, 15_000)

    test("completes rekeys initiated by both roles during authentication", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({ hostKeys: [hostKey], sendAllHostKeys: false })
        const errors: Error[] = []
        let serverRekeys = 0
        server.hooker.hook(
            "passwordAuthentication",
            async (_hook, context, decision, connection) => {
                await connection.rekey()
                decision.allowLogin = context.password === "secret"
            },
        )
        server.on("connection", (connection) => {
            connection.on("error", (error) => errors.push(error))
            connection.on("rekey", () => serverRekeys++)
        })
        server.listen({ host: "127.0.0.1", port: 0 })
        await once(server.server!, "listening")

        const client = new Client({
            hostname: "127.0.0.1",
            port: (server.server!.address() as AddressInfo).port,
            username: "rekey-user",
            password: "secret",
            authenticationMethodsOrder: [SSHAuthenticationMethods.Password],
        })
        let clientInitiated = false
        let clientRekeys = 0
        client.on("error", (error) => errors.push(error))
        client.on("rekey", () => clientRekeys++)
        client.hooker.hook("hostKey", (_hook, decision) => {
            decision.allowHostKey = true
        })
        client.hooker.hook("authenticationMethod", async () => {
            if (clientInitiated) return
            clientInitiated = true
            await client.rekey()
        })

        try {
            await client.connect()
            expect(client.isConnected).toBe(true)
            expect(clientRekeys).toBe(2)
            expect(serverRekeys).toBe(2)
            expect(errors).toEqual([])
        } finally {
            client.destroy()
            for (const connection of server.clients) connection.terminate()
            await server.close()
        }
    }, 15_000)

    test("stops authentication when method selection policy fails", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({ hostKeys: [hostKey], sendAllHostKeys: false })
        let noneAttempts = 0
        server.hooker.hook("noneAuthentication", (_hook, _context, decision) => {
            noneAttempts++
            decision.allowLogin = true
        })
        server.listen({ host: "127.0.0.1", port: 0 })
        await once(server.server!, "listening")

        const client = new Client({
            hostname: "127.0.0.1",
            port: (server.server!.address() as AddressInfo).port,
            username: "failed-selection-policy",
            authenticationMethodsOrder: [SSHAuthenticationMethods.None],
        })
        const hookErrors: Error[] = []
        client.hooker.on("uncaughtException", (_event, error) => hookErrors.push(error))
        client.hooker.hook("hostKey", (_hook, decision) => {
            decision.allowHostKey = true
        })
        client.hooker.hook("authenticationMethod", (_hook, _context, decision) => {
            decision.method = SSHAuthenticationMethods.None
        })
        client.hooker.hook("authenticationMethod", async () => {
            await Promise.resolve()
            throw new Error("authentication selector backend failed")
        })

        try {
            await expect(client.connect()).rejects.toThrow("Authentication method policy failed")
            expect(noneAttempts).toBe(0)
            expect(hookErrors.map((error) => error.message)).toEqual([
                "authentication selector backend failed",
            ])
        } finally {
            client.destroy()
            for (const connection of server.clients) connection.terminate()
            await server.close()
        }
    }, 15_000)

    test("does not send a password after a later credential hook failure", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({ hostKeys: [hostKey], sendAllHostKeys: false })
        let passwordAttempts = 0
        server.hooker.hook("passwordAuthentication", (_hook, context, decision) => {
            passwordAttempts++
            decision.allowLogin = context.password === "secret"
        })
        server.listen({ host: "127.0.0.1", port: 0 })
        await once(server.server!, "listening")

        const client = new Client({
            hostname: "127.0.0.1",
            port: (server.server!.address() as AddressInfo).port,
            username: "failed-password-policy",
            authenticationMethodsOrder: [SSHAuthenticationMethods.Password],
        })
        const hookErrors: Error[] = []
        client.hooker.on("uncaughtException", (_event, error) => hookErrors.push(error))
        client.hooker.hook("hostKey", (_hook, decision) => {
            decision.allowHostKey = true
        })
        client.hooker.hook("passwordAuth", (_hook, _context, decision) => {
            decision.password = "secret"
        })
        client.hooker.hook("passwordAuth", async () => {
            await Promise.resolve()
            throw new Error("password provider backend failed")
        })

        try {
            await expect(client.connect()).rejects.toThrow("All authentication methods failed")
            expect(passwordAttempts).toBe(0)
            expect(hookErrors.map((error) => error.message)).toEqual([
                "password provider backend failed",
            ])
        } finally {
            client.destroy()
            for (const connection of server.clients) connection.terminate()
            await server.close()
        }
    }, 15_000)

    test("does not send challenge responses after a later credential hook failure", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({ hostKeys: [hostKey], sendAllHostKeys: false })
        const rounds: number[] = []
        server.hooker.hook("keyboardInteractiveAuthentication", (_hook, context, decision) => {
            rounds.push(context.round)
            if (context.round === 0) {
                decision.prompts = [{ prompt: "Code: ", echo: false }]
            } else {
                decision.allowLogin = context.responses?.[0] === "654321"
            }
        })
        server.listen({ host: "127.0.0.1", port: 0 })
        await once(server.server!, "listening")

        const client = new Client({
            hostname: "127.0.0.1",
            port: (server.server!.address() as AddressInfo).port,
            username: "failed-challenge-policy",
            authenticationMethodsOrder: [SSHAuthenticationMethods.KeyboardInteractive],
        })
        const hookErrors: Error[] = []
        client.hooker.on("uncaughtException", (_event, error) => hookErrors.push(error))
        client.hooker.hook("hostKey", (_hook, decision) => {
            decision.allowHostKey = true
        })
        client.hooker.hook("keyboardInteractive", (_hook, _context, decision) => {
            decision.responses = ["654321"]
        })
        client.hooker.hook("keyboardInteractive", async () => {
            await Promise.resolve()
            throw new Error("challenge provider backend failed")
        })

        try {
            await expect(client.connect()).rejects.toThrow("All authentication methods failed")
            expect(rounds).toEqual([0])
            expect(hookErrors.map((error) => error.message)).toEqual([
                "challenge provider backend failed",
            ])
        } finally {
            client.destroy()
            for (const connection of server.clients) connection.terminate()
            await server.close()
        }
    }, 15_000)

    test("does not send a replacement password after a later credential hook failure", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({ hostKeys: [hostKey], sendAllHostKeys: false })
        const attempts: { password: string; newPassword?: string }[] = []
        server.hooker.hook("passwordAuthentication", (_hook, context, decision) => {
            attempts.push({ password: context.password, newPassword: context.newPassword })
            if (context.newPassword === undefined) {
                decision.requestPasswordChange = { prompt: "Choose a new password: " }
            } else {
                decision.allowLogin = true
            }
        })
        server.listen({ host: "127.0.0.1", port: 0 })
        await once(server.server!, "listening")

        const client = new Client({
            hostname: "127.0.0.1",
            port: (server.server!.address() as AddressInfo).port,
            username: "failed-password-change-policy",
            password: "current-password",
            authenticationMethodsOrder: [SSHAuthenticationMethods.Password],
        })
        const hookErrors: Error[] = []
        client.hooker.on("uncaughtException", (_event, error) => hookErrors.push(error))
        client.hooker.hook("hostKey", (_hook, decision) => {
            decision.allowHostKey = true
        })
        client.hooker.hook("passwordChange", (_hook, _context, decision) => {
            decision.newPassword = "replacement-password"
        })
        client.hooker.hook("passwordChange", async () => {
            await Promise.resolve()
            throw new Error("password change backend failed")
        })

        try {
            await expect(client.connect()).rejects.toThrow("All authentication methods failed")
            expect(attempts).toEqual([{ password: "current-password", newPassword: undefined }])
            expect(hookErrors.map((error) => error.message)).toEqual([
                "password change backend failed",
            ])
        } finally {
            client.destroy()
            for (const connection of server.clients) connection.terminate()
            await server.close()
        }
    }, 15_000)

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
                ["server-sig-algs", "ping@openssh.com", "agent-forward"],
                ["authenticated@example.test"],
            ])
            expect(client.rfc9987AgentForwarding).toBe(false)
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

    test("replaces extension information between negotiated authentication requests", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({ hostKeys: [hostKey], sendAllHostKeys: false })
        const errors: Error[] = []
        const rejectedSends: string[] = []
        let connection: ServerClient | undefined
        server.hooker.hook("passwordAuthentication", (_hook, context, decision, peer) => {
            const policy = Buffer.from(context.username)
            peer.sendAuthenticationExtensions([
                {
                    name: "server-sig-algs",
                    value: Buffer.from("ssh-ed25519", "ascii"),
                },
                {
                    name: "per-user@example.test",
                    value: policy,
                },
            ])
            policy.fill(0)
            expect(() => peer.sendAuthenticationExtensions([])).toThrow(
                "already sent authentication extension information",
            )
            decision.partialSuccess = true
            decision.authenticationMethods = [SSHAuthenticationMethods.KeyboardInteractive]
        })
        server.hooker.hook("keyboardInteractiveAuthentication", (_hook, context, decision) => {
            if (context.round === 0) {
                decision.prompts = [{ prompt: "Second factor: ", echo: false }]
            } else {
                decision.allowLogin = context.responses?.[0] === "654321"
            }
        })
        server.on("connection", (peer) => {
            connection = peer
            peer.on("error", (error) => errors.push(error))
            try {
                peer.sendAuthenticationExtensions([])
            } catch (error) {
                rejectedSends.push((error as Error).message)
            }
            peer.on("clientExtensions", () => {
                try {
                    peer.sendAuthenticationExtensions([])
                } catch (error) {
                    rejectedSends.push((error as Error).message)
                }
            })
        })
        server.listen({ host: "127.0.0.1", port: 0 })
        await once(server.server!, "listening")

        const client = new Client({
            hostname: "127.0.0.1",
            port: (server.server!.address() as AddressInfo).port,
            username: "extension-user",
            password: "first-factor",
            authenticationMethodsOrder: [
                SSHAuthenticationMethods.Password,
                SSHAuthenticationMethods.KeyboardInteractive,
            ],
        })
        const extensionSets: string[][] = []
        client.on("error", (error) => errors.push(error))
        client.on("serverExtensions", (extensions) => {
            extensionSets.push(extensions.map(({ name }) => name))
        })
        client.hooker.hook("hostKey", (_hook, decision) => {
            decision.allowHostKey = true
        })
        client.hooker.hook("keyboardInteractive", (_hook, context, decision) => {
            decision.responses = context.prompts.map(() => "654321")
        })

        try {
            await client.connect()
            expect(connection!.clientExtensions).toEqual([
                { name: "ext-info-in-auth@openssh.com", value: Buffer.alloc(0) },
            ])
            expect(extensionSets).toEqual([
                ["server-sig-algs", "ping@openssh.com", "agent-forward"],
                ["server-sig-algs", "per-user@example.test"],
            ])
            expect(client.serverSignatureAlgorithms).toEqual(["ssh-ed25519"])
            expect(client.serverExtensions[1]).toEqual({
                name: "per-user@example.test",
                value: Buffer.from("extension-user"),
            })
            expect(rejectedSends).toEqual([
                "SSH client did not advertise authentication extension information",
                "Authentication extension information requires an active authentication request",
            ])
            expect(() => connection!.sendAuthenticationExtensions([])).toThrow(
                "after authentication",
            )
            expect(errors).toEqual([])
        } finally {
            client.destroy()
            for (const peer of server.clients) peer.terminate()
            await server.close()
        }
    }, 15_000)

    test("rejects duplicate negotiated authentication extension updates", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({ hostKeys: [hostKey], sendAllHostKeys: false })
        server.hooker.hook("passwordAuthentication", (_hook, _context, decision, peer) => {
            peer.sendAuthenticationExtensions([
                { name: "first@example.test", value: Buffer.alloc(0) },
            ])
            peer.sendPacket(
                new ExtInfo({
                    extensions: [{ name: "duplicate@example.test", value: Buffer.alloc(0) }],
                }),
            )
            decision.authenticationMethods = [SSHAuthenticationMethods.Password]
        })
        server.listen({ host: "127.0.0.1", port: 0 })
        await once(server.server!, "listening")

        const client = new Client({
            hostname: "127.0.0.1",
            port: (server.server!.address() as AddressInfo).port,
            username: "extension-user",
            password: "rejected",
            authenticationMethodsOrder: [SSHAuthenticationMethods.Password],
        })
        client.hooker.hook("hostKey", (_hook, decision) => {
            decision.allowHostKey = true
        })

        try {
            await expect(client.connect()).rejects.toThrow(
                "duplicate authentication extension information",
            )
        } finally {
            client.destroy()
            for (const peer of server.clients) peer.terminate()
            await server.close()
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
            privateKey: userKey.toString({ passphrase: "bound-key-secret", rounds: 1 }),
            passphrase: "bound-key-secret",
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

    test("owns client host identity before awaited hostbased authentication", async () => {
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

        const hostbased = {
            key: clientHostKey,
            localHostname: "client.example",
            localUsername: "alice",
        }
        const client = new Client({
            hostname: "127.0.0.1",
            port,
            username: "remote",
            hostbased,
            authenticationMethodsOrder: [
                SSHAuthenticationMethods.None,
                SSHAuthenticationMethods.Hostbased,
            ],
        })
        client.on("error", (error) => errors.push(error))
        client.hooker.hook("hostKey", (_hook, decision) => {
            decision.allowHostKey = true
        })
        hostbased.localHostname = "changed.example"
        hostbased.localUsername = "mallory"

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

    test.each([
        { explicitOrder: false, authenticates: true },
        { explicitOrder: true, authenticates: false },
    ])(
        "uses an awaited keyboard-interactive hook with default ordering: $explicitOrder",
        async ({ explicitOrder, authenticates }) => {
            const hostKey = await PrivateKey.generate("ssh-ed25519")
            const server = new Server({ hostKeys: [hostKey], sendAllHostKeys: false })
            let policyCalls = 0
            server.hooker.hook("keyboardInteractiveAuthentication", (_hook, context, decision) => {
                policyCalls++
                if (context.round === 0) {
                    decision.prompts = [{ prompt: "Verification code: ", echo: false }]
                } else {
                    decision.allowLogin = context.responses?.[0] === "123456"
                }
            })
            server.listen({ host: "127.0.0.1", port: 0 })
            await new Promise<void>((resolve) => server.server!.once("listening", resolve))

            const client = new Client({
                hostname: "127.0.0.1",
                port: (server.server!.address() as AddressInfo).port,
                username: "interactive-default",
                ...(explicitOrder
                    ? { authenticationMethodsOrder: [SSHAuthenticationMethods.None] }
                    : {}),
            })
            client.hooker.hook("hostKey", (_hook, decision) => {
                decision.allowHostKey = true
            })
            client.hooker.hook("keyboardInteractive", async (_hook, context, decision) => {
                await Promise.resolve()
                decision.responses = context.prompts.map(() => "123456")
            })

            try {
                if (authenticates) {
                    await client.connect()
                    expect(client.isConnected).toBe(true)
                    expect(policyCalls).toBe(2)
                } else {
                    await expect(client.connect()).rejects.toThrow(
                        "All authentication methods failed",
                    )
                    expect(policyCalls).toBe(0)
                }
                expect("options" in client).toBe(false)
            } finally {
                client.destroy()
                for (const connection of server.clients) connection.terminate()
                await new Promise<void>((resolve, reject) => {
                    server.server!.close((error) => (error ? reject(error) : resolve()))
                })
            }
        },
        15_000,
    )

    test("restarts advertised method selection after partial success", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({
            hostKeys: [hostKey],
            sendAllHostKeys: false,
            maxAuthenticationAttempts: 2,
        })
        const passwordCompleted = new WeakSet<ServerClient>()
        const attempts: string[] = []
        const selections: {
            attemptedMethods: readonly SSHAuthenticationMethods[]
            defaultMethod: SSHAuthenticationMethods
            methodsRemaining: readonly SSHAuthenticationMethods[] | undefined
            partialSuccess: boolean
        }[] = []
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
        client.hooker.hook("authenticationMethod", async (_hook, context, decision) => {
            await Promise.resolve()
            expect(Object.isFrozen(context)).toBe(true)
            expect(Object.isFrozen(context.attemptedMethods)).toBe(true)
            if (context.methodsRemaining)
                expect(Object.isFrozen(context.methodsRemaining)).toBe(true)
            selections.push(context)
            if (!context.methodsRemaining) decision.method = SSHAuthenticationMethods.Password
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
            expect(attempts).toEqual(["password", "keyboard:0", "keyboard:1"])
            expect(selections).toEqual([
                {
                    attemptedMethods: [],
                    defaultMethod: SSHAuthenticationMethods.None,
                    methodsRemaining: undefined,
                    partialSuccess: false,
                },
                {
                    attemptedMethods: [],
                    defaultMethod: SSHAuthenticationMethods.KeyboardInteractive,
                    methodsRemaining: [SSHAuthenticationMethods.KeyboardInteractive],
                    partialSuccess: true,
                },
            ])
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

    test("rejects a selected method outside the server continuation list", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({ hostKeys: [hostKey], sendAllHostKeys: false })
        let passwordPolicyCalls = 0
        server.hooker.hook("passwordAuthentication", () => {
            passwordPolicyCalls += 1
        })
        server.listen({ host: "127.0.0.1", port: 0 })
        await new Promise<void>((resolve) => server.server!.once("listening", resolve))

        const client = new Client({
            hostname: "127.0.0.1",
            port: (server.server!.address() as AddressInfo).port,
            username: "selection-policy",
            authenticationMethodsOrder: [
                SSHAuthenticationMethods.None,
                SSHAuthenticationMethods.Password,
                SSHAuthenticationMethods.KeyboardInteractive,
            ],
        })
        client.hooker.hook("hostKey", (_hook, decision) => {
            decision.allowHostKey = true
        })
        client.hooker.hook("authenticationMethod", (_hook, context, decision) => {
            if (context.methodsRemaining) {
                decision.method = SSHAuthenticationMethods.KeyboardInteractive
            }
        })

        try {
            await expect(client.connect()).rejects.toThrow(
                "Selected SSH authentication method was not advertised by the server: keyboard-interactive",
            )
            expect(passwordPolicyCalls).toBe(0)
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
        const disconnects: Readonly<PeerDisconnectInfo>[] = []
        client.on("disconnect", (info) => disconnects.push(info))
        client.hooker.hook("hostKey", (_hook, decision) => {
            decision.allowHostKey = true
        })

        try {
            await expect(client.connect()).rejects.toThrow()
            expect(passwordAttempts).toBe(1)
            expect(disconnects).toHaveLength(1)
            expect(disconnects[0]).toEqual({
                reasonCode: DisconnectReason.SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE,
                description: "Too many authentication failures",
                languageTag: "",
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
        const disconnects: Readonly<PeerDisconnectInfo>[] = []
        client.on("disconnect", (info) => disconnects.push(info))
        client.hooker.hook("hostKey", (_hook, decision) => {
            decision.allowHostKey = true
        })

        try {
            const connection = client.connect()
            await started
            await expect(connection).rejects.toThrow()
            expect(disconnects).toHaveLength(1)
            expect(disconnects[0].reasonCode).toBe(
                DisconnectReason.SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE,
            )
            expect(disconnects[0].description).toBe("Authentication timed out")
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

    test("does not send an old password decision on a reconnected transport", async () => {
        const server = new Server({
            hostKeys: [await PrivateKey.generate("ssh-ed25519")],
            sendAllHostKeys: false,
        })
        server.hooker.hook("passwordAuthentication", (_hook, context, decision) => {
            decision.allowLogin = context.password === "correct"
        })
        server.on("connection", (connection) => connection.on("error", () => undefined))
        server.listen({ host: "127.0.0.1", port: 0 })
        await once(server, "listening")

        let releaseOldPassword!: () => void
        const oldPasswordReleased = new Promise<void>((resolve) => {
            releaseOldPassword = resolve
        })
        let reportOldPassword!: () => void
        const oldPasswordStarted = new Promise<void>((resolve) => {
            reportOldPassword = resolve
        })
        let passwordRequests = 0
        const client = new Client({
            hostname: "127.0.0.1",
            port: (server.address() as AddressInfo).port,
            username: "password-reconnect",
            authenticationMethodsOrder: [SSHAuthenticationMethods.Password],
        })
        client.on("error", () => undefined)
        client.hooker.hook("hostKey", (_hook, decision) => {
            decision.allowHostKey = true
        })
        client.hooker.hook("passwordAuth", async (_hook, _context, decision) => {
            passwordRequests++
            if (passwordRequests === 1) {
                reportOldPassword()
                await oldPasswordReleased
            }
            decision.password = "correct"
        })

        try {
            const oldConnection = client.connect().then(
                () => undefined,
                (error: unknown) => error,
            )
            await oldPasswordStarted

            const oldTransportClosed = once(client, "close")
            client.destroy()
            await oldTransportClosed

            await client.connect()
            expect(passwordRequests).toBe(2)
            expect(client.isConnected).toBe(true)

            releaseOldPassword()
            expect(await oldConnection).toBeInstanceOf(Error)
            await new Promise<void>((resolve) => setImmediate(resolve))
            expect(client.isConnected).toBe(true)
        } finally {
            releaseOldPassword()
            client.destroy()
            for (const connection of server.clients) connection.terminate()
            await server.close()
        }
    }, 15_000)
})
