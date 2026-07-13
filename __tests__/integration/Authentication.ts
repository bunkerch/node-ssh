import { AddressInfo } from "node:net"
import Client from "../../src/Client.js"
import { SSHAuthenticationMethods } from "../../src/constants.js"
import Server from "../../src/Server.js"
import type ServerClient from "../../src/ServerClient.js"
import PrivateKey from "../../src/utils/PrivateKey.js"
import EncodedSignature from "../../src/utils/Signature.js"

describe("RFC 4252 multi-method authentication", () => {
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
        const server = new Server({ hostKeys: [hostKey], sendAllHostKeys: false })
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
})
