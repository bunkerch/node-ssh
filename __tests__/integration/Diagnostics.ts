import Client from "../../src/Client.js"
import Server from "../../src/Server.js"
import { once } from "node:events"
import { type AddressInfo } from "node:net"
import { PassThrough } from "node:stream"
import PrivateKeyAgent from "../../src/publickey/PrivateKeyAgent.js"
import PrivateKey from "../../src/utils/PrivateKey.js"
import { AgentType, type Agent } from "../../src/publickey/Agent.js"
import { SSHAuthenticationMethods } from "../../src/constants.js"

describe("configured diagnostic sinks", () => {
    test("receives an allow-listed client configuration summary without secret-bearing objects", async () => {
        const authenticationKey = await PrivateKey.generate("ssh-ed25519")
        const hostbasedKey = await PrivateKey.generate("ssh-ed25519")
        Object.assign(hostbasedKey, { diagnosticSecret: "hostbased-private-metadata" })
        const agent = new PrivateKeyAgent(authenticationKey)
        Object.assign(agent, { diagnosticSecret: "agent-private-metadata" })
        const socket = new PassThrough()
        Object.assign(socket, { diagnosticSecret: "transport-private-metadata" })
        const hostVerifier = Object.assign(() => true, {
            diagnosticSecret: "verifier-private-metadata",
        })
        const configured: unknown[][] = []
        const emitted: unknown[][] = []
        const client = new Client({
            username: "diagnostic-user",
            password: "diagnostic-secret",
            agent,
            hostbased: {
                key: hostbasedKey,
                localHostname: "client.example.com",
                localUsername: "local-user",
            },
            hostVerifier,
            ident: Buffer.from("identifier_private_metadata"),
            sock: socket,
            debug: (...message) => configured.push(message),
        })
        client.on("debug", (...message) => emitted.push(message))

        await new Promise<void>((resolve) => setImmediate(resolve))

        expect(configured).toEqual(emitted)
        expect(configured[0]?.[0]).toBe("Client created with options:")
        const summary = configured[0]?.[1] as Record<string, unknown>
        expect(summary).toMatchObject({
            username: "diagnostic-user",
            password: "<redacted>",
            agent: "<configured>",
            hostVerifier: "<configured>",
            hostbased: "<configured>",
            sock: "<configured>",
            debug: "<configured>",
        })
        expect(
            Object.values(summary).every(
                (value) =>
                    value === undefined ||
                    typeof value === "string" ||
                    typeof value === "number" ||
                    typeof value === "boolean",
            ),
        ).toBe(true)
        const output = JSON.stringify(configured)
        expect(output).toContain("<redacted>")
        expect(output).toContain("<configured>")
        expect(output).not.toContain("diagnostic-secret")
        expect(output).not.toContain("hostbased-private-metadata")
        expect(output).not.toContain("agent-private-metadata")
        expect(output).not.toContain("transport-private-metadata")
        expect(output).not.toContain("verifier-private-metadata")
        expect(output).not.toContain("identifier_private_metadata")
    })

    test("receives the same server diagnostic arguments", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const configured: unknown[][] = []
        const emitted: unknown[][] = []
        const server = new Server({
            hostKeys: [hostKey],
            debug: (...message) => configured.push(message),
        })
        server.on("debug", (...message) => emitted.push(message))

        server.debug("server diagnostic", { ready: true })

        expect(configured).toEqual([["server diagnostic", { ready: true }]])
        expect(configured).toEqual(emitted)
    })

    test("does not expose opaque agent identity IDs or key comments", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const identity = await PrivateKey.generate("ssh-ed25519")
        const publicKey = identity.data.publicKey
        publicKey.data.comment = "agent-comment-private-metadata"
        const identityId = "agent-id-private-metadata"
        const agent: Agent<string> = {
            type: AgentType.NonInteractive,
            async getPublicKeys() {
                return [[identityId, publicKey]]
            },
            async getPublicKey(id) {
                if (id !== identityId) throw new Error("Unknown identity")
                return publicKey
            },
            async sign(id, data, algorithm) {
                if (id !== identityId) throw new Error("Unknown identity")
                return identity.sign(data, algorithm)
            },
        }
        const server = new Server({ hostKeys: [hostKey], sendAllHostKeys: false })
        server.hooker.hook("publicKeyAuthentication", (_hook, context, decision) => {
            decision.allowLogin =
                context.signature !== undefined &&
                context.publicKey.equals(publicKey) &&
                context.publicKey.verifySignature(context.signatureMessage, context.signature)
        })
        server.listen({ host: "127.0.0.1", port: 0 })
        await once(server, "listening")
        const diagnostics: unknown[][] = []
        const client = new Client({
            hostname: "127.0.0.1",
            port: (server.address() as AddressInfo).port,
            username: "diagnostic-agent-user",
            agent,
            authenticationMethodsOrder: [SSHAuthenticationMethods.PublicKey],
            debug: (...message) => diagnostics.push(message),
        })
        client.hooker.hook("hostKey", (_hook, decision) => {
            decision.allowHostKey = true
        })

        try {
            await client.connect()
            const output = JSON.stringify(diagnostics)
            expect(output).toContain(publicKey.hash("sha256"))
            expect(output).not.toContain(identityId)
            expect(output).not.toContain(publicKey.data.comment)
            expect(output).not.toContain(publicKey.serialize().toString("base64"))
        } finally {
            client.destroy()
            for (const connection of server.clients) connection.terminate()
            await server.close()
        }
    }, 15_000)

    test("rejects non-callable diagnostic options", () => {
        expect(() => new Client({ debug: "invalid" as never })).toThrow("must be a function")
        expect(() => new Server({ debug: "invalid" as never })).toThrow("must be a function")
    })
})
