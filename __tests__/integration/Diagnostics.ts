import Client from "../../src/Client.js"
import Server from "../../src/Server.js"
import { once } from "node:events"
import { type AddressInfo } from "node:net"
import { PassThrough } from "node:stream"
import PrivateKeyAgent from "../../src/publickey/PrivateKeyAgent.js"
import PrivateKey from "../../src/utils/PrivateKey.js"
import { AgentType, type Agent } from "../../src/publickey/Agent.js"
import { SSHAuthenticationMethods } from "../../src/constants.js"
import SessionChannel from "../../src/channels/SessionChannel.js"
import type Shell from "../../src/channels/Session/Shell.js"

function containsDiagnosticValue(
    value: unknown,
    expected: string,
    seen = new WeakSet<object>(),
): boolean {
    if (typeof value === "string") return value.includes(expected)
    if (Buffer.isBuffer(value)) return value.includes(Buffer.from(expected))
    if (typeof value !== "object" || value === null) return false
    if (seen.has(value)) return false
    seen.add(value)
    return Object.values(value).some((nested) => containsDiagnosticValue(nested, expected, seen))
}

describe("diagnostic events", () => {
    test("receives an allow-listed client configuration summary without secret-bearing objects", async () => {
        const authenticationKey = await PrivateKey.generate("ssh-ed25519")
        const hostbasedKey = await PrivateKey.generate("ssh-ed25519")
        Object.assign(hostbasedKey, { diagnosticSecret: "hostbased-private-metadata" })
        const agent = new PrivateKeyAgent(authenticationKey)
        Object.assign(agent, { diagnosticSecret: "agent-private-metadata" })
        const socket = new PassThrough()
        Object.assign(socket, { diagnosticSecret: "transport-private-metadata" })
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
            ident: Buffer.from("identifier_private_metadata"),
            sock: socket,
        })
        client.on("debug", (...message) => emitted.push(message))

        await new Promise<void>((resolve) => setImmediate(resolve))

        expect(emitted[0]?.[0]).toBe("Client created with options:")
        const summary = emitted[0]?.[1] as Record<string, unknown>
        expect(summary).toMatchObject({
            username: "diagnostic-user",
            password: "<redacted>",
            agent: "<configured>",
            hostbased: "<configured>",
            sock: "<configured>",
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
        const output = JSON.stringify(emitted)
        expect(output).toContain("<redacted>")
        expect(output).toContain("<configured>")
        expect(output).not.toContain("diagnostic-secret")
        expect(output).not.toContain("hostbased-private-metadata")
        expect(output).not.toContain("agent-private-metadata")
        expect(output).not.toContain("transport-private-metadata")
        expect(output).not.toContain("identifier_private_metadata")
    })

    test("receives server diagnostic arguments", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const emitted: unknown[][] = []
        const server = new Server({ hostKeys: [hostKey] })
        server.on("debug", (...message) => emitted.push(message))

        server.debug("server diagnostic", { ready: true })

        expect(emitted).toEqual([["server diagnostic", { ready: true }]])
    })

    test("does not expose session or opaque request payloads", async () => {
        const secrets = {
            command: "command-secret-9c183f",
            environment: "environment-secret-d2b760",
            input: "input-secret-257e1a",
            output: "output-secret-bf4890",
            request: "request-secret-0a3e71",
            response: "response-secret-d6624e",
        }
        const serverDiagnostics: unknown[][] = []
        const clientDiagnostics: unknown[][] = []
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({
            hostKeys: [hostKey],
            sendAllHostKeys: false,
            algorithms: { kex: ["curve25519-sha256"] },
        })
        server.on("debug", (...message) => serverDiagnostics.push(message))
        server.hooker.hook("noneAuthentication", (_hook, _context, controller) => {
            controller.allowLogin = true
        })
        server.hooker.hook("channelOpenRequest", (_hook, channel, controller) => {
            controller.allowOpen = channel instanceof SessionChannel
        })
        server.hooker.hook("globalRequest", (_hook, context, controller) => {
            if (context.name !== "sensitive-query@example.test") return
            expect(context.args).toEqual(Buffer.from(secrets.request))
            controller.success = true
            controller.response = Buffer.from(secrets.response)
        })
        let resolveShell!: (shell: Shell) => void
        const shellReady = new Promise<Shell>((resolve) => {
            resolveShell = resolve
        })
        server.on("connection", (connection) => {
            connection.on("channel", (channel) => {
                if (!(channel instanceof SessionChannel)) return
                channel.hooker.hook("envRequest", (_hook, _environment, controller) => {
                    controller.success = true
                })
                channel.hooker.hook("execRequest", (_hook, _command, controller) => {
                    controller.success = true
                })
                channel.events.once("exec", (_command, shell) => resolveShell(shell))
            })
        })
        server.listen({ host: "127.0.0.1", port: 0 })
        await once(server, "listening")

        const client = new Client({
            hostname: "127.0.0.1",
            port: (server.address() as AddressInfo).port,
            username: "diagnostic-payload-user",
            authenticationMethodsOrder: [SSHAuthenticationMethods.None],
            algorithms: { kex: ["curve25519-sha256"] },
        })
        client.on("debug", (...message) => clientDiagnostics.push(message))
        client.hooker.hook("hostKey", (_hook, controller) => {
            controller.allowHostKey = true
        })

        try {
            await client.connect()
            const session = await client.exec(secrets.command, {
                env: { API_TOKEN: secrets.environment },
            })
            const shell = await shellReady
            const inputReceived = once(shell, "data")
            session.write(Buffer.from(secrets.input))
            await inputReceived
            const outputReceived = once(session, "data")
            await shell.writeStdout(secrets.output)
            await outputReceived
            expect(
                await client.globalRequest(
                    "sensitive-query@example.test",
                    Buffer.from(secrets.request),
                ),
            ).toEqual(Buffer.from(secrets.response))

            for (const secret of Object.values(secrets)) {
                expect(
                    [...serverDiagnostics, ...clientDiagnostics].some((message) =>
                        containsDiagnosticValue(message, secret),
                    ),
                ).toBe(false)
            }
        } finally {
            client.destroy()
            for (const connection of server.clients) connection.terminate()
            await server.close()
        }
    }, 15_000)

    test("does not expose opaque agent identity IDs or key comments", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const rejectedIdentity = await PrivateKey.generate("ssh-ed25519")
        const identity = await PrivateKey.generate("ssh-ed25519")
        const rejectedPublicKey = rejectedIdentity.data.publicKey
        const publicKey = identity.data.publicKey
        rejectedPublicKey.data.comment = "rejected-agent-comment-private-metadata"
        publicKey.data.comment = "agent-comment-private-metadata"
        const rejectedIdentityId = "rejected-agent-id-private-metadata"
        const identityId = "accepted-agent-id-private-metadata"
        const agent: Agent<string> = {
            type: AgentType.NonInteractive,
            async getPublicKeys() {
                return [
                    [rejectedIdentityId, rejectedPublicKey],
                    [identityId, publicKey],
                ]
            },
            async getPublicKey(id) {
                if (id === rejectedIdentityId) return rejectedPublicKey
                if (id !== identityId) throw new Error("Unknown identity")
                return publicKey
            },
            async sign(id, data, algorithm) {
                if (id === rejectedIdentityId) {
                    throw new Error("agent-error-private-metadata")
                }
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
        })
        client.on("debug", (...message) => diagnostics.push(message))
        client.hooker.hook("hostKey", (_hook, decision) => {
            decision.allowHostKey = true
        })

        try {
            await client.connect()
            const output = diagnostics
                .flatMap((message) => message)
                .map((value) =>
                    value instanceof Error
                        ? `${value.name}: ${value.message}`
                        : typeof value === "string"
                          ? value
                          : JSON.stringify(value),
                )
                .join("\n")
            expect(output).toContain(publicKey.hash("sha256"))
            expect(output).toContain(rejectedPublicKey.hash("sha256"))
            expect(output).not.toContain(identityId)
            expect(output).not.toContain(rejectedIdentityId)
            expect(output).not.toContain(publicKey.data.comment)
            expect(output).not.toContain(rejectedPublicKey.data.comment)
            expect(output).not.toContain(publicKey.serialize().toString("base64"))
            expect(output).not.toContain("agent-error-private-metadata")
        } finally {
            client.destroy()
            for (const connection of server.clients) connection.terminate()
            await server.close()
        }
    }, 15_000)

    test("rejects removed callback options instead of silently ignoring them", () => {
        expect(() => new Client({ username: "test", debug: () => undefined } as never)).toThrow(
            "SSH debug option was removed; listen for the debug event",
        )
        expect(() => new Server({ debug: () => undefined } as never)).toThrow(
            "SSH debug option was removed; listen for the debug event",
        )
        expect(() => new Client({ username: "test", hostVerifier: () => true } as never)).toThrow(
            "SSH hostVerifier and hostHash options were removed; use the hostKey Hooker",
        )
        expect(() => new Client({ username: "test", hostHash: "sha256" } as never)).toThrow(
            "SSH hostVerifier and hostHash options were removed; use the hostKey Hooker",
        )
    })
})
