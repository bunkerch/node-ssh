import { once } from "node:events"
import { mkdtemp, rm } from "node:fs/promises"
import type { AddressInfo } from "node:net"
import { tmpdir } from "node:os"
import { join } from "node:path"
import Client from "../../src/Client.js"
import { SSHAuthenticationMethods } from "../../src/constants.js"
import Server from "../../src/Server.js"
import type ServerClient from "../../src/ServerClient.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

async function listen(server: Server): Promise<number> {
    server.listen({ host: "127.0.0.1", port: 0 })
    await once(server, "listening")
    return (server.address() as AddressInfo).port
}

async function close(server: Server, client: Client): Promise<void> {
    client.destroy()
    for (const connection of server.clients) connection.terminate()
    await server.close()
}

function settlement(connecting: Promise<void>): Promise<"fulfilled" | "rejected"> {
    return connecting.then(
        () => "fulfilled",
        () => "rejected",
    )
}

describe("contained authorization hook failures", () => {
    test("cannot retain an earlier host-key trust decision", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({
            hostKeys: [hostKey],
            sendAllHostKeys: false,
            algorithms: { kex: ["curve25519-sha256"] },
        })
        server.hooker.hook("noneAuthentication", (_hook, _context, controller) => {
            controller.allowLogin = true
        })
        const port = await listen(server)

        const client = new Client({
            hostname: "127.0.0.1",
            port,
            username: "host-policy-failure",
            authenticationMethodsOrder: [SSHAuthenticationMethods.None],
            algorithms: { kex: ["curve25519-sha256"] },
        })
        const hookErrors: Error[] = []
        client.hooker.on("uncaughtException", (_event, error) => hookErrors.push(error))
        client.hooker.hook("hostKey", (_hook, controller) => {
            controller.allowHostKey = true
        })
        client.hooker.hook("hostKey", async () => {
            await Promise.resolve()
            throw new Error("host trust backend failed")
        })

        try {
            expect(await settlement(client.connect())).toBe("rejected")
            expect(hookErrors.map((error) => error.message)).toEqual(["host trust backend failed"])
            expect(client.isConnected).toBe(false)
        } finally {
            await close(server, client)
        }
    }, 15_000)

    test("cannot retain an earlier user-authentication decision", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({
            hostKeys: [hostKey],
            sendAllHostKeys: false,
            algorithms: { kex: ["curve25519-sha256"] },
        })
        const hookErrors: Error[] = []
        server.hooker.on("uncaughtException", (_event, error) => hookErrors.push(error))
        server.hooker.hook("noneAuthentication", (_hook, _context, controller) => {
            controller.allowLogin = true
        })
        server.hooker.hook("noneAuthentication", async () => {
            await Promise.resolve()
            throw new Error("identity backend failed")
        })
        const port = await listen(server)

        const client = new Client({
            hostname: "127.0.0.1",
            port,
            username: "authentication-policy-failure",
            authenticationMethodsOrder: [SSHAuthenticationMethods.None],
            algorithms: { kex: ["curve25519-sha256"] },
        })
        client.hooker.hook("hostKey", (_hook, controller) => {
            controller.allowHostKey = true
        })

        try {
            expect(await settlement(client.connect())).toBe("rejected")
            expect(hookErrors.map((error) => error.message)).toEqual(["identity backend failed"])
            expect(client.isConnected).toBe(false)
        } finally {
            await close(server, client)
        }
    }, 15_000)

    test("cannot retain an earlier channel-open decision", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({
            hostKeys: [hostKey],
            sendAllHostKeys: false,
            algorithms: { kex: ["curve25519-sha256"] },
        })
        const hookErrors: Error[] = []
        server.hooker.on("uncaughtException", (_event, error) => hookErrors.push(error))
        server.hooker.hook("noneAuthentication", (_hook, _context, controller) => {
            controller.allowLogin = true
        })
        server.hooker.hook("channelOpenRequest", (_hook, _channel, controller) => {
            controller.allowOpen = true
        })
        server.hooker.hook("channelOpenRequest", async () => {
            await Promise.resolve()
            throw new Error("channel policy backend failed")
        })
        const port = await listen(server)

        const client = new Client({
            hostname: "127.0.0.1",
            port,
            username: "channel-policy-failure",
            authenticationMethodsOrder: [SSHAuthenticationMethods.None],
            algorithms: { kex: ["curve25519-sha256"] },
        })
        client.hooker.hook("hostKey", (_hook, controller) => {
            controller.allowHostKey = true
        })

        try {
            await client.connect()
            await expect(client.openSession()).rejects.toThrow("not allowed")
            expect(hookErrors.map((error) => error.message)).toEqual([
                "channel policy backend failed",
            ])
        } finally {
            await close(server, client)
        }
    }, 15_000)

    test("cannot retain an earlier TCP forwarding decision", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({
            hostKeys: [hostKey],
            sendAllHostKeys: false,
            algorithms: { kex: ["curve25519-sha256"] },
        })
        const hookErrors: Error[] = []
        server.hooker.on("uncaughtException", (_event, error) => hookErrors.push(error))
        server.hooker.hook("noneAuthentication", (_hook, _context, controller) => {
            controller.allowLogin = true
        })
        server.hooker.hook("tcpipForward", (_hook, _context, controller) => {
            controller.allow = true
        })
        server.hooker.hook("tcpipForward", async () => {
            await Promise.resolve()
            throw new Error("forwarding policy backend failed")
        })
        const port = await listen(server)

        const client = new Client({
            hostname: "127.0.0.1",
            port,
            username: "forwarding-policy-failure",
            authenticationMethodsOrder: [SSHAuthenticationMethods.None],
            algorithms: { kex: ["curve25519-sha256"] },
        })
        client.hooker.hook("hostKey", (_hook, controller) => {
            controller.allowHostKey = true
        })

        try {
            await client.connect()
            await expect(client.forwardIn("127.0.0.1", 0)).rejects.toThrow("failed")
            expect(hookErrors.map((error) => error.message)).toEqual([
                "forwarding policy backend failed",
            ])
        } finally {
            await close(server, client)
        }
    }, 15_000)

    test("cannot retain an earlier server global-request decision", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({
            hostKeys: [hostKey],
            sendAllHostKeys: false,
            algorithms: { kex: ["curve25519-sha256"] },
        })
        const hookErrors: Error[] = []
        server.hooker.on("uncaughtException", (_event, error) => hookErrors.push(error))
        server.hooker.hook("noneAuthentication", (_hook, _context, controller) => {
            controller.allowLogin = true
        })
        server.hooker.hook("globalRequest", (_hook, _context, controller) => {
            controller.success = true
            controller.response = Buffer.from("should not escape")
        })
        server.hooker.hook("globalRequest", async () => {
            await Promise.resolve()
            throw new Error("server request policy backend failed")
        })
        const port = await listen(server)

        const client = new Client({
            hostname: "127.0.0.1",
            port,
            username: "server-request-policy-failure",
            authenticationMethodsOrder: [SSHAuthenticationMethods.None],
            algorithms: { kex: ["curve25519-sha256"] },
        })
        client.hooker.hook("hostKey", (_hook, controller) => {
            controller.allowHostKey = true
        })

        try {
            await client.connect()
            await expect(client.globalRequest("policy@example.test")).rejects.toThrow("failed")
            expect(hookErrors.map((error) => error.message)).toEqual([
                "server request policy backend failed",
            ])
        } finally {
            await close(server, client)
        }
    }, 15_000)

    test("cannot retain an earlier client global-request decision", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({
            hostKeys: [hostKey],
            sendAllHostKeys: false,
            algorithms: { kex: ["curve25519-sha256"] },
        })
        server.hooker.hook("noneAuthentication", (_hook, _context, controller) => {
            controller.allowLogin = true
        })
        let peer: ServerClient | undefined
        server.on("connection", (connection) => {
            peer = connection
        })
        const port = await listen(server)

        const client = new Client({
            hostname: "127.0.0.1",
            port,
            username: "client-request-policy-failure",
            authenticationMethodsOrder: [SSHAuthenticationMethods.None],
            algorithms: { kex: ["curve25519-sha256"] },
        })
        const hookErrors: Error[] = []
        client.hooker.on("uncaughtException", (_event, error) => hookErrors.push(error))
        client.hooker.hook("hostKey", (_hook, controller) => {
            controller.allowHostKey = true
        })
        client.hooker.hook("globalRequest", (_hook, _context, controller) => {
            controller.success = true
            controller.response = Buffer.from("should not escape")
        })
        client.hooker.hook("globalRequest", async () => {
            await Promise.resolve()
            throw new Error("client request policy backend failed")
        })

        try {
            await client.connect()
            await expect(peer!.globalRequest("policy@example.test")).rejects.toThrow("failed")
            expect(hookErrors.map((error) => error.message)).toEqual([
                "client request policy backend failed",
            ])
        } finally {
            await close(server, client)
        }
    }, 15_000)

    test("cannot retain an earlier stream-local forwarding decision", async () => {
        const directory = await mkdtemp(join(tmpdir(), "modernssh-policy-"))
        const socketPath = join(directory, "forward.sock")
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({
            hostKeys: [hostKey],
            sendAllHostKeys: false,
            ident: "OpenSSH_9.9",
            algorithms: { kex: ["curve25519-sha256"] },
        })
        const hookErrors: Error[] = []
        server.hooker.on("uncaughtException", (_event, error) => hookErrors.push(error))
        server.hooker.hook("noneAuthentication", (_hook, _context, controller) => {
            controller.allowLogin = true
        })
        server.hooker.hook("streamLocalForward", (_hook, _context, controller) => {
            controller.allow = true
        })
        server.hooker.hook("streamLocalForward", async () => {
            await Promise.resolve()
            throw new Error("stream-local policy backend failed")
        })
        const port = await listen(server)

        const client = new Client({
            hostname: "127.0.0.1",
            port,
            username: "stream-local-policy-failure",
            authenticationMethodsOrder: [SSHAuthenticationMethods.None],
            algorithms: { kex: ["curve25519-sha256"] },
        })
        client.hooker.hook("hostKey", (_hook, controller) => {
            controller.allowHostKey = true
        })

        try {
            await client.connect()
            await expect(client.openssh_forwardInStreamLocal(socketPath)).rejects.toThrow("failed")
            expect(hookErrors.map((error) => error.message)).toEqual([
                "stream-local policy backend failed",
            ])
        } finally {
            await close(server, client)
            await rm(directory, { recursive: true, force: true })
        }
    }, 15_000)
})
