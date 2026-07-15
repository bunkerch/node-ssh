import { once } from "node:events"
import { mkdtemp, rm } from "node:fs/promises"
import type { AddressInfo } from "node:net"
import { tmpdir } from "node:os"
import { join } from "node:path"
import Client from "../../src/Client.js"
import { ChannelOpenError } from "../../src/packets/ChannelOpenFailure.js"
import SessionChannel from "../../src/channels/SessionChannel.js"
import { SSHAuthenticationMethods } from "../../src/constants.js"
import Agent, { AgentType } from "../../src/publickey/Agent.js"
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
            controller.rejection = new ChannelOpenError(0xfe00_0001, "stale rejection", "fr")
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
            await expect(client.openSession()).rejects.toMatchObject({
                reasonCode: 1,
                message: "Opening channel type not allowed by the server.",
                languageTag: "",
            })
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

    test("cannot retain an earlier shell-request decision", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({
            hostKeys: [hostKey],
            sendAllHostKeys: false,
            algorithms: { kex: ["curve25519-sha256"] },
        })
        server.hooker.hook("noneAuthentication", (_hook, _context, controller) => {
            controller.allowLogin = true
        })
        server.hooker.hook("channelOpenRequest", (_hook, channel, controller) => {
            controller.allowOpen = channel instanceof SessionChannel
        })
        const hookErrors: Error[] = []
        let serverChannel: SessionChannel | undefined
        let shells = 0
        server.on("connection", (connection) => {
            connection.on("channel", (channel) => {
                if (!(channel instanceof SessionChannel)) return
                serverChannel = channel
                channel.hooker.on("uncaughtException", (_event, error) => hookErrors.push(error))
                channel.hooker.hook("shellRequest", (_hook, controller) => {
                    controller.success = true
                })
                channel.hooker.hook("shellRequest", async () => {
                    await Promise.resolve()
                    throw new Error("shell policy backend failed")
                })
                channel.events.on("shell", () => {
                    shells++
                })
            })
        })
        const port = await listen(server)

        const client = new Client({
            hostname: "127.0.0.1",
            port,
            username: "shell-policy-failure",
            authenticationMethodsOrder: [SSHAuthenticationMethods.None],
            algorithms: { kex: ["curve25519-sha256"] },
        })
        client.hooker.hook("hostKey", (_hook, controller) => {
            controller.allowHostKey = true
        })

        try {
            await client.connect()
            const channel = await client.openSession()
            expect(serverChannel).toBeDefined()
            await expect(channel.shell()).rejects.toThrow("failed")
            expect(shells).toBe(0)
            expect(hookErrors.map((error) => error.message)).toEqual([
                "shell policy backend failed",
            ])
        } finally {
            await close(server, client)
        }
    }, 15_000)

    test("cannot retain an earlier PTY-request decision", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({
            hostKeys: [hostKey],
            sendAllHostKeys: false,
            algorithms: { kex: ["curve25519-sha256"] },
        })
        server.hooker.hook("noneAuthentication", (_hook, _context, controller) => {
            controller.allowLogin = true
        })
        server.hooker.hook("channelOpenRequest", (_hook, channel, controller) => {
            controller.allowOpen = channel instanceof SessionChannel
        })
        const hookErrors: Error[] = []
        let serverChannel: SessionChannel | undefined
        let ptyEvents = 0
        server.on("connection", (connection) => {
            connection.on("channel", (channel) => {
                if (!(channel instanceof SessionChannel)) return
                serverChannel = channel
                channel.hooker.on("uncaughtException", (_event, error) => hookErrors.push(error))
                channel.hooker.hook("ptyRequest", (_hook, _context, controller) => {
                    controller.success = true
                })
                channel.hooker.hook("ptyRequest", async () => {
                    await Promise.resolve()
                    throw new Error("PTY policy backend failed")
                })
                channel.events.on("pty", () => {
                    ptyEvents++
                })
            })
        })
        const port = await listen(server)

        const client = new Client({
            hostname: "127.0.0.1",
            port,
            username: "pty-policy-failure",
            authenticationMethodsOrder: [SSHAuthenticationMethods.None],
            algorithms: { kex: ["curve25519-sha256"] },
        })
        client.hooker.hook("hostKey", (_hook, controller) => {
            controller.allowHostKey = true
        })

        try {
            await client.connect()
            const channel = await client.openSession()
            await expect(
                channel.requestPty({ term: "xterm", columns: 100, rows: 40 }),
            ).rejects.toThrow("failed")
            expect(serverChannel?.pty).toBeUndefined()
            expect(ptyEvents).toBe(0)
            expect(hookErrors.map((error) => error.message)).toEqual(["PTY policy backend failed"])
        } finally {
            await close(server, client)
        }
    }, 15_000)

    test("cannot retain an earlier environment-request decision", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({
            hostKeys: [hostKey],
            sendAllHostKeys: false,
            algorithms: { kex: ["curve25519-sha256"] },
        })
        server.hooker.hook("noneAuthentication", (_hook, _context, controller) => {
            controller.allowLogin = true
        })
        server.hooker.hook("channelOpenRequest", (_hook, channel, controller) => {
            controller.allowOpen = channel instanceof SessionChannel
        })
        const hookErrors: Error[] = []
        let serverChannel: SessionChannel | undefined
        let envEvents = 0
        server.on("connection", (connection) => {
            connection.on("channel", (channel) => {
                if (!(channel instanceof SessionChannel)) return
                serverChannel = channel
                channel.hooker.on("uncaughtException", (_event, error) => hookErrors.push(error))
                channel.hooker.hook("envRequest", (_hook, _context, controller) => {
                    controller.success = true
                })
                channel.hooker.hook("envRequest", async () => {
                    await Promise.resolve()
                    throw new Error("environment policy backend failed")
                })
                channel.events.on("env", () => {
                    envEvents++
                })
            })
        })
        const port = await listen(server)

        const client = new Client({
            hostname: "127.0.0.1",
            port,
            username: "environment-policy-failure",
            authenticationMethodsOrder: [SSHAuthenticationMethods.None],
            algorithms: { kex: ["curve25519-sha256"] },
        })
        client.hooker.hook("hostKey", (_hook, controller) => {
            controller.allowHostKey = true
        })

        try {
            await client.connect()
            const channel = await client.openSession()
            await expect(channel.setEnv("ROLE", "operator")).rejects.toThrow("failed")
            expect(serverChannel?.env).toEqual(new Map())
            expect(envEvents).toBe(0)
            expect(hookErrors.map((error) => error.message)).toEqual([
                "environment policy backend failed",
            ])
        } finally {
            await close(server, client)
        }
    }, 15_000)

    test("cannot retain an earlier exec-request decision", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({
            hostKeys: [hostKey],
            sendAllHostKeys: false,
            algorithms: { kex: ["curve25519-sha256"] },
        })
        server.hooker.hook("noneAuthentication", (_hook, _context, controller) => {
            controller.allowLogin = true
        })
        server.hooker.hook("channelOpenRequest", (_hook, channel, controller) => {
            controller.allowOpen = channel instanceof SessionChannel
        })
        const hookErrors: Error[] = []
        let serverChannel: SessionChannel | undefined
        let execEvents = 0
        server.on("connection", (connection) => {
            connection.on("channel", (channel) => {
                if (!(channel instanceof SessionChannel)) return
                serverChannel = channel
                channel.hooker.on("uncaughtException", (_event, error) => hookErrors.push(error))
                channel.hooker.hook("execRequest", (_hook, _context, controller) => {
                    controller.success = true
                })
                channel.hooker.hook("execRequest", async () => {
                    await Promise.resolve()
                    throw new Error("exec policy backend failed")
                })
                channel.events.on("exec", () => {
                    execEvents++
                })
            })
        })
        const port = await listen(server)

        const client = new Client({
            hostname: "127.0.0.1",
            port,
            username: "exec-policy-failure",
            authenticationMethodsOrder: [SSHAuthenticationMethods.None],
            algorithms: { kex: ["curve25519-sha256"] },
        })
        client.hooker.hook("hostKey", (_hook, controller) => {
            controller.allowHostKey = true
        })

        try {
            await client.connect()
            const channel = await client.openSession()
            await expect(channel.exec("id -u")).rejects.toThrow("failed")
            expect(serverChannel).toMatchObject({ consumed: false, shell: undefined })
            expect(execEvents).toBe(0)
            expect(hookErrors.map((error) => error.message)).toEqual(["exec policy backend failed"])
        } finally {
            await close(server, client)
        }
    }, 15_000)

    test("cannot retain an earlier subsystem-request decision", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({
            hostKeys: [hostKey],
            sendAllHostKeys: false,
            algorithms: { kex: ["curve25519-sha256"] },
        })
        server.hooker.hook("noneAuthentication", (_hook, _context, controller) => {
            controller.allowLogin = true
        })
        server.hooker.hook("channelOpenRequest", (_hook, channel, controller) => {
            controller.allowOpen = channel instanceof SessionChannel
        })
        const hookErrors: Error[] = []
        let serverChannel: SessionChannel | undefined
        let subsystemEvents = 0
        server.on("connection", (connection) => {
            connection.on("channel", (channel) => {
                if (!(channel instanceof SessionChannel)) return
                serverChannel = channel
                channel.hooker.on("uncaughtException", (_event, error) => hookErrors.push(error))
                channel.hooker.hook("subsystemRequest", (_hook, _context, controller) => {
                    controller.success = true
                })
                channel.hooker.hook("subsystemRequest", async () => {
                    await Promise.resolve()
                    throw new Error("subsystem policy backend failed")
                })
                channel.events.on("subsystem", () => {
                    subsystemEvents++
                })
            })
        })
        const port = await listen(server)

        const client = new Client({
            hostname: "127.0.0.1",
            port,
            username: "subsystem-policy-failure",
            authenticationMethodsOrder: [SSHAuthenticationMethods.None],
            algorithms: { kex: ["curve25519-sha256"] },
        })
        client.hooker.hook("hostKey", (_hook, controller) => {
            controller.allowHostKey = true
        })

        try {
            await client.connect()
            const channel = await client.openSession()
            await expect(channel.subsystem("audit@example.test")).rejects.toThrow("failed")
            expect(serverChannel).toMatchObject({ consumed: false, shell: undefined })
            expect(subsystemEvents).toBe(0)
            expect(hookErrors.map((error) => error.message)).toEqual([
                "subsystem policy backend failed",
            ])
        } finally {
            await close(server, client)
        }
    }, 15_000)

    test("cannot retain an earlier X11-request decision", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({
            hostKeys: [hostKey],
            sendAllHostKeys: false,
            algorithms: { kex: ["curve25519-sha256"] },
        })
        server.hooker.hook("noneAuthentication", (_hook, _context, controller) => {
            controller.allowLogin = true
        })
        server.hooker.hook("channelOpenRequest", (_hook, channel, controller) => {
            controller.allowOpen = channel instanceof SessionChannel
        })
        const hookErrors: Error[] = []
        let serverChannel: SessionChannel | undefined
        let x11Events = 0
        server.on("connection", (connection) => {
            connection.on("channel", (channel) => {
                if (!(channel instanceof SessionChannel)) return
                serverChannel = channel
                channel.hooker.on("uncaughtException", (_event, error) => hookErrors.push(error))
                channel.hooker.hook("x11Request", (_hook, _context, controller) => {
                    controller.success = true
                })
                channel.hooker.hook("x11Request", async () => {
                    await Promise.resolve()
                    throw new Error("X11 policy backend failed")
                })
                channel.events.on("x11", () => {
                    x11Events++
                })
            })
        })
        const port = await listen(server)

        const client = new Client({
            hostname: "127.0.0.1",
            port,
            username: "x11-policy-failure",
            authenticationMethodsOrder: [SSHAuthenticationMethods.None],
            algorithms: { kex: ["curve25519-sha256"] },
        })
        client.hooker.hook("hostKey", (_hook, controller) => {
            controller.allowHostKey = true
        })

        try {
            await client.connect()
            const channel = await client.openSession()
            await expect(
                channel.requestX11({ cookie: "00112233445566778899aabbccddeeff" }),
            ).rejects.toThrow("failed")
            expect(serverChannel?.x11).toBeUndefined()
            expect(x11Events).toBe(0)
            expect(hookErrors.map((error) => error.message)).toEqual(["X11 policy backend failed"])
        } finally {
            await close(server, client)
        }
    }, 15_000)

    test("cannot retain an earlier BREAK-request decision", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({
            hostKeys: [hostKey],
            sendAllHostKeys: false,
            algorithms: { kex: ["curve25519-sha256"] },
        })
        server.hooker.hook("noneAuthentication", (_hook, _context, controller) => {
            controller.allowLogin = true
        })
        server.hooker.hook("channelOpenRequest", (_hook, channel, controller) => {
            controller.allowOpen = channel instanceof SessionChannel
        })
        const hookErrors: Error[] = []
        let breakEvents = 0
        server.on("connection", (connection) => {
            connection.on("channel", (channel) => {
                if (!(channel instanceof SessionChannel)) return
                channel.hooker.on("uncaughtException", (_event, error) => hookErrors.push(error))
                channel.hooker.hook("execRequest", (_hook, _context, controller) => {
                    controller.success = true
                })
                channel.hooker.hook("breakRequest", (_hook, _context, controller) => {
                    controller.success = true
                })
                channel.hooker.hook("breakRequest", async () => {
                    await Promise.resolve()
                    throw new Error("BREAK policy backend failed")
                })
                channel.events.on("break", () => {
                    breakEvents++
                })
            })
        })
        const port = await listen(server)

        const client = new Client({
            hostname: "127.0.0.1",
            port,
            username: "break-policy-failure",
            authenticationMethodsOrder: [SSHAuthenticationMethods.None],
            algorithms: { kex: ["curve25519-sha256"] },
        })
        client.hooker.hook("hostKey", (_hook, controller) => {
            controller.allowHostKey = true
        })

        try {
            await client.connect()
            const channel = await client.openSession()
            await channel.exec("interactive-program")
            await expect(channel.sendBreak(750)).rejects.toThrow("failed")
            expect(breakEvents).toBe(0)
            expect(hookErrors.map((error) => error.message)).toEqual([
                "BREAK policy backend failed",
            ])
        } finally {
            await close(server, client)
        }
    }, 15_000)

    test("cannot retain an earlier agent-forwarding decision", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({
            hostKeys: [hostKey],
            sendAllHostKeys: false,
            algorithms: { kex: ["curve25519-sha256"] },
        })
        server.hooker.hook("noneAuthentication", (_hook, _context, controller) => {
            controller.allowLogin = true
        })
        server.hooker.hook("channelOpenRequest", (_hook, channel, controller) => {
            controller.allowOpen = channel instanceof SessionChannel
        })
        const hookErrors: Error[] = []
        let forwardingEvents = 0
        server.on("connection", (connection) => {
            connection.on("channel", (channel) => {
                if (!(channel instanceof SessionChannel)) return
                channel.hooker.on("uncaughtException", (_event, error) => hookErrors.push(error))
                channel.hooker.hook("agentForwardRequest", (_hook, controller) => {
                    controller.success = true
                })
                channel.hooker.hook("agentForwardRequest", async () => {
                    await Promise.resolve()
                    throw new Error("agent-forwarding policy backend failed")
                })
                channel.events.on("agentForward", () => {
                    forwardingEvents++
                })
            })
        })
        const port = await listen(server)
        const agent: Agent<string> = {
            type: AgentType.NonInteractive,
            async getPublicKeys() {
                return []
            },
            async getPublicKey() {
                throw new Error("No test identity")
            },
            async sign() {
                throw new Error("No test identity")
            },
            async getStream() {
                throw new Error("A denied forwarding request must not open the agent")
            },
        }

        const client = new Client({
            hostname: "127.0.0.1",
            port,
            username: "agent-forwarding-policy-failure",
            agent,
            authenticationMethodsOrder: [SSHAuthenticationMethods.None],
            algorithms: { kex: ["curve25519-sha256"] },
        })
        client.hooker.hook("hostKey", (_hook, controller) => {
            controller.allowHostKey = true
        })

        try {
            await client.connect()
            const channel = await client.openSession()
            await expect(channel.forwardAgent()).rejects.toThrow("failed")
            expect(forwardingEvents).toBe(0)
            expect(hookErrors.map((error) => error.message)).toEqual([
                "agent-forwarding policy backend failed",
            ])
        } finally {
            await close(server, client)
        }
    }, 15_000)

    test("cannot retain an earlier server channel-request decision", async () => {
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
        server.hooker.hook("channelOpenRequest", (_hook, channel, controller) => {
            controller.allowOpen = channel instanceof SessionChannel
        })
        server.hooker.hook("channelRequest", (_hook, _channel, controller) => {
            controller.handled = true
            controller.success = true
        })
        server.hooker.hook("channelRequest", async () => {
            await Promise.resolve()
            throw new Error("server channel policy backend failed")
        })
        const port = await listen(server)

        const client = new Client({
            hostname: "127.0.0.1",
            port,
            username: "server-channel-policy-failure",
            authenticationMethodsOrder: [SSHAuthenticationMethods.None],
            algorithms: { kex: ["curve25519-sha256"] },
        })
        client.hooker.hook("hostKey", (_hook, controller) => {
            controller.allowHostKey = true
        })

        try {
            await client.connect()
            const channel = await client.openSession()
            await expect(channel.request("policy@example.test")).rejects.toThrow("failed")
            expect(hookErrors.map((error) => error.message)).toEqual([
                "server channel policy backend failed",
            ])
        } finally {
            await close(server, client)
        }
    }, 15_000)

    test("cannot retain an earlier client channel-request decision", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({
            hostKeys: [hostKey],
            sendAllHostKeys: false,
            algorithms: { kex: ["curve25519-sha256"] },
        })
        server.hooker.hook("noneAuthentication", (_hook, _context, controller) => {
            controller.allowLogin = true
        })
        server.hooker.hook("channelOpenRequest", (_hook, channel, controller) => {
            controller.allowOpen = channel instanceof SessionChannel
        })
        let serverChannel: SessionChannel | undefined
        server.on("connection", (connection) => {
            connection.on("channel", (channel) => {
                if (channel instanceof SessionChannel) serverChannel = channel
            })
        })
        const port = await listen(server)

        const client = new Client({
            hostname: "127.0.0.1",
            port,
            username: "client-channel-policy-failure",
            authenticationMethodsOrder: [SSHAuthenticationMethods.None],
            algorithms: { kex: ["curve25519-sha256"] },
        })
        client.hooker.hook("hostKey", (_hook, controller) => {
            controller.allowHostKey = true
        })

        try {
            await client.connect()
            const channel = await client.openSession()
            const hookErrors: Error[] = []
            channel.hooker.on("uncaughtException", (_event, error) => hookErrors.push(error))
            channel.hooker.hook("request", (_hook, _context, controller) => {
                controller.success = true
            })
            channel.hooker.hook("request", async () => {
                await Promise.resolve()
                throw new Error("client channel policy backend failed")
            })

            await expect(serverChannel!.request("policy@example.test")).rejects.toThrow("failed")
            expect(hookErrors.map((error) => error.message)).toEqual([
                "client channel policy backend failed",
            ])
        } finally {
            await close(server, client)
        }
    }, 15_000)
})
