import { once } from "node:events"
import type { AddressInfo } from "node:net"
import Client, { type ClientSessionOptions } from "../../src/Client.js"
import SessionChannel from "../../src/channels/SessionChannel.js"
import { SSHAuthenticationMethods } from "../../src/constants.js"
import Server from "../../src/Server.js"
import { TerminalMode } from "../../src/TerminalModes.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

describe("client session configuration ownership", () => {
    test("rejects malformed session policy before opening a channel", async () => {
        const client = new Client({})
        const invalidOptions: readonly [unknown, string][] = [
            [null, "SSH session options must be an object"],
            [[], "SSH session options must be an object"],
            [{ agentForward: "false" }, "SSH session agentForward option must be a boolean"],
            [{ allowHalfOpen: "false" }, "SSH session allowHalfOpen option must be a boolean"],
            [{ env: [] }, "SSH session environment must be an object"],
            [{ env: { LANG: 7 } }, "SSH session environment values must be strings"],
            [{ pty: "yes" }, "SSH session pty option must be a boolean or object"],
            [{ x11: "yes" }, "SSH session x11 option must be a boolean, number, or object"],
        ]

        for (const [options, message] of invalidOptions) {
            const exec = client.exec("true", options as ClientSessionOptions)
            const shell = client.shell(options as ClientSessionOptions)
            expect(exec).toBeInstanceOf(Promise)
            expect(shell).toBeInstanceOf(Promise)
            await expect(exec).rejects.toThrow(message)
            await expect(shell).rejects.toThrow(message)
        }
    })

    test("rejects malformed subsystem options before opening a channel", async () => {
        const client = new Client({})
        const cases: readonly [Promise<unknown>, string][] = [
            [client.sftp(null as never), "SSH SFTP environment must be an object"],
            [client.sftp({}, null as never), "SFTP client options must be an object"],
            [client.sftp({ LANG: 7 } as never), "SSH SFTP environment values must be strings"],
            [
                client.sftp({}, { requestTimeout: null as never }),
                "SFTP request timeout must be a positive number",
            ],
            [
                client.publicKeySubsystem(null as never),
                "Public-key subsystem client options must be an object",
            ],
            [
                client.publicKeySubsystem({ requestTimeout: null as never }),
                "Public-key subsystem request timeout must be a positive number",
            ],
        ]

        for (const [operation, message] of cases) {
            await expect(operation).rejects.toThrow(message)
        }
    })

    test("exec owns its environment when the operation starts", async () => {
        const server = new Server({
            hostKeys: [await PrivateKey.generate("ssh-ed25519")],
            sendAllHostKeys: false,
            algorithms: { kex: ["curve25519-sha256"] },
        })
        server.hooker.hook("noneAuthentication", (_hook, _context, controller) => {
            controller.allowLogin = true
        })
        server.hooker.hook("channelOpenRequest", (_hook, channel, controller) => {
            controller.allowOpen = channel instanceof SessionChannel
        })

        let receivedRole: string | undefined
        server.on("connection", (connection) => {
            connection.on("channel", (channel) => {
                if (!(channel instanceof SessionChannel)) return
                channel.hooker.hook("envRequest", (_hook, context, controller) => {
                    receivedRole = context.value
                    controller.success = true
                })
                channel.hooker.hook("execRequest", (_hook, _context, controller) => {
                    controller.success = true
                })
            })
        })

        server.listen({ host: "127.0.0.1", port: 0 })
        await once(server, "listening")
        const client = new Client({
            hostname: "127.0.0.1",
            port: (server.address() as AddressInfo).port,
            username: "session-ownership",
            authenticationMethodsOrder: [SSHAuthenticationMethods.None],
            algorithms: { kex: ["curve25519-sha256"] },
        })
        client.hooker.hook("hostKey", (_hook, controller) => {
            controller.allowHostKey = true
        })

        try {
            await client.connect()
            const options: ClientSessionOptions = { env: { ROLE: "original" } }
            const opening = client.exec("true", options)
            options.env!.ROLE = "mutated"

            const channel = await opening
            expect(receivedRole).toBe("original")
            channel.close()
        } finally {
            client.destroy()
            for (const connection of server.clients) connection.terminate()
            await server.close()
        }
    }, 15_000)

    test("exec owns structured PTY and X11 metadata when the operation starts", async () => {
        const server = new Server({
            hostKeys: [await PrivateKey.generate("ssh-ed25519")],
            sendAllHostKeys: false,
            algorithms: { kex: ["curve25519-sha256"] },
        })
        server.hooker.hook("noneAuthentication", (_hook, _context, controller) => {
            controller.allowLogin = true
        })
        server.hooker.hook("channelOpenRequest", (_hook, channel, controller) => {
            controller.allowOpen = channel instanceof SessionChannel
        })

        const received: {
            pty?: { term: string; columns: number; echo: number | undefined }
            x11?: { protocol: string; cookie: string; screen: number }
        } = {}
        server.on("connection", (connection) => {
            connection.on("channel", (channel) => {
                if (!(channel instanceof SessionChannel)) return
                channel.hooker.hook("ptyRequest", (_hook, context, controller) => {
                    received.pty = {
                        term: context.term,
                        columns: context.columns,
                        echo: context.modes.get(TerminalMode.ECHO),
                    }
                    controller.success = true
                })
                channel.hooker.hook("x11Request", (_hook, context, controller) => {
                    received.x11 = {
                        protocol: context.protocol,
                        cookie: context.cookie,
                        screen: context.screen,
                    }
                    controller.success = true
                })
                channel.hooker.hook("execRequest", (_hook, _context, controller) => {
                    controller.success = true
                })
            })
        })

        server.listen({ host: "127.0.0.1", port: 0 })
        await once(server, "listening")
        const client = new Client({
            hostname: "127.0.0.1",
            port: (server.address() as AddressInfo).port,
            username: "session-ownership",
            authenticationMethodsOrder: [SSHAuthenticationMethods.None],
            algorithms: { kex: ["curve25519-sha256"] },
        })
        client.hooker.hook("hostKey", (_hook, controller) => {
            controller.allowHostKey = true
        })

        const modes = { [TerminalMode.ECHO]: 1 }
        const pty = { term: "xterm-original", columns: 101, modes }
        const cookie = Buffer.from("0011223344556677", "hex")
        const x11 = { protocol: "ORIGINAL-AUTH", cookie, screen: 3 }

        try {
            await client.connect()
            const opening = client.exec("true", { pty, x11 })
            pty.term = "xterm-mutated"
            pty.columns = 202
            modes[TerminalMode.ECHO] = 0
            x11.protocol = "MUTATED-AUTH"
            x11.screen = 9
            cookie.fill(0xff)

            const channel = await opening
            expect(received).toEqual({
                pty: { term: "xterm-original", columns: 101, echo: 1 },
                x11: { protocol: "ORIGINAL-AUTH", cookie: "0011223344556677", screen: 3 },
            })
            channel.close()
        } finally {
            client.destroy()
            for (const connection of server.clients) connection.terminate()
            await server.close()
        }
    }, 15_000)

    test("shell owns its environment when the operation starts", async () => {
        const server = new Server({
            hostKeys: [await PrivateKey.generate("ssh-ed25519")],
            sendAllHostKeys: false,
            algorithms: { kex: ["curve25519-sha256"] },
        })
        server.hooker.hook("noneAuthentication", (_hook, _context, controller) => {
            controller.allowLogin = true
        })
        server.hooker.hook("channelOpenRequest", (_hook, channel, controller) => {
            controller.allowOpen = channel instanceof SessionChannel
        })

        let receivedRole: string | undefined
        server.on("connection", (connection) => {
            connection.on("channel", (channel) => {
                if (!(channel instanceof SessionChannel)) return
                channel.hooker.hook("envRequest", (_hook, context, controller) => {
                    receivedRole = context.value
                    controller.success = true
                })
                channel.hooker.hook("shellRequest", (_hook, controller) => {
                    controller.success = true
                })
            })
        })

        server.listen({ host: "127.0.0.1", port: 0 })
        await once(server, "listening")
        const client = new Client({
            hostname: "127.0.0.1",
            port: (server.address() as AddressInfo).port,
            username: "session-ownership",
            authenticationMethodsOrder: [SSHAuthenticationMethods.None],
            algorithms: { kex: ["curve25519-sha256"] },
        })
        client.hooker.hook("hostKey", (_hook, controller) => {
            controller.allowHostKey = true
        })

        try {
            await client.connect()
            const options: ClientSessionOptions = {
                env: { ROLE: "original" },
                pty: false,
            }
            const opening = client.shell(options)
            options.env!.ROLE = "mutated"

            const channel = await opening
            expect(receivedRole).toBe("original")
            channel.close()
        } finally {
            client.destroy()
            for (const connection of server.clients) connection.terminate()
            await server.close()
        }
    }, 15_000)

    test("sftp owns its environment and timeout options when the operation starts", async () => {
        const server = new Server({
            hostKeys: [await PrivateKey.generate("ssh-ed25519")],
            sendAllHostKeys: false,
            algorithms: { kex: ["curve25519-sha256"] },
        })
        server.hooker.hook("noneAuthentication", (_hook, _context, controller) => {
            controller.allowLogin = true
        })
        server.hooker.hook("channelOpenRequest", (_hook, channel, controller) => {
            controller.allowOpen = channel instanceof SessionChannel
        })

        let receivedRole: string | undefined
        server.on("connection", (connection) => {
            connection.on("channel", (channel) => {
                if (!(channel instanceof SessionChannel)) return
                channel.hooker.hook("envRequest", (_hook, context, controller) => {
                    receivedRole = context.value
                    controller.success = true
                })
                channel.hooker.hook("subsystemRequest", (_hook, context, controller) => {
                    if (context.subsystem !== "sftp") return
                    controller.success = true
                    controller.sftp = {}
                })
            })
        })

        server.listen({ host: "127.0.0.1", port: 0 })
        await once(server, "listening")
        const client = new Client({
            hostname: "127.0.0.1",
            port: (server.address() as AddressInfo).port,
            username: "session-ownership",
            authenticationMethodsOrder: [SSHAuthenticationMethods.None],
            algorithms: { kex: ["curve25519-sha256"] },
            replyTimeout: 2_345,
        })
        client.hooker.hook("hostKey", (_hook, controller) => {
            controller.allowHostKey = true
        })

        try {
            await client.connect()
            const environment = { ROLE: "original" }
            const options = { requestTimeout: 1_234 }
            const opening = client.sftp(environment, options)
            environment.ROLE = "mutated"
            options.requestTimeout = 9_999

            const sftp = await opening
            expect(receivedRole).toBe("original")
            expect(sftp.requestTimeout).toBe(1_234)
            const closed = once(sftp.channel, "close")
            sftp.end()
            await closed

            const inherited = await client.sftp()
            expect(inherited.requestTimeout).toBe(2_345)
            inherited.end()
        } finally {
            client.destroy()
            for (const connection of server.clients) connection.terminate()
            await server.close()
        }
    }, 15_000)
})
