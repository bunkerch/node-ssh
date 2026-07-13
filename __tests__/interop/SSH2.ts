import { AddressInfo } from "node:net"
import { Client as SSH2Client, Server as SSH2Server, type Algorithms } from "ssh2"
import Client from "../../src/Client.js"
import Server from "../../src/Server.js"
import PrivateKey from "../../src/utils/PrivateKey.js"
import { DEFAULT_CHANNEL_WINDOW_SIZE } from "../../src/channels/ClientChannel.js"
import SessionChannel from "../../src/channels/SessionChannel.js"
import DirectTCPIPChannel from "../../src/channels/DirectTCPIPChannel.js"

const algorithms: Algorithms = {
    kex: ["diffie-hellman-group14-sha256"],
    cipher: ["aes128-ctr"],
    serverHostKey: ["ssh-ed25519"],
    hmac: ["hmac-sha2-256"],
    compress: ["none"],
}

describe("ssh2 interoperability", () => {
    test("modernssh client authenticates with an ssh2 server", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const serverErrors: Error[] = []
        let serverReady = false
        let command = ""
        let environment: { key: string; val: string } | undefined
        let pty: { cols: number; rows: number; width: number; height: number } | undefined
        let windowChange: { cols: number; rows: number; width: number; height: number } | undefined
        let signal = ""
        let subsystemName = ""
        let forwardingDetails:
            | { srcIP: string; srcPort: number; destIP: string; destPort: number }
            | undefined
        const expectedStdout = Buffer.alloc(DEFAULT_CHANNEL_WINDOW_SIZE + 65_536, "o")
        const server = new SSH2Server({ hostKeys: [hostKey.toString()], algorithms })
        server.on("error", (error) => serverErrors.push(error))
        server.on("connection", (connection) => {
            connection.on("error", (error) => serverErrors.push(error))
            connection.on("authentication", (context) => {
                if (context.method === "none" && context.username === "interop") {
                    context.accept()
                } else {
                    context.reject()
                }
            })
            connection.on("ready", () => {
                serverReady = true
            })
            connection.on("session", (accept) => {
                const session = accept()
                session.on("pty", (acceptPty, _reject, info) => {
                    pty = info
                    acceptPty()
                })
                session.on("env", (acceptEnv, _reject, info) => {
                    environment = info
                    acceptEnv()
                })
                session.on("window-change", (_accept, _reject, info) => {
                    windowChange = info
                })
                session.on("signal", (_accept, _reject, info) => {
                    signal = info.name
                })
                session.on("exec", (acceptExec, _reject, info) => {
                    command = info.command
                    const stream = acceptExec()
                    stream.stderr.write("diagnostic output")
                    stream.write(expectedStdout, () => {
                        stream.exit(7)
                        stream.end()
                    })
                })
                session.on("subsystem", (acceptSubsystem, _reject, info) => {
                    subsystemName = info.name
                    const stream = acceptSubsystem()
                    stream.end("subsystem ready")
                })
            })
            connection.on("tcpip", (accept, _reject, info) => {
                forwardingDetails = info
                const stream = accept()
                const input: Buffer[] = []
                stream.on("data", (data: Buffer) => input.push(data))
                stream.on("end", () => stream.end(Buffer.concat(input).toString().toUpperCase()))
            })
        })
        server.listen(0, "127.0.0.1")
        await new Promise<void>((resolve) => server.once("listening", resolve))

        const address = server.address() as AddressInfo
        const client = new Client({
            hostname: "127.0.0.1",
            port: address.port,
            username: "interop",
        })
        const clientErrors: Error[] = []
        client.on("error", (error) => clientErrors.push(error))
        client.hooker.hook("hostKey", (_hook, decision) => {
            decision.allowHostKey = true
        })

        try {
            await client.connect()
            const channel = await client.openSession()
            await channel.requestPty({
                term: "xterm-256color",
                columns: 100,
                rows: 40,
                width: 800,
                height: 600,
                modes: { 1: 3 },
            })
            await channel.setEnv("LANG", "en_US.UTF-8")
            await channel.exec("produce-output")
            await channel.setWindow({ columns: 120, rows: 50, width: 960, height: 750 })
            await channel.signal("SIGTERM")
            const stdout: Buffer[] = []
            const stderr: Buffer[] = []
            channel.on("data", (data: Buffer) => stdout.push(data))
            channel.stderr.on("data", (data: Buffer) => stderr.push(data))
            const exit = new Promise<number>((resolve) => channel.once("exit", resolve))
            await new Promise<void>((resolve) => channel.once("close", resolve))

            expect(client.hasAuthenticated).toBe(true)
            expect(serverReady).toBe(true)
            expect(command).toBe("produce-output")
            expect(environment).toEqual({ key: "LANG", val: "en_US.UTF-8" })
            expect(pty).toMatchObject({ cols: 100, rows: 40, width: 800, height: 600 })
            expect(windowChange).toEqual({ cols: 120, rows: 50, width: 960, height: 750 })
            expect(signal).toBe("TERM")
            expect(Buffer.concat(stdout)).toEqual(expectedStdout)
            expect(Buffer.concat(stderr).toString()).toBe("diagnostic output")
            expect(await exit).toBe(7)

            const subsystem = await client.openSession()
            await subsystem.subsystem("test-service")
            const subsystemOutput: Buffer[] = []
            subsystem.on("data", (data: Buffer) => subsystemOutput.push(data))
            await new Promise<void>((resolve) => subsystem.once("close", resolve))
            expect(subsystemName).toBe("test-service")
            expect(Buffer.concat(subsystemOutput).toString()).toBe("subsystem ready")

            const forwarding = await client.forwardOut(
                "192.0.2.10",
                12_345,
                "service.internal",
                8080,
            )
            const forwardedOutput: Buffer[] = []
            forwarding.on("data", (data: Buffer) => forwardedOutput.push(data))
            forwarding.end("forwarded data")
            await new Promise<void>((resolve) => forwarding.once("close", resolve))
            expect(forwardingDetails).toEqual({
                srcIP: "192.0.2.10",
                srcPort: 12_345,
                destIP: "service.internal",
                destPort: 8080,
            })
            expect(Buffer.concat(forwardedOutput).toString()).toBe("FORWARDED DATA")
            expect(clientErrors).toEqual([])
            expect(serverErrors).toEqual([])
        } finally {
            const closed = new Promise<void>((resolve) => client.once("close", resolve))
            client.end()
            await closed
            await new Promise<void>((resolve, reject) => {
                server.close((error) => (error ? reject(error) : resolve()))
            })
        }
    }, 15_000)

    test("ssh2 client authenticates with a modernssh server", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({ hostKeys: [hostKey], sendAllHostKeys: false })
        const serverErrors: Error[] = []
        let serverReady = false
        const commands: string[] = []
        const receivedInput: Buffer[] = []
        const environments: [string, string][] = []
        const ptys: { columns: number; rows: number; width: number; height: number }[] = []
        const windowChanges: {
            columns: number
            rows: number
            width: number
            height: number
        }[] = []
        const signals: string[] = []
        const subsystems: string[] = []
        const forwardingDetails: DirectTCPIPChannel["details"][] = []
        const expectedStdout = Buffer.alloc(DEFAULT_CHANNEL_WINDOW_SIZE + 65_536, "s")
        server.hooker.hook("noneAuthentication", (_hook, context, decision) => {
            decision.allowLogin = context.username === "interop"
        })
        server.hooker.hook("channelOpenRequest", (_hook, channel, decision) => {
            decision.allowOpen =
                channel instanceof SessionChannel || channel instanceof DirectTCPIPChannel
        })
        server.on("connection", (connection) => {
            connection.on("error", (error) => serverErrors.push(error))
            connection.on("connect", () => {
                serverReady = true
            })
            connection.on("channel", (channel) => {
                if (channel instanceof DirectTCPIPChannel) {
                    forwardingDetails.push(channel.details)
                    const input: Buffer[] = []
                    channel.stream.on("data", (data: Buffer) => input.push(data))
                    channel.stream.on("end", () => {
                        channel.stream.end(Buffer.concat(input).toString().toUpperCase())
                    })
                    return
                }
                if (!(channel instanceof SessionChannel)) return
                channel.hooker.hook("execRequest", (_hook, context, decision) => {
                    commands.push(context.command)
                    decision.success = true
                })
                channel.hooker.hook("shellRequest", (_hook, decision) => {
                    decision.success = true
                })
                channel.hooker.hook("ptyRequest", (_hook, _context, decision) => {
                    decision.success = true
                })
                channel.hooker.hook("envRequest", (_hook, _context, decision) => {
                    decision.success = true
                })
                channel.hooker.hook("subsystemRequest", (_hook, _context, decision) => {
                    decision.success = true
                })
                channel.events.on("pty", ({ columns, rows, width, height }) => {
                    ptys.push({ columns, rows, width, height })
                })
                channel.events.on("env", (name, value) => environments.push([name, value]))
                channel.events.on("windowChange", (dimensions) => {
                    windowChanges.push(dimensions)
                })
                channel.events.on("signal", (name) => signals.push(name))
                channel.events.on("exec", (_command, shell) => {
                    shell.on("data", (data: Buffer) => receivedInput.push(data))
                    shell.on("end", () => {
                        shell.stderr.write("server diagnostic")
                        shell.write(expectedStdout, () => {
                            shell.exit(23)
                            shell.end()
                        })
                    })
                })
                channel.events.on("shell", (shell) => {
                    const input: Buffer[] = []
                    shell.on("data", (data: Buffer) => input.push(data))
                    shell.on("end", () => {
                        shell.end(Buffer.concat(input).toString().toUpperCase())
                    })
                })
                channel.events.on("subsystem", (name, shell) => {
                    subsystems.push(name)
                    shell.end("modern subsystem")
                })
            })
        })
        server.listen({ host: "127.0.0.1", port: 0 })
        await new Promise<void>((resolve) => server.server!.once("listening", resolve))

        const address = server.server!.address() as AddressInfo
        const client = new SSH2Client()
        const clientErrors: Error[] = []
        client.on("error", (error) => clientErrors.push(error))

        try {
            client.connect({
                host: "127.0.0.1",
                port: address.port,
                username: "interop",
                authHandler: ["none"],
                algorithms,
                hostVerifier: () => true,
                readyTimeout: 10_000,
            })
            await new Promise<void>((resolve) => client.once("ready", resolve))

            const execResult = await new Promise<{
                stdout: Buffer
                stderr: Buffer
                exitCode: number | undefined
            }>((resolve, reject) => {
                client.exec(
                    "consume-input",
                    {
                        env: { TEST_VARIABLE: "accepted" },
                        pty: { cols: 90, rows: 30, width: 720, height: 450 },
                    },
                    (error, stream) => {
                        if (error) return reject(error)
                        const stdout: Buffer[] = []
                        const stderr: Buffer[] = []
                        let exitCode: number | undefined
                        stream.on("data", (data: Buffer) => stdout.push(data))
                        stream.stderr.on("data", (data: Buffer) => stderr.push(data))
                        stream.on("exit", (code: number) => {
                            exitCode = code
                        })
                        stream.on("error", reject)
                        stream.on("close", () => {
                            resolve({
                                stdout: Buffer.concat(stdout),
                                stderr: Buffer.concat(stderr),
                                exitCode,
                            })
                        })
                        stream.setWindow(45, 110, 675, 880)
                        stream.signal("SIGUSR1")
                        stream.end("client input")
                    },
                )
            })

            const shellOutput = await new Promise<Buffer>((resolve, reject) => {
                client.shell(false, (error, stream) => {
                    if (error) return reject(error)
                    const output: Buffer[] = []
                    stream.on("data", (data: Buffer) => output.push(data))
                    stream.on("error", reject)
                    stream.on("close", () => resolve(Buffer.concat(output)))
                    stream.end("interactive input")
                })
            })

            const subsystemOutput = await new Promise<Buffer>((resolve, reject) => {
                client.subsys("test-subsystem", (error, stream) => {
                    if (error) return reject(error)
                    const output: Buffer[] = []
                    stream.on("data", (data: Buffer) => output.push(data))
                    stream.on("error", reject)
                    stream.on("close", () => resolve(Buffer.concat(output)))
                })
            })

            const forwardedOutput = await new Promise<Buffer>((resolve, reject) => {
                client.forwardOut(
                    "198.51.100.20",
                    23_456,
                    "database.internal",
                    5432,
                    (error, stream) => {
                        if (error) return reject(error)
                        const output: Buffer[] = []
                        stream.on("data", (data: Buffer) => output.push(data))
                        stream.on("error", reject)
                        stream.on("close", () => resolve(Buffer.concat(output)))
                        stream.end("tunnel data")
                    },
                )
            })

            expect(serverReady).toBe(true)
            expect(commands).toEqual(["consume-input"])
            expect(environments).toContainEqual(["TEST_VARIABLE", "accepted"])
            expect(ptys).toContainEqual({ columns: 90, rows: 30, width: 720, height: 450 })
            expect(windowChanges).toContainEqual({
                columns: 110,
                rows: 45,
                width: 880,
                height: 675,
            })
            expect(signals).toContain("USR1")
            expect(Buffer.concat(receivedInput).toString()).toBe("client input")
            expect(execResult.stdout).toEqual(expectedStdout)
            expect(execResult.stderr.toString()).toBe("server diagnostic")
            expect(execResult.exitCode).toBe(23)
            expect(shellOutput.toString()).toBe("INTERACTIVE INPUT")
            expect(subsystems).toEqual(["test-subsystem"])
            expect(subsystemOutput.toString()).toBe("modern subsystem")
            expect(forwardingDetails).toEqual([
                {
                    sourceHost: "198.51.100.20",
                    sourcePort: 23_456,
                    destinationHost: "database.internal",
                    destinationPort: 5432,
                },
            ])
            expect(forwardedOutput.toString()).toBe("TUNNEL DATA")
            expect(clientErrors).toEqual([])
            expect(serverErrors).toEqual([])
        } finally {
            const closed = new Promise<void>((resolve) => client.once("close", resolve))
            client.end()
            await closed
            await new Promise<void>((resolve, reject) => {
                server.server!.close((error) => (error ? reject(error) : resolve()))
            })
        }
    }, 15_000)
})
