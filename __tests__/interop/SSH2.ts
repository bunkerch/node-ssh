import { AddressInfo } from "node:net"
import { Client as SSH2Client, Server as SSH2Server, type Algorithms } from "ssh2"
import Client from "../../src/Client.js"
import Server from "../../src/Server.js"
import PrivateKey from "../../src/utils/PrivateKey.js"
import { DEFAULT_CHANNEL_WINDOW_SIZE } from "../../src/channels/ClientChannel.js"
import SessionChannel from "../../src/channels/SessionChannel.js"

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
                session.on("exec", (acceptExec, _reject, info) => {
                    command = info.command
                    const stream = acceptExec()
                    stream.stderr.write("diagnostic output")
                    stream.write(expectedStdout, () => {
                        stream.exit(7)
                        stream.end()
                    })
                })
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
            const channel = await client.exec("produce-output")
            const stdout: Buffer[] = []
            const stderr: Buffer[] = []
            channel.on("data", (data: Buffer) => stdout.push(data))
            channel.stderr.on("data", (data: Buffer) => stderr.push(data))
            const exit = new Promise<number>((resolve) => channel.once("exit", resolve))
            await new Promise<void>((resolve) => channel.once("close", resolve))

            expect(client.hasAuthenticated).toBe(true)
            expect(serverReady).toBe(true)
            expect(command).toBe("produce-output")
            expect(Buffer.concat(stdout)).toEqual(expectedStdout)
            expect(Buffer.concat(stderr).toString()).toBe("diagnostic output")
            expect(await exit).toBe(7)
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
        const expectedStdout = Buffer.alloc(DEFAULT_CHANNEL_WINDOW_SIZE + 65_536, "s")
        server.hooker.hook("noneAuthentication", (_hook, context, decision) => {
            decision.allowLogin = context.username === "interop"
        })
        server.hooker.hook("channelOpenRequest", (_hook, channel, decision) => {
            decision.allowOpen = channel instanceof SessionChannel
        })
        server.on("connection", (connection) => {
            connection.on("error", (error) => serverErrors.push(error))
            connection.on("connect", () => {
                serverReady = true
            })
            connection.on("channel", (channel) => {
                if (!(channel instanceof SessionChannel)) return
                channel.hooker.hook("execRequest", (_hook, context, decision) => {
                    commands.push(context.command)
                    decision.success = true
                })
                channel.hooker.hook("shellRequest", (_hook, decision) => {
                    decision.success = true
                })
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
                client.exec("consume-input", (error, stream) => {
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
                    stream.end("client input")
                })
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

            expect(serverReady).toBe(true)
            expect(commands).toEqual(["consume-input"])
            expect(Buffer.concat(receivedInput).toString()).toBe("client input")
            expect(execResult.stdout).toEqual(expectedStdout)
            expect(execResult.stderr.toString()).toBe("server diagnostic")
            expect(execResult.exitCode).toBe(23)
            expect(shellOutput.toString()).toBe("INTERACTIVE INPUT")
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
