import { execFile, spawn } from "node:child_process"
import { AddressInfo, createConnection, createServer, type Socket } from "node:net"
import { promisify } from "node:util"
import Client from "../../src/Client.js"
import Server from "../../src/Server.js"
import ClientChannel from "../../src/channels/ClientChannel.js"
import SessionChannel from "../../src/channels/SessionChannel.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

const execFileAsync = promisify(execFile)
const imageName = "modernssh-openssh-test:bookworm"

async function waitForPort(port: number): Promise<void> {
    for (let attempt = 0; attempt < 100; attempt++) {
        const connected = await new Promise<boolean>((resolve) => {
            const socket = createConnection({ host: "127.0.0.1", port })
            socket.once("connect", () => {
                socket.destroy()
                resolve(true)
            })
            socket.once("error", () => resolve(false))
        })
        if (connected) return
        await new Promise<void>((resolve) => setTimeout(resolve, 100))
    }
    throw new Error(`OpenSSH server did not listen on port ${port}`)
}

async function listenOnEphemeralPort(
    connectionListener?: Parameters<typeof createServer>[0],
): Promise<{ server: ReturnType<typeof createServer>; port: number }> {
    const server = createServer(connectionListener)
    server.listen({ host: "127.0.0.1", port: 0 })
    await new Promise<void>((resolve) => server.once("listening", resolve))
    return { server, port: (server.address() as AddressInfo).port }
}

async function reservePort(): Promise<number> {
    const { server, port } = await listenOnEphemeralPort()
    await new Promise<void>((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()))
    })
    return port
}

async function collectProcess(
    executable: string,
    args: string[],
    input = "",
): Promise<{ code: number | null; stdout: string; stderr: string }> {
    const child = spawn(executable, args, { stdio: "pipe" })
    const stdout: Buffer[] = []
    const stderr: Buffer[] = []
    child.stdout.on("data", (data: Buffer) => stdout.push(data))
    child.stderr.on("data", (data: Buffer) => stderr.push(data))
    child.stdin.end(input)
    const code = await new Promise<number | null>((resolve, reject) => {
        child.once("error", reject)
        child.once("close", resolve)
    })
    return {
        code,
        stdout: Buffer.concat(stdout).toString(),
        stderr: Buffer.concat(stderr).toString(),
    }
}

async function exchangeTCP(port: number, input: string, expectedBytes: number): Promise<string> {
    return new Promise((resolve, reject) => {
        const output: Buffer[] = []
        const socket = createConnection({ host: "127.0.0.1", port })
        const timeout = setTimeout(() => socket.destroy(new Error("TCP exchange timed out")), 5_000)
        socket.on("data", (data: Buffer) => {
            output.push(data)
            if (Buffer.concat(output).length >= expectedBytes) socket.end()
        })
        socket.once("error", (error) => {
            clearTimeout(timeout)
            reject(error)
        })
        socket.once("close", () => {
            clearTimeout(timeout)
            resolve(Buffer.concat(output).toString())
        })
        socket.once("connect", () => socket.write(input))
    })
}

async function exchangeTCPWhenReady(
    port: number,
    input: string,
    expectedBytes: number,
): Promise<string> {
    for (let attempt = 0; attempt < 100; attempt++) {
        try {
            return await exchangeTCP(port, input, expectedBytes)
        } catch (error) {
            if ((error as NodeJS.ErrnoException).code !== "ECONNREFUSED") throw error
            await new Promise<void>((resolve) => setTimeout(resolve, 20))
        }
    }
    throw new Error(`Remote forwarding listener did not open on port ${port}`)
}

async function exchangeChannel(
    channel: ClientChannel,
    input: string,
    expectedBytes: number,
): Promise<string> {
    return new Promise((resolve, reject) => {
        const output: Buffer[] = []
        const timeout = setTimeout(
            () => channel.destroy(new Error("SSH channel exchange timed out")),
            5_000,
        )
        channel.on("data", (data: Buffer) => {
            output.push(data)
            if (Buffer.concat(output).length < expectedBytes) return
            clearTimeout(timeout)
            channel.close()
            resolve(Buffer.concat(output).toString())
        })
        channel.once("error", (error) => {
            clearTimeout(timeout)
            reject(error)
        })
        channel.write(input)
    })
}

describe("OpenSSH interoperability", () => {
    test("OpenSSH client executes a command on a modernssh server", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({ hostKeys: [hostKey], sendAllHostKeys: false })
        const errors: Error[] = []
        const input: Buffer[] = []
        let command = ""
        server.hooker.hook("noneAuthentication", (_hook, context, decision) => {
            decision.allowLogin = context.username === "interop"
        })
        server.hooker.hook("channelOpenRequest", (_hook, channel, decision) => {
            decision.allowOpen = channel instanceof SessionChannel
        })
        server.on("connection", (connection) => {
            connection.on("error", (error) => errors.push(error))
            connection.on("channel", (channel) => {
                if (!(channel instanceof SessionChannel)) return
                channel.hooker.hook("execRequest", (_hook, context, decision) => {
                    command = context.command
                    decision.success = true
                })
                channel.events.on("exec", (_command, stream) => {
                    stream.on("data", (data: Buffer) => input.push(data))
                    stream.on("end", () => {
                        stream.stderr.write("openssh stderr\n")
                        stream.stdout.write("openssh stdout\n", () => {
                            stream.exit(17)
                            stream.end()
                        })
                    })
                })
            })
        })
        server.listen({ host: "127.0.0.1", port: 0 })
        await new Promise<void>((resolve) => server.server!.once("listening", resolve))
        const port = (server.server!.address() as AddressInfo).port

        try {
            const result = await collectProcess(
                "/usr/bin/ssh",
                [
                    "-F",
                    "/dev/null",
                    "-p",
                    String(port),
                    "-o",
                    "BatchMode=yes",
                    "-o",
                    "PreferredAuthentications=none",
                    "-o",
                    "PubkeyAuthentication=no",
                    "-o",
                    "PasswordAuthentication=no",
                    "-o",
                    "StrictHostKeyChecking=no",
                    "-o",
                    "UserKnownHostsFile=/dev/null",
                    "-o",
                    "LogLevel=ERROR",
                    "interop@127.0.0.1",
                    "vector-command",
                ],
                "openssh stdin",
            )

            expect(result.code).toBe(17)
            expect(result.stdout).toBe("openssh stdout\n")
            expect(result.stderr).toBe("openssh stderr\n")
            expect(command).toBe("vector-command")
            expect(Buffer.concat(input).toString()).toBe("openssh stdin")
            expect(errors).toEqual([])
        } finally {
            await new Promise<void>((resolve, reject) => {
                server.server!.close((error) => (error ? reject(error) : resolve()))
            })
        }
    }, 15_000)

    test("OpenSSH client uses remote forwarding on a modernssh server", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const remotePort = await reservePort()
        const targetSockets = new Set<Socket>()
        const target = await listenOnEphemeralPort((socket) => {
            targetSockets.add(socket)
            socket.on("close", () => targetSockets.delete(socket))
            socket.on("data", (data: Buffer) => socket.write(data.toString().toUpperCase()))
            socket.on("end", () => socket.end())
        })
        const server = new Server({ hostKeys: [hostKey], sendAllHostKeys: false })
        const errors: Error[] = []
        server.hooker.hook("noneAuthentication", (_hook, context, decision) => {
            decision.allowLogin = context.username === "interop"
        })
        server.hooker.hook("tcpipForward", (_hook, context, decision) => {
            decision.allow = context.bindAddress === "127.0.0.1" && context.bindPort === remotePort
        })
        server.on("connection", (connection) => {
            connection.on("error", (error) => errors.push(error))
        })
        server.listen({ host: "127.0.0.1", port: 0 })
        await new Promise<void>((resolve) => server.server!.once("listening", resolve))
        const serverPort = (server.server!.address() as AddressInfo).port
        const ssh = spawn(
            "/usr/bin/ssh",
            [
                "-F",
                "/dev/null",
                "-N",
                "-T",
                "-p",
                String(serverPort),
                "-R",
                `127.0.0.1:${remotePort}:127.0.0.1:${target.port}`,
                "-o",
                "BatchMode=yes",
                "-o",
                "PreferredAuthentications=none",
                "-o",
                "PubkeyAuthentication=no",
                "-o",
                "PasswordAuthentication=no",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-o",
                "LogLevel=ERROR",
                "-o",
                "ExitOnForwardFailure=yes",
                "interop@127.0.0.1",
            ],
            { stdio: "pipe" },
        )
        const stderr: Buffer[] = []
        ssh.stderr.on("data", (data: Buffer) => stderr.push(data))

        try {
            let forwardingOutput: string
            try {
                forwardingOutput = await Promise.race([
                    exchangeTCPWhenReady(remotePort, "openssh remote", 14),
                    new Promise<never>((_resolve, reject) => {
                        ssh.once("close", (code) =>
                            reject(new Error(`OpenSSH exited unexpectedly with code ${code}`)),
                        )
                    }),
                ])
            } catch (error) {
                throw new Error(
                    `${String(error)}; stderr=${Buffer.concat(stderr).toString()}; server errors=${errors.map(String)}`,
                )
            }
            expect(forwardingOutput).toBe("OPENSSH REMOTE")
            expect(errors).toEqual([])
        } finally {
            ssh.kill("SIGTERM")
            await new Promise<void>((resolve) => {
                if (ssh.exitCode !== null || ssh.signalCode !== null) resolve()
                else ssh.once("close", () => resolve())
            })
            for (const socket of targetSockets) socket.destroy()
            await new Promise<void>((resolve, reject) => {
                target.server.close((error) => (error ? reject(error) : resolve()))
            })
            for (const client of server.clients) client.terminate()
            await new Promise<void>((resolve, reject) => {
                server.server!.close((error) => (error ? reject(error) : resolve()))
            })
        }
    }, 30_000)

    test("modernssh client executes a command on an OpenSSH server", async () => {
        await execFileAsync("docker", ["build", "--quiet", "--tag", imageName, "__tests__/openssh"])
        const { stdout } = await execFileAsync("docker", [
            "run",
            "--detach",
            "--rm",
            "--publish",
            "127.0.0.1::22",
            "--publish",
            "127.0.0.1::40000",
            imageName,
        ])
        const containerId = stdout.trim()

        try {
            const { stdout: portOutput } = await execFileAsync("docker", [
                "port",
                containerId,
                "22/tcp",
            ])
            const port = Number(portOutput.trim().match(/:(\d+)$/u)?.[1])
            expect(Number.isInteger(port)).toBe(true)
            await waitForPort(port)

            const client = new Client({
                hostname: "127.0.0.1",
                port,
                username: "interop",
                password: "correct-horse-battery-staple",
            })
            const errors: Error[] = []
            client.on("error", (error) => errors.push(error))
            client.hooker.hook("hostKey", (_hook, decision) => {
                decision.allowHostKey = true
            })
            let forwardingDetails:
                | {
                      destinationHost: string
                      destinationPort: number
                      sourceHost: string
                      sourcePort: number
                  }
                | undefined
            client.on("tcp connection", (details, accept) => {
                forwardingDetails = details
                const channel = accept()!
                channel.on("data", (data: Buffer) => channel.write(data.toString().toUpperCase()))
                channel.on("end", () => channel.close())
            })
            client.on("unix connection", (_details, accept) => {
                const channel = accept()!
                channel.on("data", (data: Buffer) => channel.write(data.toString().toUpperCase()))
                channel.on("end", () => channel.close())
            })

            await client.connect()
            const channel = await client.exec(
                "printf 'openssh server stdout\\n'; printf 'openssh server stderr\\n' >&2; exit 23",
            )
            const output: Buffer[] = []
            const stderr: Buffer[] = []
            let exitCode: number | null | undefined
            channel.on("data", (data: Buffer) => output.push(data))
            channel.stderr.on("data", (data: Buffer) => stderr.push(data))
            channel.on("exit", (code: number | null) => {
                exitCode = code
            })
            await new Promise<void>((resolve) => channel.once("close", resolve))

            expect(Buffer.concat(output).toString()).toBe("openssh server stdout\n")
            expect(Buffer.concat(stderr).toString()).toBe("openssh server stderr\n")
            expect(exitCode).toBe(23)
            expect(errors).toEqual([])

            expect(await client.forwardIn("0.0.0.0", 40_000)).toBe(40_000)
            const { stdout: forwardingPortOutput } = await execFileAsync("docker", [
                "port",
                containerId,
                "40000/tcp",
            ])
            const forwardingPort = Number(forwardingPortOutput.trim().match(/:(\d+)$/u)?.[1])
            const forwardingOutput = await exchangeTCP(forwardingPort, "remote forwarding", 17)
            expect({ forwardingOutput, forwardingDetails, errors: errors.map(String) }).toEqual({
                forwardingOutput: "REMOTE FORWARDING",
                forwardingDetails: {
                    destinationHost: "0.0.0.0",
                    destinationPort: 40_000,
                    sourceHost: expect.any(String),
                    sourcePort: expect.any(Number),
                },
                errors: [],
            })
            await client.unforwardIn("0.0.0.0", 40_000)

            const directStreamLocal = await client.openssh_forwardOutStreamLocal("/tmp/echo.sock")
            expect(await exchangeChannel(directStreamLocal, "direct stream local", 19)).toBe(
                "direct stream local",
            )

            const forwardedSocketPath = "/tmp/modernssh-forward.sock"
            await client.openssh_forwardInStreamLocal(forwardedSocketPath)
            const { stdout: streamLocalOutput } = await execFileAsync("docker", [
                "exec",
                containerId,
                "sh",
                "-c",
                `printf 'remote stream local' | socat - UNIX-CONNECT:${forwardedSocketPath}`,
            ])
            expect(streamLocalOutput).toBe("REMOTE STREAM LOCAL")
            await client.openssh_unforwardInStreamLocal(forwardedSocketPath)

            const closed = new Promise<void>((resolve) => client.once("close", resolve))
            client.end()
            await closed
        } finally {
            await execFileAsync("docker", ["rm", "--force", containerId]).catch(() => undefined)
        }
    }, 120_000)
})
