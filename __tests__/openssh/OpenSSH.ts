import { execFile, spawn } from "node:child_process"
import { AddressInfo, createConnection } from "node:net"
import { promisify } from "node:util"
import Client from "../../src/Client.js"
import Server from "../../src/Server.js"
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

            const closed = new Promise<void>((resolve) => client.once("close", resolve))
            client.end()
            await closed
        } finally {
            await execFileAsync("docker", ["rm", "--force", containerId]).catch(() => undefined)
        }
    }, 120_000)
})
