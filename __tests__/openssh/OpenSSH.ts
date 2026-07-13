import { execFile, spawn } from "node:child_process"
import { once } from "node:events"
import { access, mkdtemp, readFile, rm, writeFile } from "node:fs/promises"
import { AddressInfo, createConnection, createServer, type Socket } from "node:net"
import { tmpdir } from "node:os"
import { join } from "node:path"
import type { Duplex } from "node:stream"
import { promisify } from "node:util"
import Client from "../../src/Client.js"
import Server from "../../src/Server.js"
import DirectStreamLocalChannel from "../../src/channels/DirectStreamLocalChannel.js"
import SessionChannel from "../../src/channels/SessionChannel.js"
import SSHAgent from "../../src/publickey/SSHAgent.js"
import { readNextBuffer, readNextUint32 } from "../../src/utils/Buffer.js"
import PrivateKey from "../../src/utils/PrivateKey.js"
import PublicKey from "../../src/utils/PublicKey.js"
import { SSHAuthenticationMethods } from "../../src/constants.js"
import { SFTPStatusError } from "../../src/sftp/SFTPClient.js"
import { SFTPPacketType, SFTPStatusCode } from "../../src/sftp/constants.js"
import GlobalRequest from "../../src/packets/GlobalRequest.js"
import { attachFilesystemSFTPServer } from "./SFTPServerFixture.js"

const execFileAsync = promisify(execFile)
const imageName = "modernssh-openssh-test:bookworm"

interface OpenSSHAgentFixture {
    directory: string
    socketPath: string
    publicKey: PublicKey
    close: () => Promise<void>
}

async function createOpenSSHAgentFixture(): Promise<OpenSSHAgentFixture> {
    const directory = await mkdtemp(join(tmpdir(), "modernssh-agent-forward-"))
    const socketPath = join(directory, "agent.sock")
    const keyPath = join(directory, "id_ed25519")
    const child = spawn("ssh-agent", ["-D", "-a", socketPath], { stdio: "ignore" })
    try {
        for (let attempt = 0; attempt < 100; attempt++) {
            try {
                await access(socketPath)
                break
            } catch {
                await new Promise<void>((resolve) => setTimeout(resolve, 20))
            }
        }
        await access(socketPath)
        await execFileAsync("ssh-keygen", [
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            "agent-forwarding-fixture",
            "-f",
            keyPath,
        ])
        await execFileAsync("ssh-add", [keyPath], {
            env: { ...process.env, SSH_AUTH_SOCK: socketPath },
        })
        const publicKey = PublicKey.parseString(await readFile(`${keyPath}.pub`, "utf8"))
        return {
            directory,
            socketPath,
            publicKey,
            close: async () => {
                child.kill("SIGTERM")
                await new Promise<void>((resolve) => {
                    if (child.exitCode !== null || child.signalCode !== null) resolve()
                    else child.once("close", () => resolve())
                })
                await rm(directory, { recursive: true, force: true })
            },
        }
    } catch (error) {
        child.kill("SIGTERM")
        await rm(directory, { recursive: true, force: true })
        throw error
    }
}

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
    options: { env?: NodeJS.ProcessEnv } = {},
): Promise<{ code: number | null; stdout: string; stderr: string }> {
    const child = spawn(executable, args, { stdio: "pipe", ...options })
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

async function exchangeUnixWhenReady(
    socketPath: string,
    input: string,
    expectedBytes: number,
): Promise<string> {
    for (let attempt = 0; attempt < 100; attempt++) {
        try {
            return await new Promise<string>((resolve, reject) => {
                const output: Buffer[] = []
                const socket = createConnection(socketPath)
                const timeout = setTimeout(
                    () => socket.destroy(new Error("UNIX socket exchange timed out")),
                    5_000,
                )
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
        } catch (error) {
            const code = (error as NodeJS.ErrnoException).code
            if (code !== "ENOENT" && code !== "ECONNREFUSED") throw error
            await new Promise<void>((resolve) => setTimeout(resolve, 20))
        }
    }
    throw new Error(`UNIX forwarding listener did not open at ${socketPath}`)
}

async function exchangeChannel(
    channel: Duplex,
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
            channel.end()
            resolve(Buffer.concat(output).toString())
        })
        channel.once("error", (error) => {
            clearTimeout(timeout)
            reject(error)
        })
        channel.write(input)
    })
}

function x11SetupRequest(cookie: Buffer): Buffer {
    const protocol = Buffer.from("MIT-MAGIC-COOKIE-1", "ascii")
    const padded = (length: number): number => (length + 3) & ~3
    const header = Buffer.alloc(12)
    header[0] = 0x6c
    header.writeUInt16LE(11, 2)
    header.writeUInt16LE(protocol.length, 6)
    header.writeUInt16LE(cookie.length, 8)
    const request = Buffer.alloc(12 + padded(protocol.length) + padded(cookie.length))
    header.copy(request)
    protocol.copy(request, 12)
    cookie.copy(request, 12 + padded(protocol.length))
    return request
}

function parseX11SetupCookie(request: Buffer): Buffer {
    if (request.length < 12) throw new Error("X11 setup request is truncated")
    const littleEndian = request[0] === 0x6c
    if (!littleEndian && request[0] !== 0x42) throw new Error("Invalid X11 byte order")
    const readUint16 = littleEndian
        ? (offset: number) => request.readUInt16LE(offset)
        : (offset: number) => request.readUInt16BE(offset)
    const protocolLength = readUint16(6)
    const cookieLength = readUint16(8)
    const cookieOffset = 12 + ((protocolLength + 3) & ~3)
    if (request.length < cookieOffset + cookieLength) throw new Error("X11 cookie is truncated")
    return request.subarray(cookieOffset, cookieOffset + cookieLength)
}

async function requestAgentIdentities(stream: Duplex): Promise<Buffer> {
    return new Promise((resolve, reject) => {
        let response = Buffer.alloc(0)
        const timeout = setTimeout(
            () => stream.destroy(new Error("Forwarded agent did not reply")),
            5_000,
        )
        stream.on("data", (data: Buffer) => {
            response = Buffer.concat([response, data])
            if (response.length < 4 || response.length < response.readUInt32BE(0) + 4) return
            clearTimeout(timeout)
            stream.end()
            resolve(response)
        })
        stream.once("error", (error) => {
            clearTimeout(timeout)
            reject(error)
        })
        stream.write(Buffer.from("000000010b", "hex"))
    })
}

describe("OpenSSH interoperability", () => {
    test("OpenSSH client uses keyboard-interactive authentication on a modernssh server", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({
            hostKeys: [hostKey],
            sendAllHostKeys: false,
            banner: "modernssh authentication banner\r\n",
        })
        const errors: Error[] = []
        const rounds: (readonly string[] | undefined)[] = []
        server.hooker.hook("keyboardInteractiveAuthentication", (_hook, context, decision) => {
            rounds.push(context.responses)
            if (context.round === 0) {
                decision.name = "modernssh login"
                decision.instruction = "Supply both credentials"
                decision.prompts = [
                    { prompt: "Password: ", echo: false },
                    { prompt: "OTP: ", echo: false },
                ]
                return
            }
            decision.allowLogin =
                context.responses?.[0] === "correct-horse-battery-staple" &&
                context.responses?.[1] === "654321"
        })
        server.hooker.hook("channelOpenRequest", (_hook, channel, decision) => {
            decision.allowOpen = channel instanceof SessionChannel
        })
        server.on("connection", (connection) => {
            connection.on("error", (error) => errors.push(error))
            connection.on("channel", (channel) => {
                if (!(channel instanceof SessionChannel)) return
                channel.hooker.hook("execRequest", (_hook, _context, decision) => {
                    decision.success = true
                })
                channel.events.on("exec", (_command, shell) => {
                    shell.stdout.write("keyboard-interactive accepted\n", () => {
                        shell.exit(0).end()
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
                    "-T",
                    "-p",
                    String(port),
                    "-o",
                    "PreferredAuthentications=keyboard-interactive",
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
                    "keyboard-test",
                ],
                "",
                {
                    env: {
                        ...process.env,
                        DISPLAY: "modernssh-test",
                        SSH_ASKPASS: join(process.cwd(), "__tests__/openssh/askpass.sh"),
                        SSH_ASKPASS_REQUIRE: "force",
                    },
                },
            )
            expect({ result, rounds, errors: errors.map(String) }).toEqual({
                result: {
                    code: 0,
                    stdout: "keyboard-interactive accepted\n",
                    stderr: "",
                },
                rounds: [undefined, ["correct-horse-battery-staple", "654321"]],
                errors: [],
            })
        } finally {
            for (const client of server.clients) client.terminate()
            await new Promise<void>((resolve, reject) => {
                server.server!.close((error) => (error ? reject(error) : resolve()))
            })
        }
    }, 15_000)

    test("OpenSSH and modernssh clients complete an RFC 4252 password change", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({ hostKeys: [hostKey], sendAllHostKeys: false })
        const attempts: { password: string; newPassword?: string }[] = []
        const errors: Error[] = []
        server.hooker.hook("passwordAuthentication", (_hook, context, decision) => {
            attempts.push({ password: context.password, newPassword: context.newPassword })
            if (context.newPassword === undefined) {
                decision.requestPasswordChange = { prompt: "Choose a new password: " }
                return
            }
            decision.allowLogin =
                context.password === "correct-horse-battery-staple" &&
                context.newPassword === "new-password"
        })
        server.hooker.hook("channelOpenRequest", (_hook, channel, decision) => {
            decision.allowOpen = channel instanceof SessionChannel
        })
        server.on("connection", (connection) => {
            connection.on("error", (error) => errors.push(error))
            connection.on("channel", (channel) => {
                if (!(channel instanceof SessionChannel)) return
                channel.hooker.hook("execRequest", (_hook, _context, decision) => {
                    decision.success = true
                })
                channel.events.on("exec", (_command, shell) => {
                    shell.stdout.write("password changed\n", () => shell.exit(0).end())
                })
            })
        })
        server.listen({ host: "127.0.0.1", port: 0 })
        await new Promise<void>((resolve) => server.server!.once("listening", resolve))
        const port = (server.server!.address() as AddressInfo).port

        try {
            const openssh = await collectProcess(
                "/usr/bin/ssh",
                [
                    "-F",
                    "/dev/null",
                    "-T",
                    "-p",
                    String(port),
                    "-o",
                    "PreferredAuthentications=password",
                    "-o",
                    "PubkeyAuthentication=no",
                    "-o",
                    "KbdInteractiveAuthentication=no",
                    "-o",
                    "StrictHostKeyChecking=no",
                    "-o",
                    "UserKnownHostsFile=/dev/null",
                    "-o",
                    "LogLevel=ERROR",
                    "interop@127.0.0.1",
                    "password-change-test",
                ],
                "",
                {
                    env: {
                        ...process.env,
                        DISPLAY: "modernssh-test",
                        SSH_ASKPASS: join(process.cwd(), "__tests__/openssh/askpass.sh"),
                        SSH_ASKPASS_REQUIRE: "force",
                    },
                },
            )
            expect({ openssh, attempts, errors: errors.map(String) }).toEqual({
                openssh: { code: 0, stdout: "password changed\n", stderr: "" },
                attempts: [
                    { password: "correct-horse-battery-staple", newPassword: undefined },
                    { password: "correct-horse-battery-staple", newPassword: "new-password" },
                ],
                errors: [],
            })

            const client = new Client({
                hostname: "127.0.0.1",
                port,
                username: "interop",
                password: "correct-horse-battery-staple",
                authenticationMethodsOrder: [
                    SSHAuthenticationMethods.None,
                    SSHAuthenticationMethods.Password,
                ],
            })
            client.hooker.hook("hostKey", (_hook, decision) => {
                decision.allowHostKey = true
            })
            client.hooker.hook("passwordChange", (_hook, context, decision) => {
                expect(context.prompt).toBe("Choose a new password: ")
                decision.newPassword = "new-password"
            })
            await client.connect()
            client.end()

            expect(attempts).toEqual([
                { password: "correct-horse-battery-staple", newPassword: undefined },
                { password: "correct-horse-battery-staple", newPassword: "new-password" },
                { password: "correct-horse-battery-staple", newPassword: undefined },
                { password: "correct-horse-battery-staple", newPassword: "new-password" },
            ])
            expect(errors).toEqual([])
        } finally {
            for (const client of server.clients) client.terminate()
            await new Promise<void>((resolve, reject) => {
                server.server!.close((error) => (error ? reject(error) : resolve()))
            })
        }
    }, 20_000)

    test("OpenSSH client executes a command on a modernssh server", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({ hostKeys: [hostKey], sendAllHostKeys: false })
        const errors: Error[] = []
        const input: Buffer[] = []
        let command = ""
        let rekeys = 0
        server.hooker.hook("noneAuthentication", (_hook, context, decision) => {
            decision.allowLogin = context.username === "interop"
        })
        server.hooker.hook("channelOpenRequest", (_hook, channel, decision) => {
            decision.allowOpen = channel instanceof SessionChannel
        })
        server.on("connection", (connection) => {
            connection.on("error", (error) => errors.push(error))
            connection.on("rekey", () => rekeys++)
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
                    "-o",
                    "RekeyLimit=1K",
                    "interop@127.0.0.1",
                    "vector-command",
                ],
                "x".repeat(65_536),
            )

            expect(result.code).toBe(17)
            expect(result.stdout).toBe("openssh stdout\n")
            expect(result.stderr).toBe("openssh stderr\n")
            expect(command).toBe("vector-command")
            expect(Buffer.concat(input).toString()).toBe("x".repeat(65_536))
            expect(rekeys).toBeGreaterThan(0)
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

    test("OpenSSH client forwards its agent to a modernssh server", async () => {
        const agent = await createOpenSSHAgentFixture()
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({ hostKeys: [hostKey], sendAllHostKeys: false })
        const errors: Error[] = []
        let resolveResponse!: (response: Buffer) => void
        let rejectResponse!: (error: Error) => void
        const responsePromise = new Promise<Buffer>((resolve, reject) => {
            resolveResponse = resolve
            rejectResponse = reject
        })
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
                channel.hooker.hook("agentForwardRequest", (_hook, decision) => {
                    decision.success = true
                })
                channel.hooker.hook("execRequest", (_hook, _context, decision) => {
                    decision.success = true
                })
                channel.events.on("exec", (_command, shell) => {
                    void (async () => {
                        const forwardedAgent = await connection.openssh_forwardAgent()
                        resolveResponse(await requestAgentIdentities(forwardedAgent.stream))
                        shell.exit(0).end()
                    })().catch((error: Error) => {
                        rejectResponse(error)
                        shell.exit(1).end()
                    })
                })
            })
        })
        server.listen({ host: "127.0.0.1", port: 0 })
        await new Promise<void>((resolve) => server.server!.once("listening", resolve))
        const port = (server.server!.address() as AddressInfo).port

        try {
            const resultPromise = collectProcess(
                "/usr/bin/ssh",
                [
                    "-F",
                    "/dev/null",
                    "-A",
                    "-T",
                    "-p",
                    String(port),
                    "-o",
                    "BatchMode=yes",
                    "-o",
                    "PreferredAuthentications=none",
                    "-o",
                    "PubkeyAuthentication=no",
                    "-o",
                    "StrictHostKeyChecking=no",
                    "-o",
                    "UserKnownHostsFile=/dev/null",
                    "-o",
                    "LogLevel=ERROR",
                    "interop@127.0.0.1",
                    "agent-forwarding-test",
                ],
                "",
                { env: { ...process.env, SSH_AUTH_SOCK: agent.socketPath } },
            )
            const response = await responsePromise
            const result = await resultPromise
            expect(result).toEqual({ code: 0, stdout: "", stderr: "" })
            expect(response.readUInt32BE(0)).toBe(response.length - 4)
            let payload = response.subarray(4)
            expect(payload[0]).toBe(12)
            payload = payload.subarray(1)
            const [count, afterCount] = readNextUint32(payload)
            expect(count).toBe(1)
            const [keyBlob, afterKey] = readNextBuffer(afterCount)
            const [, remaining] = readNextBuffer(afterKey)
            expect(remaining.length).toBe(0)
            expect(PublicKey.parse(keyBlob).equals(agent.publicKey)).toBe(true)
            expect(errors).toEqual([])
        } finally {
            for (const client of server.clients) client.terminate()
            await new Promise<void>((resolve, reject) => {
                server.server!.close((error) => (error ? reject(error) : resolve()))
            })
            await agent.close()
        }
    }, 30_000)

    test("OpenSSH client accepts an X11 channel from a modernssh server", async () => {
        const directory = await mkdtemp(join(tmpdir(), "modernssh-x11-"))
        const authorityPath = join(directory, "Xauthority")
        const realCookie = Buffer.from("ffeeddccbbaa99887766554433221100", "hex")
        let resolveReceivedCookie!: (cookie: Buffer) => void
        const receivedCookie = new Promise<Buffer>((resolve) => {
            resolveReceivedCookie = resolve
        })
        const xServer = await listenOnEphemeralPort((socket) => {
            let request = Buffer.alloc(0)
            socket.on("data", (data: Buffer) => {
                request = Buffer.concat([request, data])
                if (request.length < 12) return
                const protocolLength = request.readUInt16LE(6)
                const cookieLength = request.readUInt16LE(8)
                const total = 12 + ((protocolLength + 3) & ~3) + ((cookieLength + 3) & ~3)
                if (request.length < total) return
                resolveReceivedCookie(parseX11SetupCookie(request))
                socket.end("X11 RESPONSE")
            })
        })
        const display = `127.0.0.1:${xServer.port - 6000}.0`
        await execFileAsync("xauth", [
            "-f",
            authorityPath,
            "add",
            display,
            "MIT-MAGIC-COOKIE-1",
            realCookie.toString("hex"),
        ])

        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({ hostKeys: [hostKey], sendAllHostKeys: false })
        const errors: Error[] = []
        let forwardedResponse: Promise<Buffer> | undefined
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
                let fakeCookie: Buffer | undefined
                channel.hooker.hook("x11Request", (_hook, context, decision) => {
                    fakeCookie = Buffer.from(context.cookie, "hex")
                    decision.success = context.protocol === "MIT-MAGIC-COOKIE-1"
                })
                channel.hooker.hook("execRequest", (_hook, _context, decision) => {
                    decision.success = true
                })
                channel.events.on("exec", (_command, shell) => {
                    forwardedResponse = (async () => {
                        if (!fakeCookie) throw new Error("OpenSSH did not request X11 forwarding")
                        const x11 = await connection.x11("203.0.113.10", 42_000)
                        const response = await exchangeChannel(
                            x11.stream,
                            x11SetupRequest(fakeCookie),
                            12,
                        )
                        shell.exit(0).end()
                        return Buffer.from(response)
                    })()
                    void forwardedResponse.catch(() => shell.exit(1).end())
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
                    "-X",
                    "-T",
                    "-p",
                    String(port),
                    "-o",
                    "BatchMode=yes",
                    "-o",
                    "PreferredAuthentications=none",
                    "-o",
                    "PubkeyAuthentication=no",
                    "-o",
                    "StrictHostKeyChecking=no",
                    "-o",
                    "UserKnownHostsFile=/dev/null",
                    "-o",
                    "LogLevel=ERROR",
                    "interop@127.0.0.1",
                    "x11-forwarding-test",
                ],
                "",
                {
                    env: { ...process.env, DISPLAY: display, XAUTHORITY: authorityPath },
                },
            )
            if (result.code !== 0) {
                throw new Error(
                    `OpenSSH X11 command failed: ${JSON.stringify({ result, errors: errors.map(String) })}`,
                )
            }
            const response = await forwardedResponse
            expect({ result, errors: errors.map(String) }).toEqual({
                result: { code: 0, stdout: "", stderr: "" },
                errors: [],
            })
            expect(await receivedCookie).toEqual(realCookie)
            expect(response?.toString()).toBe("X11 RESPONSE")
        } finally {
            for (const client of server.clients) client.terminate()
            await new Promise<void>((resolve, reject) => {
                server.server!.close((error) => (error ? reject(error) : resolve()))
            })
            await new Promise<void>((resolve, reject) => {
                xServer.server.close((error) => (error ? reject(error) : resolve()))
            })
            await rm(directory, { recursive: true, force: true })
        }
    }, 30_000)

    test("OpenSSH client uses stream-local forwarding on a modernssh server", async () => {
        const directory = await mkdtemp(join(tmpdir(), "modernssh-streamlocal-"))
        const localForwardPath = join(directory, "local-forward.sock")
        const directDestinationPath = join(directory, "direct-destination.sock")
        const remoteForwardPath = join(directory, "remote-forward.sock")
        const remoteTargetPath = join(directory, "remote-target.sock")
        const targetSockets = new Set<Socket>()
        const target = createServer((socket) => {
            targetSockets.add(socket)
            socket.on("close", () => targetSockets.delete(socket))
            socket.on("data", (data: Buffer) => socket.write(data.toString().toUpperCase()))
            socket.on("end", () => socket.end())
        })
        target.listen(remoteTargetPath)
        await new Promise<void>((resolve) => target.once("listening", resolve))

        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({ hostKeys: [hostKey], sendAllHostKeys: false })
        const errors: Error[] = []
        server.hooker.hook("noneAuthentication", (_hook, context, decision) => {
            decision.allowLogin = context.username === "interop"
        })
        server.hooker.hook("channelOpenRequest", (_hook, channel, decision) => {
            decision.allowOpen =
                channel instanceof DirectStreamLocalChannel &&
                channel.details.socketPath === directDestinationPath
        })
        server.hooker.hook("streamLocalForward", (_hook, context, decision) => {
            decision.allow = context.socketPath === remoteForwardPath
        })
        server.on("connection", (connection) => {
            connection.on("error", (error) => errors.push(error))
            connection.on("channel", (channel) => {
                if (!(channel instanceof DirectStreamLocalChannel)) return
                channel.stream.on("data", (data: Buffer) => {
                    channel.stream.write(data.toString().toUpperCase())
                })
                channel.stream.on("end", () => channel.close())
            })
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
                "-L",
                `${localForwardPath}:${directDestinationPath}`,
                "-R",
                `${remoteForwardPath}:${remoteTargetPath}`,
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
            expect(await exchangeUnixWhenReady(localForwardPath, "direct unix", 11)).toBe(
                "DIRECT UNIX",
            )
            expect(await exchangeUnixWhenReady(remoteForwardPath, "remote unix", 11)).toBe(
                "REMOTE UNIX",
            )
            expect(errors).toEqual([])
        } catch (error) {
            throw new Error(`${String(error)}; OpenSSH stderr=${Buffer.concat(stderr).toString()}`)
        } finally {
            ssh.kill("SIGTERM")
            await new Promise<void>((resolve) => {
                if (ssh.exitCode !== null || ssh.signalCode !== null) resolve()
                else ssh.once("close", () => resolve())
            })
            for (const socket of targetSockets) socket.destroy()
            await new Promise<void>((resolve, reject) => {
                target.close((error) => (error ? reject(error) : resolve()))
            })
            for (const client of server.clients) client.terminate()
            await new Promise<void>((resolve, reject) => {
                server.server!.close((error) => (error ? reject(error) : resolve()))
            })
            await rm(directory, { recursive: true, force: true })
        }
    }, 30_000)

    test("OpenSSH sftp client transfers files through a modernssh server", async () => {
        const directory = await mkdtemp(join(tmpdir(), "modernssh-sftp-server-"))
        const root = join(directory, "root")
        const sourcePath = join(directory, "source.bin")
        const destinationPath = join(directory, "destination.bin")
        const contents = Buffer.allocUnsafe(70_000)
        for (let index = 0; index < contents.length; index++) contents[index] = index % 239
        await writeFile(sourcePath, contents)
        await execFileAsync("mkdir", [root])

        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({ hostKeys: [hostKey], sendAllHostKeys: false })
        const errors: Error[] = []
        const requests: string[] = []
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
                channel.hooker.hook("subsystemRequest", (_hook, context, decision) => {
                    decision.success = context.subsystem === "sftp"
                })
                channel.events.on("sftp", (sftp) => {
                    sftp.on("error", (error) => errors.push(error))
                    sftp.on("requestReceived", (request) => {
                        requests.push(`${SFTPPacketType[request.type]}:${request.requestId}`)
                    })
                    attachFilesystemSFTPServer(sftp, root)
                })
            })
        })
        server.listen({ host: "127.0.0.1", port: 0 })
        await new Promise<void>((resolve) => server.server!.once("listening", resolve))
        const port = (server.server!.address() as AddressInfo).port

        try {
            const result = await collectProcess(
                "/usr/bin/sftp",
                [
                    "-F",
                    "/dev/null",
                    "-b",
                    "-",
                    "-P",
                    String(port),
                    "-o",
                    "BatchMode=yes",
                    "-o",
                    "PreferredAuthentications=none",
                    "-o",
                    "PubkeyAuthentication=no",
                    "-o",
                    "StrictHostKeyChecking=no",
                    "-o",
                    "UserKnownHostsFile=/dev/null",
                    "-o",
                    "LogLevel=ERROR",
                    "interop@127.0.0.1",
                ],
                [
                    "mkdir /transfer",
                    `put ${sourcePath} /transfer/source.bin`,
                    "ls -l /transfer",
                    "rename /transfer/source.bin /transfer/renamed.bin",
                    "symlink /transfer/renamed.bin /transfer/renamed.link",
                    `get /transfer/renamed.bin ${destinationPath}`,
                    "rm /transfer/renamed.link",
                    "rm /transfer/renamed.bin",
                    "rmdir /transfer",
                    "quit",
                    "",
                ].join("\n"),
            )
            if (result.code !== 0) {
                throw new Error(
                    `OpenSSH SFTP failed: ${JSON.stringify({ result, errors: errors.map(String), requests })}`,
                )
            }
            expect({
                code: result.code,
                stderr: result.stderr,
                errors: errors.map(String),
            }).toEqual({
                code: 0,
                stderr: "",
                errors: [],
            })
            expect(await readFile(destinationPath)).toEqual(contents)
            expect(result.stdout).toContain("renamed.bin")
        } finally {
            for (const client of server.clients) client.terminate()
            await new Promise<void>((resolve, reject) => {
                server.server!.close((error) => (error ? reject(error) : resolve()))
            })
            await rm(directory, { recursive: true, force: true })
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
        let agentFixture: OpenSSHAgentFixture | undefined
        let transferDirectory: string | undefined

        try {
            const { stdout: portOutput } = await execFileAsync("docker", [
                "port",
                containerId,
                "22/tcp",
            ])
            const port = Number(portOutput.trim().match(/:(\d+)$/u)?.[1])
            expect(Number.isInteger(port)).toBe(true)
            await waitForPort(port)
            agentFixture = await createOpenSSHAgentFixture()
            transferDirectory = await mkdtemp(join(tmpdir(), "modernssh-sftp-client-"))

            const keyboardClient = new Client({
                hostname: "127.0.0.1",
                port,
                username: "interop",
                authenticationMethodsOrder: [
                    SSHAuthenticationMethods.None,
                    SSHAuthenticationMethods.KeyboardInteractive,
                ],
            })
            const keyboardBanners: string[] = []
            const keyboardDebug: unknown[][] = []
            const keyboardErrors: Error[] = []
            keyboardClient.on("banner", (message) => keyboardBanners.push(message))
            keyboardClient.on("debug", (...message) => keyboardDebug.push(message))
            keyboardClient.on("error", (error) => keyboardErrors.push(error))
            keyboardClient.hooker.hook("hostKey", (_hook, decision) => {
                decision.allowHostKey = true
            })
            keyboardClient.hooker.hook("keyboardInteractive", (_hook, context, decision) => {
                decision.responses = context.prompts.map(() => "correct-horse-battery-staple")
            })
            try {
                await keyboardClient.connect()
            } catch (error) {
                throw new Error(
                    `Keyboard-interactive OpenSSH authentication failed: ${String(error)}; ` +
                        `errors=${keyboardErrors.map(String).join(" | ")}; ` +
                        `debug=${JSON.stringify(keyboardDebug)}`,
                )
            }
            const keyboardSession = await keyboardClient.exec("printf keyboard-ok")
            const keyboardOutput: Buffer[] = []
            keyboardSession.on("data", (data: Buffer) => keyboardOutput.push(data))
            await new Promise<void>((resolve) => keyboardSession.once("close", resolve))
            expect(Buffer.concat(keyboardOutput).toString()).toBe("keyboard-ok")
            expect(keyboardBanners).toEqual(["OpenSSH authentication banner\n"])
            keyboardClient.end()

            const client = new Client({
                hostname: "127.0.0.1",
                port,
                username: "interop",
                password: "correct-horse-battery-staple",
                agent: new SSHAgent(agentFixture.socketPath),
                keepaliveInterval: 20,
                keepaliveCountMax: 3,
            })
            const errors: Error[] = []
            let keepalives = 0
            let rekeys = 0
            client.on("error", (error) => errors.push(error))
            client.on("debug", (message, packet) => {
                if (
                    message === "Sending packet:" &&
                    packet instanceof GlobalRequest &&
                    packet.data.request_name === "keepalive@openssh.com"
                ) {
                    keepalives++
                }
            })
            client.on("rekey", () => rekeys++)
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
            let x11Details: { originatorAddress: string; originatorPort: number } | undefined
            client.on("x11", (details, accept) => {
                x11Details = details
                const x11 = accept()!
                x11.on("data", (data: Buffer) => x11.write(data.toString().toUpperCase()))
                x11.on("end", () => x11.close())
            })

            await client.connect()
            await new Promise<void>((resolve) => setTimeout(resolve, 60))
            expect(keepalives).toBeGreaterThan(0)
            const sessionId = Buffer.from(client.sessionID!)
            const exchangeHash = Buffer.from(client.H!)
            await client.rekey()
            expect(rekeys).toBe(1)
            expect(client.sessionID).toEqual(sessionId)
            expect(client.H).not.toEqual(exchangeHash)

            const sftp = await client.sftp()
            expect(sftp.protocolVersion).toBe(3)
            expect(sftp.isOpenSSH).toBe(true)
            expect(sftp.supportsExtension("posix-rename@openssh.com", "1")).toBe(true)
            expect(sftp.limits).toBeDefined()
            expect(sftp.maxReadLength).toBeGreaterThanOrEqual(32_768)
            expect(sftp.maxWriteLength).toBeGreaterThanOrEqual(32_768)

            const sftpDirectory = "/home/interop/modernssh-sftp"
            const originalPath = `${sftpDirectory}/original.bin`
            const renamedPath = `${sftpDirectory}/renamed.bin`
            const linkPath = `${sftpDirectory}/renamed.link`
            const hardlinkPath = `${sftpDirectory}/renamed.hardlink`
            const copiedPath = `${sftpDirectory}/copied.bin`
            const helperPath = `${sftpDirectory}/helpers.txt`
            const transferPath = `${sftpDirectory}/fast-transfer.bin`
            const streamPath = `${sftpDirectory}/stream.bin`
            await sftp.mkdir(sftpDirectory, { permissions: 0o700 })
            const contents = Buffer.allocUnsafe(70_000)
            for (let index = 0; index < contents.length; index++) contents[index] = index % 251

            const writeHandle = await sftp.open(originalPath, "wx", { permissions: 0o640 })
            await sftp.write(writeHandle, contents, 0n)
            expect((await sftp.fstat(writeHandle)).size).toBe(70_000n)
            await sftp.opensshFSync(writeHandle)
            await sftp.close(writeHandle)

            const readHandle = await sftp.open(originalPath, "r")
            const fileSystem = await sftp.opensshFStatVFS(readHandle)
            expect(fileSystem.blockSize).toBeGreaterThan(0n)
            const [tail, beginning, middle] = await Promise.all([
                sftp.read(readHandle, contents.length - 65_536, 65_536n),
                sftp.read(readHandle, 32_768, 0n),
                sftp.read(readHandle, 32_768, 32_768n),
            ])
            await sftp.close(readHandle)
            expect(Buffer.concat([beginning, middle, tail])).toEqual(contents)

            await sftp.chmod(originalPath, "600")
            await sftp.utimes(originalPath, 1_700_000_000, 1_700_000_001)
            const attributes = await sftp.stat(originalPath)
            expect(attributes.size).toBe(70_000n)
            expect(attributes.isFile()).toBe(true)
            expect(attributes.isDirectory()).toBe(false)
            expect(attributes.permissions! & 0o777).toBe(0o600)
            expect(attributes.accessTime).toBe(1_700_000_000)
            expect(attributes.modificationTime).toBe(1_700_000_001)

            await sftp.opensshPosixRename(originalPath, renamedPath)
            expect(await sftp.opensshExpandPath(renamedPath)).toBe(renamedPath)
            expect((await sftp.opensshStatVFS(sftpDirectory)).blockSize).toBe(fileSystem.blockSize)
            await sftp.opensshHardlink(renamedPath, hardlinkPath)
            await sftp.symlink("renamed.bin", linkPath)
            expect(await sftp.readlink(linkPath)).toBe("renamed.bin")
            const linkAttributes = await sftp.lstat(linkPath)
            expect(linkAttributes.permissions! & 0o170000).toBe(0o120000)
            expect(linkAttributes.isSymbolicLink()).toBe(true)
            expect(await sftp.realpath(renamedPath)).toBe(renamedPath)
            const expectedDirectoryEntries = ["renamed.bin", "renamed.hardlink", "renamed.link"]
            if (sftp.supportsExtension("copy-data", "1")) {
                const copySource = await sftp.open(renamedPath, "r")
                const copyDestination = await sftp.open(copiedPath, "wx", { permissions: 0o600 })
                try {
                    await sftp.copyData(copySource, 0n, 0n, copyDestination, 0n)
                } finally {
                    await sftp.close(copySource)
                    await sftp.close(copyDestination)
                }
                expect((await sftp.stat(copiedPath)).size).toBe(70_000n)
                expectedDirectoryEntries.push("copied.bin")
            }
            if (sftp.supportsExtension("home-directory", "1")) {
                // OpenSSH 9.2 advertises the extension but mishandles the draft's empty-username
                // shorthand. Supplying the authenticated user exercises the interoperable form.
                expect(await sftp.homeDirectory("interop")).toBe("/home/interop")
            }
            if (sftp.supportsExtension("users-groups-by-id@openssh.com", "1")) {
                const names = await sftp.usersGroups([attributes.uid!], [attributes.gid!])
                expect(names.usernames).toEqual(["interop"])
                expect(names.groupNames).toEqual(["interop"])
            }
            expect(
                (await sftp.readDirectory(sftpDirectory))
                    .map((entry) => entry.filename.toString())
                    .sort(),
            ).toEqual(expectedDirectoryEntries.sort())

            let missingError: unknown
            try {
                await sftp.stat(`${sftpDirectory}/missing`)
            } catch (error) {
                missingError = error
            }
            expect(missingError).toBeInstanceOf(SFTPStatusError)
            expect((missingError as SFTPStatusError).code).toBe(SFTPStatusCode.NoSuchFile)

            await sftp.writeFile(helperPath, "first", { mode: "640" })
            await sftp.appendFile(helperPath, Buffer.from("-second"))
            expect(await sftp.readFile(helperPath, "utf8")).toBe("first-second")
            expect(await sftp.exists(helperPath)).toBe(true)
            expect(await sftp.exists(`${sftpDirectory}/still-missing`)).toBe(false)
            await expect(sftp.readFile(helperPath, { maxBytes: 5 })).rejects.toThrow(
                "exceeds the 5-byte read limit",
            )

            const transferContents = Buffer.allocUnsafe(350_000)
            for (let index = 0; index < transferContents.length; index++) {
                transferContents[index] = (index * 17) % 251
            }
            const uploadPath = join(transferDirectory, "upload.bin")
            const downloadPath = join(transferDirectory, "download.bin")
            await writeFile(uploadPath, transferContents)
            let uploaded = 0
            await sftp.fastPut(uploadPath, transferPath, {
                chunkSize: 19_999,
                concurrency: 7,
                step: (total) => {
                    uploaded = total
                },
            })
            expect(uploaded).toBe(transferContents.length)
            let downloaded = 0
            await sftp.fastGet(transferPath, downloadPath, {
                chunkSize: 17_777,
                concurrency: 5,
                step: (total) => {
                    downloaded = total
                },
            })
            expect(downloaded).toBe(transferContents.length)
            expect(await readFile(downloadPath)).toEqual(transferContents)

            const writeStream = sftp.createWriteStream(streamPath, { highWaterMark: 11 })
            const writeClosed = once(writeStream, "close")
            writeStream.write("stream-")
            writeStream.write(Buffer.from("payload-"))
            writeStream.end("complete")
            await writeClosed
            expect(writeStream.bytesWritten).toBe(23n)

            const readStream = sftp.createReadStream(streamPath, {
                start: 7,
                end: 14,
                highWaterMark: 3,
            })
            const readClosed = once(readStream, "close")
            const streamChunks: Buffer[] = []
            for await (const chunk of readStream) streamChunks.push(chunk as Buffer)
            await readClosed
            expect(Buffer.concat(streamChunks).toString()).toBe("payload-")
            expect(readStream.bytesRead).toBe(8n)

            await sftp.unlink(linkPath)
            await sftp.unlink(hardlinkPath)
            if (sftp.supportsExtension("copy-data", "1")) await sftp.unlink(copiedPath)
            await sftp.unlink(helperPath)
            await sftp.unlink(transferPath)
            await sftp.unlink(streamPath)
            await sftp.unlink(renamedPath)
            await sftp.rmdir(sftpDirectory)
            const sftpClosed = new Promise<void>((resolve) => sftp.channel.once("close", resolve))
            sftp.end()
            await sftpClosed

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

            const agentSession = await client.openSession()
            const agentOutput: Buffer[] = []
            agentSession.on("data", (data: Buffer) => agentOutput.push(data))
            await agentSession.openssh_forwardAgent()
            await agentSession.exec("ssh-add -L")
            await new Promise<void>((resolve) => agentSession.once("close", resolve))
            const forwardedKey = PublicKey.parseString(Buffer.concat(agentOutput).toString())
            expect(forwardedKey.equals(agentFixture.publicKey)).toBe(true)

            const x11Session = await client.openSession()
            const x11Output: Buffer[] = []
            x11Session.on("data", (data: Buffer) => x11Output.push(data))
            await expect(x11Session.requestX11({ cookie: "not-hex" })).rejects.toThrow(
                "hexadecimal",
            )
            const x11Request = await x11Session.requestX11({
                single: true,
                cookie: "00112233445566778899AABBCCDDEEFF",
            })
            expect(x11Request).toEqual({
                single: true,
                protocol: "MIT-MAGIC-COOKIE-1",
                cookie: "00112233445566778899aabbccddeeff",
                screen: 0,
            })
            await x11Session.exec(
                "display=${DISPLAY#localhost:}; display=${display%%.*}; " +
                    "port=$((6000 + display)); " +
                    "printf 'x11 forwarding' | socat - TCP:127.0.0.1:$port; " +
                    "sleep 0.1; " +
                    "if printf 'second' | socat - TCP:127.0.0.1:$port 2>/dev/null; " +
                    "then exit 42; fi",
            )
            await new Promise<void>((resolve) => x11Session.once("close", resolve))
            expect(Buffer.concat(x11Output).toString()).toBe("X11 FORWARDING")
            expect(x11Session.exitCode).toBe(0)
            expect(x11Details).toEqual({
                originatorAddress: expect.any(String),
                originatorPort: expect.any(Number),
            })

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
            await client.openssh_noMoreSessions()
            await expect(client.openSession()).rejects.toThrow()

            if (client.isConnected) client.end()
            await closed
        } finally {
            await execFileAsync("docker", ["rm", "--force", containerId]).catch(() => undefined)
            await agentFixture?.close()
            if (transferDirectory !== undefined) {
                await rm(transferDirectory, { recursive: true, force: true })
            }
        }
    }, 120_000)
})
