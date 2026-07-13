import { execFile, spawn } from "node:child_process"
import { access, mkdtemp, readFile, rm } from "node:fs/promises"
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

            const client = new Client({
                hostname: "127.0.0.1",
                port,
                username: "interop",
                password: "correct-horse-battery-staple",
                agent: new SSHAgent(agentFixture.socketPath),
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
            let x11Details: { originatorAddress: string; originatorPort: number } | undefined
            client.on("x11", (details, accept) => {
                x11Details = details
                const x11 = accept()!
                x11.on("data", (data: Buffer) => x11.write(data.toString().toUpperCase()))
                x11.on("end", () => x11.close())
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
            client.end()
            await closed
        } finally {
            await execFileAsync("docker", ["rm", "--force", containerId]).catch(() => undefined)
            await agentFixture?.close()
        }
    }, 120_000)
})
