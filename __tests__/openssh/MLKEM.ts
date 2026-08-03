import { spawn } from "node:child_process"
import { once } from "node:events"
import { access, mkdtemp, readFile, rm } from "node:fs/promises"
import type { AddressInfo } from "node:net"
import { createConnection, type Socket } from "node:net"
import { tmpdir } from "node:os"
import { join } from "node:path"

import SessionChannel from "../../src/channels/SessionChannel.js"
import Client from "../../src/Client.js"
import SSHAgent from "../../src/publickey/SSHAgent.js"
import { SSHAgentProtocolClient } from "../../src/publickey/SSHAgentProtocol.js"
import Server from "../../src/Server.js"
import PrivateKey from "../../src/utils/PrivateKey.js"
import PublicKey from "../../src/utils/PublicKey.js"

const keyExchange = "mlkem768x25519-sha256"
const imageName = "modernssh-openssh-test:trixie"
let imageBuild: Promise<void> | undefined

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
    const [code] = (await once(child, "close")) as [number | null]
    return {
        code,
        stdout: Buffer.concat(stdout).toString(),
        stderr: Buffer.concat(stderr).toString(),
    }
}

async function buildImage(): Promise<void> {
    imageBuild ??= collectProcess("docker", [
        "build",
        "--quiet",
        "--file",
        "__tests__/openssh/Dockerfile.mlkem",
        "--tag",
        imageName,
        "__tests__/openssh",
    ]).then((build) => {
        expect(build).toMatchObject({ code: 0, stderr: "" })
    })
    await imageBuild
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

async function connectToPort(port: number): Promise<Socket> {
    for (let attempt = 0; attempt < 100; attempt++) {
        const socket = createConnection({ host: "127.0.0.1", port })
        const connected = await new Promise<boolean>((resolve) => {
            const onError = () => resolve(false)
            socket.once("error", onError)
            socket.once("connect", () => {
                socket.off("error", onError)
                resolve(true)
            })
        })
        if (connected) return socket
        socket.destroy()
        await new Promise<void>((resolve) => setTimeout(resolve, 100))
    }
    throw new Error(`OpenSSH agent relay did not listen on port ${port}`)
}

describe("OpenSSH 10.4 interoperability", () => {
    test("modernssh queries the standard extensions of an OpenSSH 10.4 agent", async () => {
        await buildImage()
        const version = await collectProcess("docker", ["run", "--rm", imageName, "ssh", "-V"])
        expect(version).toEqual({
            code: 0,
            stdout: "",
            stderr: expect.stringContaining("OpenSSH_10.4p1"),
        })

        const started = await collectProcess("docker", [
            "run",
            "--detach",
            "--rm",
            "--publish",
            "127.0.0.1::18080",
            imageName,
            "sh",
            "-c",
            "ssh-agent -D -a /tmp/agent.sock & while [ ! -S /tmp/agent.sock ]; do sleep 0.01; done; exec socat TCP-LISTEN:18080,reuseaddr,fork UNIX-CONNECT:/tmp/agent.sock",
        ])
        expect(started.code).toBe(0)
        const containerId = started.stdout.trim()
        let protocol: SSHAgentProtocolClient | undefined
        try {
            const portResult = await collectProcess("docker", ["port", containerId, "18080/tcp"])
            expect(portResult.code).toBe(0)
            const port = Number(portResult.stdout.trim().match(/:(\d+)$/u)?.[1])
            expect(Number.isInteger(port)).toBe(true)
            const stream = await connectToPort(port)
            protocol = new SSHAgentProtocolClient(stream)
            expect(await protocol.queryExtensions()).toEqual(["session-bind@openssh.com"])
        } finally {
            protocol?.destroy()
            await collectProcess("docker", ["rm", "--force", containerId])
        }
    }, 90_000)

    test("OpenSSH exchanges traffic and rekeys with a modernssh server", async () => {
        await buildImage()

        const server = new Server({
            hostKeys: [PrivateKey.generateSync("ssh-ed25519")],
            sendAllHostKeys: false,
            algorithms: { kex: [keyExchange] },
        })
        const errors: Error[] = []
        const handshakes: string[] = []
        let rekeys = 0
        server.hooker.hook("noneAuthentication", (_hook, context, decision) => {
            decision.allowLogin = context.username === "interop"
        })
        server.hooker.hook("channelOpenRequest", (_hook, channel, decision) => {
            decision.allowOpen = channel instanceof SessionChannel
        })
        server.on("connection", (connection) => {
            connection.on("error", (error) => errors.push(error))
            connection.on("handshake", (negotiated) => handshakes.push(negotiated.kex))
            connection.on("rekey", () => rekeys++)
            connection.on("channel", (channel) => {
                if (!(channel instanceof SessionChannel)) return
                channel.hooker.hook("execRequest", (_hook, _context, decision) => {
                    decision.success = true
                })
                channel.events.on("exec", (_command, shell) => {
                    shell.resume()
                    shell.on("end", () => {
                        const finish = (): void => {
                            shell.stdout.write("mlkem-server-ok\n", () => shell.exit(0).close())
                        }
                        if (rekeys > 0) finish()
                        else connection.once("rekey", finish)
                    })
                })
            })
        })

        server.listen(0, "127.0.0.1")
        await once(server, "listening")
        const port = (server.address() as AddressInfo).port
        try {
            const result = await collectProcess(
                "docker",
                [
                    "run",
                    "--rm",
                    "--interactive",
                    "--network",
                    "host",
                    imageName,
                    "ssh",
                    "-F",
                    "/dev/null",
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
                    "PasswordAuthentication=no",
                    "-o",
                    `KexAlgorithms=${keyExchange}`,
                    "-o",
                    "RekeyLimit=1K",
                    "-o",
                    "StrictHostKeyChecking=no",
                    "-o",
                    "UserKnownHostsFile=/dev/null",
                    "-o",
                    "LogLevel=ERROR",
                    "interop@127.0.0.1",
                    "mlkem-test",
                ],
                "x".repeat(65_536),
            )

            expect({
                errors,
                handshakes: new Set(handshakes),
                process: result,
                rekeyed: rekeys > 0,
            }).toEqual({
                errors: [],
                handshakes: new Set([keyExchange]),
                process: { code: 0, stdout: "mlkem-server-ok\n", stderr: "" },
                rekeyed: true,
            })
        } finally {
            for (const connection of server.clients) connection.terminate()
            await server.close()
        }
    }, 90_000)

    test("modernssh exchanges ping, traffic, and rekeys with an OpenSSH server", async () => {
        await buildImage()
        const agentDirectory = await mkdtemp(join(tmpdir(), "modernssh-rfc9987-forwarding-"))
        const agentSocketPath = join(agentDirectory, "agent.sock")
        const agentKeyPath = join(agentDirectory, "id_ed25519")
        const agentProcess = spawn("ssh-agent", ["-D", "-a", agentSocketPath], { stdio: "ignore" })
        let containerId = ""
        const started = await collectProcess("docker", [
            "run",
            "--detach",
            "--rm",
            "--publish",
            "127.0.0.1::22",
            imageName,
        ])
        expect(started.code).toBe(0)
        containerId = started.stdout.trim()
        try {
            for (let attempt = 0; attempt < 100; attempt++) {
                try {
                    await access(agentSocketPath)
                    break
                } catch {
                    await new Promise<void>((resolve) => setTimeout(resolve, 20))
                }
            }
            await access(agentSocketPath)
            expect(
                await collectProcess("ssh-keygen", [
                    "-q",
                    "-t",
                    "ed25519",
                    "-N",
                    "",
                    "-f",
                    agentKeyPath,
                ]),
            ).toMatchObject({ code: 0, stderr: "" })
            expect(
                await collectProcess("ssh-add", [agentKeyPath], "", {
                    env: { ...process.env, SSH_AUTH_SOCK: agentSocketPath },
                }),
            ).toMatchObject({ code: 0 })
            const agentPublicKey = PublicKey.parseString(
                await readFile(`${agentKeyPath}.pub`, "utf8"),
            )

            const portResult = await collectProcess("docker", ["port", containerId, "22/tcp"])
            expect(portResult.code).toBe(0)
            const port = Number(portResult.stdout.trim().match(/:(\d+)$/u)?.[1])
            expect(Number.isInteger(port)).toBe(true)
            await waitForPort(port)

            const client = new Client({
                hostname: "127.0.0.1",
                port,
                username: "interop",
                password: "correct-horse-battery-staple",
                algorithms: { kex: [keyExchange] },
                agent: new SSHAgent(agentSocketPath),
            })
            const errors: Error[] = []
            const handshakes: string[] = []
            client.on("error", (error) => errors.push(error))
            client.on("handshake", (negotiated) => handshakes.push(negotiated.kex))
            client.hooker.hook("hostKey", (_hook, decision) => {
                decision.allowHostKey = true
            })
            try {
                await client.connect()
                const pingData = Buffer.from("mlkem-transport-ping")
                const pingPromise = client.ping(pingData)
                pingData.fill(0)
                const pingReply = await pingPromise

                expect(client.rfc9987AgentForwarding).toBe(true)
                const agentSession = await client.openSession()
                const agentOutput: Buffer[] = []
                agentSession.on("data", (data: Buffer) => agentOutput.push(data))
                await agentSession.forwardAgent()
                await agentSession.exec("ssh-add -L")
                await once(agentSession, "close")
                expect(
                    PublicKey.parseString(Buffer.concat(agentOutput).toString()).equals(
                        agentPublicKey,
                    ),
                ).toBe(true)

                const first = await client.exec("printf mlkem-client-first")
                const firstOutput: Buffer[] = []
                first.on("data", (data: Buffer) => firstOutput.push(data))
                await once(first, "close")

                const sessionId = Buffer.from(client.sessionID!)
                const firstExchangeHash = Buffer.from(client.exchangeHash!)
                await client.rekey()

                const second = await client.exec("printf mlkem-client-second")
                const secondOutput: Buffer[] = []
                second.on("data", (data: Buffer) => secondOutput.push(data))
                await once(second, "close")

                expect({
                    errors,
                    firstExchangeHashChanged: !client.exchangeHash!.equals(firstExchangeHash),
                    firstOutput: Buffer.concat(firstOutput).toString(),
                    handshakes,
                    pingReply,
                    secondOutput: Buffer.concat(secondOutput).toString(),
                    sessionIdStable: client.sessionID!.equals(sessionId),
                }).toEqual({
                    errors: [],
                    firstExchangeHashChanged: true,
                    firstOutput: "mlkem-client-first",
                    handshakes: [keyExchange, keyExchange],
                    pingReply: Buffer.from("mlkem-transport-ping"),
                    secondOutput: "mlkem-client-second",
                    sessionIdStable: true,
                })
            } finally {
                if (client.isConnected) {
                    const closed = once(client, "close")
                    client.end()
                    await closed
                } else {
                    client.destroy()
                }
            }
        } finally {
            if (containerId) await collectProcess("docker", ["rm", "--force", containerId])
            agentProcess.kill("SIGTERM")
            if (agentProcess.exitCode === null && agentProcess.signalCode === null) {
                await once(agentProcess, "close")
            }
            await rm(agentDirectory, { recursive: true, force: true })
        }
    }, 90_000)
})
