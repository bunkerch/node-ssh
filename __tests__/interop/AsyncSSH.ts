import { spawn, type ChildProcess } from "node:child_process"
import { randomBytes } from "node:crypto"
import { once } from "node:events"
import type { AddressInfo } from "node:net"

import Client from "../../src/Client.js"
import Server from "../../src/Server.js"
import SessionChannel from "../../src/channels/SessionChannel.js"
import PrivateKey from "../../src/utils/PrivateKey.js"
import PublicKey from "../../src/utils/PublicKey.js"

const fixturePath = "__tests__/interop/AsyncSSHPeer.py"
const imageName = "modernssh-independent-peer:asyncssh-2.24.0"
const localPython = process.env.ASYNCSSH_PYTHON
const password = "correct-horse-battery-staple"
const publicKey = PublicKey.parse(
    Buffer.from(
        "0000000b7373682d6564323535313900000020" +
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "hex",
    ),
)
const keyExchanges = [
    "curve448-sha512",
    "rsa2048-sha256",
    "mlkem768nistp256-sha256",
    "mlkem1024nistp384-sha384",
] as const

interface ProcessResult {
    code: number | null
    stdout: string
    stderr: string
}

interface PeerServer {
    port: number
    close: () => Promise<void>
}

let imageBuild: Promise<void> | undefined
let containerCounter = 0

function collectProcess(executable: string, args: string[]): Promise<ProcessResult> {
    return new Promise((resolve, reject) => {
        const child = spawn(executable, args, { stdio: "pipe" })
        const stdout: Buffer[] = []
        const stderr: Buffer[] = []
        child.stdout.on("data", (data: Buffer) => stdout.push(data))
        child.stderr.on("data", (data: Buffer) => stderr.push(data))
        child.once("error", reject)
        child.once("close", (code) =>
            resolve({
                code,
                stdout: Buffer.concat(stdout).toString(),
                stderr: Buffer.concat(stderr).toString(),
            }),
        )
    })
}

async function buildImage(): Promise<void> {
    if (localPython) return
    imageBuild ??= collectProcess("docker", [
        "build",
        "--quiet",
        "--file",
        "__tests__/interop/Dockerfile.asyncssh",
        "--tag",
        imageName,
        "__tests__/interop",
    ]).then((result) => {
        expect(result).toEqual({
            code: 0,
            stdout: expect.any(String),
            stderr: "",
        })
    })
    await imageBuild
}

function peerArguments(args: readonly string[]): {
    executable: string
    args: string[]
    containerName?: string
} {
    if (localPython) {
        return { executable: localPython, args: [fixturePath, ...args] }
    }
    const containerName = `modernssh-independent-${process.pid}-${containerCounter++}-${randomBytes(4).toString("hex")}`
    return {
        executable: "docker",
        args: ["run", "--rm", "--name", containerName, "--network", "host", imageName, ...args],
        containerName,
    }
}

async function runPeer(args: readonly string[]): Promise<ProcessResult> {
    await buildImage()
    const command = peerArguments(args)
    return collectProcess(command.executable, command.args)
}

function readFirstLine(child: ChildProcess): Promise<string> {
    return new Promise((resolve, reject) => {
        let raw = ""
        const cleanup = (): void => {
            clearTimeout(timeout)
            child.stdout!.off("data", onData)
            child.off("error", onError)
            child.off("close", onClose)
        }
        const onData = (data: Buffer): void => {
            raw += data.toString()
            const newline = raw.indexOf("\n")
            if (newline === -1) return
            cleanup()
            resolve(raw.slice(0, newline))
        }
        const onError = (error: Error): void => {
            cleanup()
            reject(error)
        }
        const onClose = (code: number | null): void => {
            cleanup()
            reject(new Error(`Independent SSH peer exited before listening with status ${code}`))
        }
        const timeout = setTimeout(() => {
            cleanup()
            reject(new Error("Independent SSH peer did not report its listening port"))
        }, 10_000)
        child.stdout!.on("data", onData)
        child.once("error", onError)
        child.once("close", onClose)
    })
}

async function startPeerServer(keyExchange: string): Promise<PeerServer> {
    await buildImage()
    const command = peerArguments(["server", keyExchange])
    const child = spawn(command.executable, command.args, { stdio: ["ignore", "pipe", "pipe"] })
    const stderr: Buffer[] = []
    child.stderr!.on("data", (data: Buffer) => stderr.push(data))
    try {
        const line = await readFirstLine(child)
        const port = (JSON.parse(line) as { port?: unknown }).port
        if (!Number.isInteger(port) || (port as number) < 1 || (port as number) > 65_535) {
            throw new Error(`Independent SSH peer returned an invalid port: ${line}`)
        }
        return {
            port: port as number,
            close: async () => {
                if (command.containerName) {
                    await collectProcess("docker", ["rm", "--force", command.containerName])
                } else {
                    child.kill("SIGTERM")
                }
                if (child.exitCode === null && child.signalCode === null) await once(child, "close")
            },
        }
    } catch (error) {
        child.kill("SIGTERM")
        if (child.exitCode === null && child.signalCode === null) await once(child, "close")
        throw new Error(
            `Could not start independent SSH peer: ${Buffer.concat(stderr).toString()}`,
            { cause: error },
        )
    }
}

function decodePeerResult(result: ProcessResult): {
    exitStatus: number
    stdout: string
    stderr: string
} {
    if (result.code !== 0) {
        throw new Error(`Independent SSH peer failed: ${result.stderr}`)
    }
    const parsed = JSON.parse(result.stdout) as {
        exitStatus: number
        stdout: string
        stderr: string
    }
    return {
        exitStatus: parsed.exitStatus,
        stdout: Buffer.from(parsed.stdout, "base64").toString(),
        stderr: Buffer.from(parsed.stderr, "base64").toString(),
    }
}

describe("independent SSH peer interoperability", () => {
    test.each(keyExchanges)(
        "modernssh client exchanges traffic using %s and an Ed448 host key",
        async (keyExchange) => {
            const peer = await startPeerServer(keyExchange)
            const client = new Client({
                hostname: "127.0.0.1",
                port: peer.port,
                username: "interop",
                password,
                algorithms: {
                    kex: [keyExchange],
                    serverHostKey: ["ssh-ed448"],
                    cipher: ["aes128-ctr"],
                    hmac: ["hmac-sha2-256"],
                    compress: ["none"],
                },
            })
            const errors: Error[] = []
            client.on("error", (error) => errors.push(error))
            client.hooker.hook("hostKey", (_hook, decision, key) => {
                decision.allowHostKey = key.data.alg === "ssh-ed448"
            })
            try {
                await client.connect()
                const firstExchangeHash = Buffer.from(client.exchangeHash!)
                await client.rekey()
                expect(client.exchangeHash).not.toEqual(firstExchangeHash)

                const channel = await client.exec("library-client-command")
                const stdout: Buffer[] = []
                const stderr: Buffer[] = []
                channel.on("data", (data: Buffer) => stdout.push(data))
                channel.stderr.on("data", (data: Buffer) => stderr.push(data))
                channel.end("library-input")
                await once(channel, "close")

                expect({
                    errors,
                    exitCode: channel.exitCode,
                    keyExchange: client.negotiatedAlgorithms?.kex,
                    stderr: Buffer.concat(stderr).toString(),
                    stdout: Buffer.concat(stdout).toString(),
                }).toEqual({
                    errors: [],
                    exitCode: 23,
                    keyExchange,
                    stderr: "independent-peer-stderr",
                    stdout: "library-client-command\0library-input",
                })
            } finally {
                client.destroy()
                await peer.close()
            }
        },
        30_000,
    )

    test.each(keyExchanges)(
        "modernssh server exchanges traffic using %s and an Ed448 host key",
        async (keyExchange) => {
            const server = new Server({
                hostKeys: [PrivateKey.generateSync("ssh-ed448")],
                sendAllHostKeys: false,
                debug: process.env.MODERNSSH_PEER_DEBUG
                    ? (...message) => console.error(...message)
                    : undefined,
                algorithms: {
                    kex: [keyExchange],
                    serverHostKey: ["ssh-ed448"],
                    cipher: ["aes128-ctr"],
                    hmac: ["hmac-sha2-256"],
                    compress: ["none"],
                },
            })
            const errors: Error[] = []
            const handshakes: string[] = []
            server.hooker.hook("passwordAuthentication", (_hook, context, decision) => {
                decision.allowLogin =
                    context.username === "interop" && context.password === password
            })
            server.hooker.hook("channelOpenRequest", (_hook, channel, decision) => {
                decision.allowOpen = channel instanceof SessionChannel
            })
            server.on("connection", (connection) => {
                connection.on("error", (error) => errors.push(error))
                connection.on("handshake", (algorithms) => handshakes.push(algorithms.kex))
                connection.on("channel", (channel) => {
                    if (!(channel instanceof SessionChannel)) return
                    channel.hooker.hook("execRequest", (_hook, _context, decision) => {
                        decision.success = true
                    })
                    channel.events.on("exec", (command, shell) => {
                        const input: Buffer[] = []
                        shell.on("data", (data: Buffer) => input.push(data))
                        shell.on("end", () => {
                            shell.stderr.write("library-server-stderr")
                            shell.stdout.write(
                                `${command}\0${Buffer.concat(input).toString()}`,
                                () => shell.exit(23).close(),
                            )
                        })
                    })
                })
            })
            server.listen(0, "127.0.0.1")
            await once(server, "listening")
            const port = (server.address() as AddressInfo).port
            try {
                const peerProcess = await runPeer(["client", String(port), keyExchange])
                if (peerProcess.code !== 0) {
                    throw new Error(
                        `Independent SSH client failed: ${JSON.stringify({
                            errors: errors.map(String),
                            handshakes,
                            process: peerProcess,
                        })}`,
                    )
                }
                const result = decodePeerResult(peerProcess)
                expect({
                    errors,
                    handshakes,
                    result,
                }).toEqual({
                    errors: [],
                    handshakes: [keyExchange],
                    result: {
                        exitStatus: 23,
                        stdout: "independent-client-command\0client-input",
                        stderr: "library-server-stderr",
                    },
                })
            } finally {
                for (const connection of server.clients) connection.terminate()
                await server.close()
            }
        },
        30_000,
    )

    test("modernssh client manages keys through the RFC 4819 subsystem", async () => {
        const peer = await startPeerServer("curve25519-sha256")
        const client = new Client({
            hostname: "127.0.0.1",
            port: peer.port,
            username: "interop",
            password,
            algorithms: {
                kex: ["curve25519-sha256"],
                serverHostKey: ["ssh-ed448"],
                cipher: ["aes128-ctr"],
                hmac: ["hmac-sha2-256"],
                compress: ["none"],
            },
        })
        const errors: Error[] = []
        client.on("error", (error) => errors.push(error))
        client.hooker.hook("hostKey", (_hook, decision, key) => {
            decision.allowHostKey = key.data.alg === "ssh-ed448"
        })

        try {
            await client.connect()
            const subsystem = await client.publicKeySubsystem()
            expect(await subsystem.listAttributes()).toEqual([
                { name: "comment", compulsory: false },
                { name: "shell", compulsory: true },
            ])

            await subsystem.add(publicKey, {
                overwrite: true,
                attributes: [{ name: "comment", value: "library-client" }],
            })
            const listed = await subsystem.list()
            expect(listed).toHaveLength(1)
            expect(listed[0]!.key.equals(publicKey)).toBe(true)
            expect(listed[0]!.attributes).toEqual([
                { name: "comment", value: Buffer.from("library-client") },
            ])

            await subsystem.remove(publicKey)
            expect(await subsystem.list()).toEqual([])
            expect(errors).toEqual([])
            subsystem.end()
        } finally {
            client.destroy()
            await peer.close()
        }
    }, 30_000)

    test("modernssh server manages keys for an independent RFC 4819 client", async () => {
        const server = new Server({
            hostKeys: [PrivateKey.generateSync("ssh-ed448")],
            sendAllHostKeys: false,
            algorithms: {
                kex: ["curve25519-sha256"],
                serverHostKey: ["ssh-ed448"],
                cipher: ["aes128-ctr"],
                hmac: ["hmac-sha2-256"],
                compress: ["none"],
            },
        })
        const errors: Error[] = []
        const operations: string[] = []
        const keys = new Map<
            string,
            { key: PublicKey; attributes: readonly { name: string; value: Buffer }[] }
        >()
        server.hooker.hook("passwordAuthentication", (_hook, context, decision) => {
            decision.allowLogin = context.username === "interop" && context.password === password
        })
        server.hooker.hook("channelOpenRequest", (_hook, channel, decision) => {
            decision.allowOpen = channel instanceof SessionChannel
        })
        server.on("connection", (connection) => {
            connection.on("error", (error) => errors.push(error))
            connection.on("channel", (channel) => {
                if (!(channel instanceof SessionChannel)) return
                channel.hooker.hook("subsystemRequest", (_hook, context, decision) => {
                    if (context.subsystem !== "publickey") return
                    decision.success = true
                    decision.publicKey = {
                        attributes: [
                            { name: "comment", compulsory: false },
                            { name: "shell", compulsory: true },
                        ],
                    }
                })
                channel.events.on("publicKey", (subsystem) => {
                    subsystem.hooker.hook("add", (_hook, context, decision) => {
                        operations.push(`add:${context.overwrite}`)
                        keys.set(context.key.hash("sha256"), {
                            key: context.key,
                            attributes: context.attributes,
                        })
                        decision.success = true
                    })
                    subsystem.hooker.hook("list", (_hook, decision) => {
                        operations.push("list")
                        decision.keys = [...keys.values()]
                        decision.success = true
                    })
                    subsystem.hooker.hook("remove", (_hook, context, decision) => {
                        operations.push("remove")
                        decision.success = keys.delete(context.key.hash("sha256"))
                    })
                })
            })
        })
        server.listen(0, "127.0.0.1")
        await once(server, "listening")

        try {
            const result = await runPeer([
                "publickey-client",
                String((server.address() as AddressInfo).port),
                "curve25519-sha256",
            ])
            expect({
                errors,
                operations,
                process: {
                    code: result.code,
                    stderr: result.stderr,
                    stdout: JSON.parse(result.stdout),
                },
            }).toEqual({
                errors: [],
                operations: ["add:true", "list", "remove", "list"],
                process: {
                    code: 0,
                    stderr: "",
                    stdout: {
                        algorithm: "ssh-ed25519",
                        capabilities: [
                            ["comment", false],
                            ["shell", true],
                        ],
                        comment: "independent-client",
                        removed: true,
                    },
                },
            })
        } finally {
            for (const connection of server.clients) connection.terminate()
            await server.close()
        }
    }, 30_000)
})
