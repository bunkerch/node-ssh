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
const transportProfiles = [
    ["mlkem512-sha256", "mlkem512-sha256", "aes128-ctr", "hmac-sha2-256"],
    ["mlkem768-sha256", "mlkem768-sha256", "aes128-ctr", "hmac-sha2-256"],
    ["mlkem1024-sha384", "mlkem1024-sha384", "aes128-ctr", "hmac-sha2-256"],
    ["curve448-sha512", "curve448-sha512", "aes128-ctr", "hmac-sha2-256"],
    ["rsa2048-sha256", "rsa2048-sha256", "aes128-ctr", "hmac-sha2-256"],
    ["mlkem768nistp256-sha256", "mlkem768nistp256-sha256", "aes128-ctr", "hmac-sha2-256"],
    ["mlkem1024nistp384-sha384", "mlkem1024nistp384-sha384", "aes128-ctr", "hmac-sha2-256"],
    ["AEAD_AES_128_GCM", "curve448-sha512", "AEAD_AES_128_GCM", "AEAD_AES_128_GCM"],
    ["AEAD_AES_256_GCM", "curve448-sha512", "AEAD_AES_256_GCM", "AEAD_AES_256_GCM"],
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

async function startPeerServer(
    keyExchange: string,
    cipher = "aes128-ctr",
    mac = "hmac-sha2-256",
): Promise<PeerServer> {
    await buildImage()
    const command = peerArguments(["server", keyExchange, cipher, mac])
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
    elevated: boolean
    exitStatus: number
    stdout: string
    stderr: string
} {
    if (result.code !== 0) {
        throw new Error(`Independent SSH peer failed: ${result.stderr}`)
    }
    const parsed = JSON.parse(result.stdout) as {
        elevated: boolean
        exitStatus: number
        stdout: string
        stderr: string
    }
    return {
        elevated: parsed.elevated,
        exitStatus: parsed.exitStatus,
        stdout: Buffer.from(parsed.stdout, "base64").toString(),
        stderr: Buffer.from(parsed.stderr, "base64").toString(),
    }
}

async function exchangeClientCommand(
    client: Client,
    command: string,
    input: string,
): Promise<{ exitCode: number | null; stdout: string; stderr: string }> {
    const channel = await client.exec(command)
    const stdout: Buffer[] = []
    const stderr: Buffer[] = []
    channel.on("data", (data: Buffer) => stdout.push(data))
    channel.stderr.on("data", (data: Buffer) => stderr.push(data))
    channel.end(input)
    await once(channel, "close")
    return {
        exitCode: channel.exitCode,
        stdout: Buffer.concat(stdout).toString(),
        stderr: Buffer.concat(stderr).toString(),
    }
}

describe("independent SSH peer interoperability", () => {
    test.each(transportProfiles)(
        "modernssh client exchanges traffic using %s and an Ed448 host key",
        async (_profile, keyExchange, cipher, mac) => {
            const peer = await startPeerServer(keyExchange, cipher, mac)
            const client = new Client({
                hostname: "127.0.0.1",
                port: peer.port,
                username: "interop",
                password,
                algorithms: {
                    kex: [keyExchange],
                    serverHostKey: ["ssh-ed448"],
                    cipher: [cipher],
                    hmac: [mac],
                    compress: ["none"],
                },
                noFlowControl: "preferred",
                elevation: "unelevated",
                delayCompression: true,
            })
            const errors: Error[] = []
            client.on("error", (error) => errors.push(error))
            client.hooker.hook("hostKey", (_hook, decision, key) => {
                decision.allowHostKey = key.data.alg === "ssh-ed448"
            })
            const elevation = once(client, "elevation", {
                signal: AbortSignal.timeout(2_000),
            })
            try {
                await client.connect()
                expect(await elevation).toEqual([false])
                expect(client.serverSupportsGlobalRequests).toBe(true)
                expect(client.negotiatedAlgorithms?.cs.compress).toBe("zlib")
                expect(client.negotiatedAlgorithms?.sc.compress).toBe("zlib")
                const compressedInput = "compressed-library-input ".repeat(2_048)
                expect(
                    await exchangeClientCommand(
                        client,
                        "compressed-library-client-command",
                        compressedInput,
                    ),
                ).toEqual({
                    exitCode: 23,
                    stderr: "independent-peer-stderr",
                    stdout: `compressed-library-client-command\0${compressedInput}`,
                })

                const firstExchangeHash = Buffer.from(client.exchangeHash!)
                await client.rekey()
                expect(client.exchangeHash).not.toEqual(firstExchangeHash)
                expect(client.negotiatedAlgorithms?.cs.compress).toBe("none")
                expect(client.negotiatedAlgorithms?.sc.compress).toBe("none")
                const result = await exchangeClientCommand(
                    client,
                    "library-client-command",
                    "library-input",
                )

                expect({
                    errors,
                    elevated: client.elevated,
                    keyExchange: client.negotiatedAlgorithms?.kex,
                    cipher: client.negotiatedAlgorithms?.cs.cipher,
                    mac: client.negotiatedAlgorithms?.cs.mac,
                    noFlowControl: client.noFlowControl,
                    result,
                }).toEqual({
                    errors: [],
                    elevated: false,
                    keyExchange,
                    cipher,
                    mac,
                    noFlowControl: true,
                    result: {
                        exitCode: 23,
                        stderr: "independent-peer-stderr",
                        stdout: "library-client-command\0library-input",
                    },
                })
            } finally {
                client.destroy()
                await peer.close()
            }
        },
        30_000,
    )

    test.each(transportProfiles)(
        "modernssh server exchanges traffic using %s and an Ed448 host key",
        async (_profile, keyExchange, cipher, mac) => {
            const server = new Server({
                hostKeys: [PrivateKey.generateSync("ssh-ed448")],
                sendAllHostKeys: false,
                debug: process.env.MODERNSSH_PEER_DEBUG
                    ? (...message) => console.error(...message)
                    : undefined,
                algorithms: {
                    kex: [keyExchange],
                    serverHostKey: ["ssh-ed448"],
                    cipher: [cipher],
                    hmac: [mac],
                    compress: ["none"],
                },
                noFlowControl: "supported",
                delayCompression: true,
            })
            const errors: Error[] = []
            const handshakes: {
                kex: string
                cs: { cipher: string; mac: string }
                sc: { cipher: string; mac: string }
            }[] = []
            const clientElevationPreferences: (string | undefined)[] = []
            const globalRequestSupport: boolean[] = []
            const noFlowControl: boolean[] = []
            const elevationPreferences: string[] = []
            const compressionBeforeRekey: { cs: string; sc: string }[] = []
            server.hooker.hook("passwordAuthentication", (_hook, context, decision) => {
                decision.allowLogin =
                    context.username === "interop" && context.password === password
            })
            server.hooker.hook("channelOpenRequest", (_hook, channel, decision) => {
                decision.allowOpen = channel instanceof SessionChannel
            })
            server.hooker.hook("elevation", (_hook, context, decision) => {
                elevationPreferences.push(context.preference)
                decision.elevated = false
            })
            server.on("connection", (connection) => {
                connection.on("error", (error) => errors.push(error))
                connection.on("handshake", (algorithms) =>
                    handshakes.push({
                        kex: algorithms.kex,
                        cs: {
                            cipher: algorithms.cs.cipher,
                            mac: algorithms.cs.mac,
                        },
                        sc: {
                            cipher: algorithms.sc.cipher,
                            mac: algorithms.sc.mac,
                        },
                    }),
                )
                connection.on("clientExtensions", () => {
                    clientElevationPreferences.push(connection.clientElevationPreference)
                    globalRequestSupport.push(connection.clientSupportsGlobalRequests)
                    noFlowControl.push(connection.noFlowControl)
                })
                connection.on("channel", (channel) => {
                    if (!(channel instanceof SessionChannel)) return
                    channel.hooker.hook("execRequest", async (_hook, _context, decision) => {
                        compressionBeforeRekey.push({
                            cs: connection.negotiatedAlgorithms!.cs.compress,
                            sc: connection.negotiatedAlgorithms!.sc.compress,
                        })
                        await connection.rekey()
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
                const peerProcess = await runPeer([
                    "client",
                    String(port),
                    keyExchange,
                    cipher,
                    mac,
                ])
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
                    clientElevationPreferences,
                    compressionBeforeRekey,
                    errors,
                    elevationPreferences,
                    globalRequestSupport,
                    handshakes,
                    noFlowControl,
                    result,
                }).toEqual({
                    clientElevationPreferences: ["unelevated"],
                    compressionBeforeRekey: [{ cs: "zlib", sc: "zlib" }],
                    errors: [],
                    elevationPreferences: ["unelevated"],
                    globalRequestSupport: [true],
                    handshakes: [
                        {
                            kex: keyExchange,
                            cs: { cipher, mac },
                            sc: { cipher, mac },
                        },
                        {
                            kex: keyExchange,
                            cs: { cipher, mac },
                            sc: { cipher, mac },
                        },
                    ],
                    noFlowControl: [true],
                    result: {
                        elevated: false,
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

    test("modernssh client manages RFC 7076 namespaces and certificates", async () => {
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
                { name: "namespace", compulsory: false },
            ])

            await subsystem.add(publicKey, {
                overwrite: true,
                namespace: "ssh",
                attributes: [{ name: "comment", value: "library-client" }],
            })
            const listed = await subsystem.list({ namespace: "ssh" })
            expect(listed).toHaveLength(1)
            expect(listed[0]!.key.equals(publicKey)).toBe(true)
            expect(listed[0]!.attributes).toEqual([
                { name: "namespace", value: Buffer.from("ssh") },
                { name: "comment", value: Buffer.from("library-client") },
            ])

            await subsystem.remove(publicKey, { namespace: "ssh" })
            expect(await subsystem.list({ namespace: "ssh" })).toEqual([])
            await subsystem.addCertificate("X509", Buffer.from([1, 2, 3]), {
                namespace: "ssh",
            })
            expect(await subsystem.listCertificates()).toEqual([
                {
                    format: "X509",
                    certificate: Buffer.from([1, 2, 3]),
                    namespace: "ssh",
                    attributes: [{ name: "namespace", value: Buffer.from("ssh") }],
                },
            ])
            await subsystem.removeCertificate("X509", Buffer.from([1, 2, 3]), {
                namespace: "ssh",
            })
            expect(await subsystem.listNamespaces()).toEqual(["ssh", "ssl"])
            expect(errors).toEqual([])
            subsystem.end()
        } finally {
            client.destroy()
            await peer.close()
        }
    }, 30_000)

    test("modernssh server manages RFC 7076 data for an independent client", async () => {
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
        const certificates = new Map<
            string,
            { format: string; certificate: Buffer; namespace: string }
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
                        expect(context.namespace).toBe("ssh")
                        operations.push(`add:${context.overwrite}`)
                        keys.set(context.key.hash("sha256"), {
                            key: context.key,
                            attributes: context.attributes,
                        })
                        decision.success = true
                    })
                    subsystem.hooker.hook("list", (_hook, decision, context) => {
                        expect(context.namespace).toBe("ssh")
                        operations.push("list")
                        decision.keys = [...keys.values()]
                        decision.success = true
                    })
                    subsystem.hooker.hook("remove", (_hook, context, decision) => {
                        expect(context.namespace).toBe("ssh")
                        operations.push("remove")
                        decision.success = keys.delete(context.key.hash("sha256"))
                    })
                    subsystem.hooker.hook("addCertificate", (_hook, context, decision) => {
                        operations.push("add-certificate")
                        certificates.set(context.certificate.toString("hex"), {
                            format: context.format,
                            certificate: Buffer.from(context.certificate),
                            namespace: context.namespace,
                        })
                        decision.success = true
                    })
                    subsystem.hooker.hook("listCertificates", (_hook, decision) => {
                        operations.push("list-certificates")
                        decision.certificates = [...certificates.values()]
                        decision.success = true
                    })
                    subsystem.hooker.hook("removeCertificate", (_hook, context, decision) => {
                        operations.push("remove-certificate")
                        decision.success = certificates.delete(context.certificate.toString("hex"))
                    })
                    subsystem.hooker.hook("listNamespaces", (_hook, decision) => {
                        operations.push("list-namespaces")
                        decision.namespaces = ["ssh", "ssl"]
                        decision.success = true
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
                operations: [
                    "add:true",
                    "list",
                    "remove",
                    "list",
                    "add-certificate",
                    "list-certificates",
                    "remove-certificate",
                    "list-namespaces",
                ],
                process: {
                    code: 0,
                    stderr: "",
                    stdout: {
                        algorithm: "ssh-ed25519",
                        capabilities: [
                            ["comment", false],
                            ["shell", true],
                            ["namespace", false],
                        ],
                        certificate: "010203",
                        comment: "independent-client",
                        namespaces: ["ssh", "ssl"],
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
