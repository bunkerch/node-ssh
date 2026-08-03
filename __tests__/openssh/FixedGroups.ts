import { execFile, spawn } from "node:child_process"
import { once } from "node:events"
import { createConnection, type AddressInfo } from "node:net"
import { promisify } from "node:util"

import Client from "../../src/Client.js"
import Server from "../../src/Server.js"
import SessionChannel from "../../src/channels/SessionChannel.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

const execFileAsync = promisify(execFile)
const imageName = "modernssh-openssh-test:bookworm"

const methods = [
    ["RFC 4253", "diffie-hellman-group1-sha1"],
    ["RFC 4253", "diffie-hellman-group14-sha1"],
    ["RFC 8268", "diffie-hellman-group14-sha256"],
    ["RFC 8268", "diffie-hellman-group16-sha512"],
    ["RFC 8268", "diffie-hellman-group18-sha512"],
] as const

async function waitForPort(port: number): Promise<void> {
    for (let attempt = 0; attempt < 100; attempt++) {
        const identified = await new Promise<boolean>((resolve) => {
            const socket = createConnection({ host: "127.0.0.1", port })
            let settled = false
            const finish = (ready: boolean) => {
                if (settled) return
                settled = true
                socket.destroy()
                resolve(ready)
            }
            socket.setTimeout(100, () => finish(false))
            socket.once("data", (data) => finish(data.toString().startsWith("SSH-")))
            socket.once("close", () => finish(false))
            socket.once("error", () => finish(false))
        })
        if (identified) return
        await new Promise<void>((resolve) => setTimeout(resolve, 100))
    }
    throw new Error(`OpenSSH server did not listen on port ${port}`)
}

async function execute(client: Client, command: string): Promise<string> {
    const channel = await client.exec(command)
    const output: Buffer[] = []
    channel.on("data", (data: Buffer) => output.push(data))
    await once(channel, "close")
    expect(channel.exitCode).toBe(0)
    return Buffer.concat(output).toString()
}

async function collectProcess(
    executable: string,
    args: string[],
    input: string,
): Promise<{ code: number | null; stdout: string; stderr: string }> {
    const child = spawn(executable, args, { stdio: "pipe" })
    const stdout: Buffer[] = []
    const stderr: Buffer[] = []
    child.stdout.on("data", (data: Buffer) => stdout.push(data))
    child.stderr.on("data", (data: Buffer) => stderr.push(data))
    child.stdin.end(input)
    const [code] = await once(child, "close")
    return {
        code: code as number | null,
        stdout: Buffer.concat(stdout).toString(),
        stderr: Buffer.concat(stderr).toString(),
    }
}

describe("fixed-group Diffie-Hellman OpenSSH interoperability", () => {
    test.each(methods)(
        "%s OpenSSH exchanges traffic and rekeys with %s",
        async (_, keyExchange) => {
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
                            shell.stdout.write("fixed-group-ok\n", () => shell.exit(0).close())
                        })
                    })
                })
            })

            server.listen(0, "127.0.0.1")
            await once(server, "listening")
            const port = (server.address() as AddressInfo).port
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
                        "fixed-group-test",
                    ],
                    "x".repeat(65_536),
                )
                expect(result).toEqual({ code: 0, stdout: "fixed-group-ok\n", stderr: "" })
                expect(new Set(handshakes)).toEqual(new Set([keyExchange]))
                expect(rekeys).toBeGreaterThan(0)
                expect(errors).toEqual([])
            } finally {
                for (const connection of server.clients) connection.terminate()
                await server.close()
            }
        },
        20_000,
    )

    test("library client exchanges traffic and rekeys with every enabled fixed group", async () => {
        await execFileAsync("docker", ["build", "--quiet", "--tag", imageName, "__tests__/openssh"])
        const { stdout } = await execFileAsync("docker", [
            "run",
            "--detach",
            "--rm",
            "--publish",
            "127.0.0.1::22",
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

            for (const [, keyExchange] of methods) {
                const client = new Client({
                    hostname: "127.0.0.1",
                    port,
                    username: "interop",
                    password: "correct-horse-battery-staple",
                    readyTimeout: 5_000,
                    algorithms: { kex: [keyExchange] },
                })
                const errors: Error[] = []
                client.on("error", (error) => errors.push(error))
                client.hooker.hook("hostKey", (_hook, decision) => {
                    decision.allowHostKey = true
                })

                try {
                    await client.connect()
                    expect(client.negotiatedAlgorithms?.kex).toBe(keyExchange)
                    const sessionId = Buffer.from(client.sessionID!)
                    const firstHash = Buffer.from(client.exchangeHash!)
                    expect(await execute(client, "printf fixed-group-before")).toBe(
                        "fixed-group-before",
                    )

                    await client.rekey()
                    expect(client.sessionID).toEqual(sessionId)
                    expect(client.exchangeHash).not.toEqual(firstHash)
                    expect(await execute(client, "printf fixed-group-after")).toBe(
                        "fixed-group-after",
                    )
                    expect(errors).toEqual([])
                } finally {
                    if (client.isConnected) {
                        const closed = once(client, "close")
                        client.end()
                        await closed
                    } else {
                        client.destroy()
                    }
                }
            }
        } finally {
            await execFileAsync("docker", ["rm", "--force", containerId]).catch(() => undefined)
        }
    }, 60_000)
})
