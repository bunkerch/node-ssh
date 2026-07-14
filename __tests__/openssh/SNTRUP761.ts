import { spawn } from "node:child_process"
import { once } from "node:events"
import type { AddressInfo } from "node:net"
import { createConnection } from "node:net"

import Client from "../../src/Client.js"
import Server from "../../src/Server.js"
import SessionChannel from "../../src/channels/SessionChannel.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

const keyExchange = "sntrup761x25519-sha512@openssh.com"
const imageName = "modernssh-openssh-test:bookworm"

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

describe("RFC 9941 OpenSSH interoperability", () => {
    test("OpenSSH exchanges traffic and rekeys with a modernssh server", async () => {
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
                        shell.stdout.write("hybrid-server-ok\n", () => shell.exit(0).close())
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
                    "hybrid-test",
                ],
                "x".repeat(65_536),
            )
            expect(result).toEqual({ code: 0, stdout: "hybrid-server-ok\n", stderr: "" })
            expect(new Set(handshakes)).toEqual(new Set([keyExchange]))
            expect(rekeys).toBeGreaterThan(0)
            expect(errors).toEqual([])
        } finally {
            for (const connection of server.clients) connection.terminate()
            await server.close()
        }
    }, 20_000)

    test("modernssh exchanges traffic and rekeys with an OpenSSH server", async () => {
        const build = await collectProcess("docker", [
            "build",
            "--quiet",
            "--tag",
            imageName,
            "__tests__/openssh",
        ])
        expect(build.code).toBe(0)
        const started = await collectProcess("docker", [
            "run",
            "--detach",
            "--rm",
            "--publish",
            "127.0.0.1::22",
            imageName,
        ])
        expect(started.code).toBe(0)
        const containerId = started.stdout.trim()
        try {
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
                const first = await client.exec("printf hybrid-client-first")
                const firstOutput: Buffer[] = []
                first.on("data", (data: Buffer) => firstOutput.push(data))
                await once(first, "close")
                expect(Buffer.concat(firstOutput).toString()).toBe("hybrid-client-first")

                const sessionId = Buffer.from(client.sessionID!)
                const firstExchangeHash = Buffer.from(client.H!)
                await client.rekey()
                expect(client.sessionID).toEqual(sessionId)
                expect(client.H).not.toEqual(firstExchangeHash)

                const second = await client.exec("printf hybrid-client-second")
                const secondOutput: Buffer[] = []
                second.on("data", (data: Buffer) => secondOutput.push(data))
                await once(second, "close")
                expect(Buffer.concat(secondOutput).toString()).toBe("hybrid-client-second")
                expect(handshakes).toEqual([keyExchange, keyExchange])
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
        } finally {
            await collectProcess("docker", ["rm", "--force", containerId])
        }
    }, 30_000)
})
