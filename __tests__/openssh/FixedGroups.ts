import { spawn } from "node:child_process"
import { once } from "node:events"
import type { AddressInfo } from "node:net"

import Server from "../../src/Server.js"
import SessionChannel from "../../src/channels/SessionChannel.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

const methods = [
    "diffie-hellman-group14-sha256",
    "diffie-hellman-group16-sha512",
    "diffie-hellman-group18-sha512",
] as const

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

describe("RFC 8268 OpenSSH interoperability", () => {
    test.each(methods)(
        "OpenSSH exchanges traffic and rekeys with %s",
        async (keyExchange) => {
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
                            shell.stdout.write("fixed-group-ok\n", () => shell.exit(0).end())
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
})
