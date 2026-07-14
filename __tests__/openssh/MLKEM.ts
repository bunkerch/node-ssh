import { spawn } from "node:child_process"
import { once } from "node:events"
import type { AddressInfo } from "node:net"

import SessionChannel from "../../src/channels/SessionChannel.js"
import Server from "../../src/Server.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

const keyExchange = "mlkem768x25519-sha256"
const imageName = "modernssh-openssh-test:trixie"

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
    const [code] = (await once(child, "close")) as [number | null]
    return {
        code,
        stdout: Buffer.concat(stdout).toString(),
        stderr: Buffer.concat(stderr).toString(),
    }
}

describe("ML-KEM OpenSSH interoperability", () => {
    test("OpenSSH exchanges traffic and rekeys with a modernssh server", async () => {
        const build = await collectProcess("docker", [
            "build",
            "--quiet",
            "--file",
            "__tests__/openssh/Dockerfile.mlkem",
            "--tag",
            imageName,
            "__tests__/openssh",
        ])
        expect(build).toMatchObject({ code: 0, stderr: "" })

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
})
