import { spawn } from "node:child_process"
import type { AddressInfo } from "node:net"
import Server from "../../src/Server.js"
import SessionChannel from "../../src/channels/SessionChannel.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

describe("OpenSSH end-of-write interoperability", () => {
    test("keeps a session readable after requesting that the client stop writing", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({ hostKeys: [hostKey], sendAllHostKeys: false })
        const errors: Error[] = []
        let sent = false
        server.hooker.hook("noneAuthentication", async (_hook, _context, decision) => {
            decision.allowLogin = true
        })
        server.hooker.hook("channelOpenRequest", async (_hook, channel, decision) => {
            decision.allowOpen = channel instanceof SessionChannel
        })
        server.on("connection", (connection) => {
            connection.on("error", (error) => errors.push(error))
            connection.on("channel", (channel) => {
                if (!(channel instanceof SessionChannel)) return
                channel.hooker.hook("execRequest", async (_hook, _context, decision) => {
                    decision.success = true
                })
                channel.events.on("exec", (_command, shell) => {
                    sent = shell.sendEndOfWrite()
                    shell.stdout.write("output remains readable\n", () => shell.exit(0).end())
                })
            })
        })
        server.listen({ host: "127.0.0.1", port: 0 })
        await new Promise<void>((resolve) => server.server!.once("listening", resolve))
        const port = (server.server!.address() as AddressInfo).port

        const child = spawn(
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
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "test@127.0.0.1",
                "half-close",
            ],
            { stdio: ["pipe", "pipe", "pipe"] },
        )
        const stdout: Buffer[] = []
        const stderr: Buffer[] = []
        child.stdout.on("data", (data: Buffer) => stdout.push(data))
        child.stderr.on("data", (data: Buffer) => stderr.push(data))
        child.stdin.write("input that the server does not need")
        const code = await new Promise<number | null>((resolve, reject) => {
            child.once("error", reject)
            child.once("close", resolve)
        })

        try {
            expect(code).toBe(0)
            expect(sent).toBe(true)
            expect(Buffer.concat(stdout).toString()).toBe("output remains readable\n")
            expect(Buffer.concat(stderr).toString()).not.toContain("request failed")
            expect(errors).toEqual([])
        } finally {
            child.kill("SIGKILL")
            for (const connection of server.clients) connection.terminate()
            await new Promise<void>((resolve, reject) => {
                server.server!.close((error) => (error ? reject(error) : resolve()))
            })
        }
    }, 20_000)
})
