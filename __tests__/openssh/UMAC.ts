import { spawn } from "node:child_process"
import type { AddressInfo } from "node:net"
import Server from "../../src/Server.js"
import SessionChannel from "../../src/channels/SessionChannel.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

const variants = [
    "umac-64@openssh.com",
    "umac-128@openssh.com",
    "umac-64-etm@openssh.com",
    "umac-128-etm@openssh.com",
] as const

async function runSSH(port: number, mac: string): Promise<{ code: number | null; output: string }> {
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
            "-o",
            `MACs=${mac}`,
            "test@127.0.0.1",
            "umac-round-trip",
        ],
        { stdio: ["ignore", "pipe", "pipe"] },
    )
    const output: Buffer[] = []
    const errors: Buffer[] = []
    child.stdout.on("data", (data: Buffer) => output.push(data))
    child.stderr.on("data", (data: Buffer) => errors.push(data))
    const code = await new Promise<number | null>((resolve, reject) => {
        child.once("error", reject)
        child.once("close", resolve)
    })
    return {
        code,
        output: `${Buffer.concat(output).toString()}${Buffer.concat(errors).toString()}`,
    }
}

describe("OpenSSH UMAC interoperability", () => {
    test("exchanges channel traffic with every deployed UMAC variant", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({
            hostKeys: [hostKey],
            sendAllHostKeys: false,
            algorithms: { hmac: variants, cipher: ["aes128-ctr"] },
        })
        const negotiated: string[] = []
        let rekeys = 0
        const errors: Error[] = []
        server.hooker.hook("noneAuthentication", async (_hook, _context, decision) => {
            decision.allowLogin = true
        })
        server.hooker.hook("channelOpenRequest", async (_hook, channel, decision) => {
            decision.allowOpen = channel instanceof SessionChannel
        })
        server.on("connection", (connection) => {
            let initialHandshake = true
            connection.on("error", (error) => errors.push(error))
            connection.on("handshake", (algorithms) => {
                if (initialHandshake) negotiated.push(algorithms.cs.mac)
                initialHandshake = false
            })
            connection.on("rekey", () => rekeys++)
            connection.on("channel", (channel) => {
                if (!(channel instanceof SessionChannel)) return
                channel.hooker.hook("execRequest", async (_hook, _context, decision) => {
                    decision.success = true
                })
                channel.events.on("exec", (_command, shell) => {
                    void connection
                        .rekey()
                        .then(() => {
                            shell.stdout.write(`UMAC accepted\n${"x".repeat(8192)}`, () =>
                                shell.exit(0).close(),
                            )
                        })
                        .catch((error: Error) => shell.destroy(error))
                })
            })
        })
        server.listen({ host: "127.0.0.1", port: 0 })
        await new Promise<void>((resolve) => server.server!.once("listening", resolve))
        const port = (server.server!.address() as AddressInfo).port

        try {
            for (const variant of variants) {
                const result = await runSSH(port, variant)
                expect(result.code).toBe(0)
                expect(result.output).toContain("UMAC accepted")
            }
            expect(negotiated).toEqual(variants)
            expect(rekeys).toBeGreaterThanOrEqual(variants.length)
            expect(errors).toEqual([])
        } finally {
            for (const connection of server.clients) connection.terminate()
            await new Promise<void>((resolve, reject) => {
                server.server!.close((error) => (error ? reject(error) : resolve()))
            })
        }
    }, 20_000)
})
