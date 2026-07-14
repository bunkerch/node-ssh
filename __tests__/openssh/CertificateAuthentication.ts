import { execFile } from "node:child_process"
import { mkdtemp, readFile, rm } from "node:fs/promises"
import { AddressInfo } from "node:net"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { promisify } from "node:util"
import SessionChannel from "../../src/channels/SessionChannel.js"
import Server from "../../src/Server.js"
import PrivateKey from "../../src/utils/PrivateKey.js"
import PublicKey from "../../src/utils/PublicKey.js"

const execFileAsync = promisify(execFile)

describe("OpenSSH certificate authentication interoperability", () => {
    test("accepts an OpenSSH client certificate through awaited policy", async () => {
        const directory = await mkdtemp(join(tmpdir(), "modernssh-openssh-certificate-"))
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({ hostKeys: [hostKey], sendAllHostKeys: false })
        const errors: Error[] = []
        try {
            const caPath = join(directory, "ca")
            const identityPath = join(directory, "identity")
            await execFileAsync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", caPath])
            await execFileAsync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", identityPath])
            await execFileAsync("ssh-keygen", [
                "-q",
                "-s",
                caPath,
                "-I",
                "openssh-client",
                "-n",
                "certificate-user",
                "-V",
                "-1m:+1h",
                identityPath + ".pub",
            ])
            const ca = PublicKey.parseString(await readFile(caPath + ".pub", "utf8"))

            server.hooker.hook("publicKeyAuthentication", async (_hook, context, decision) => {
                await Promise.resolve()
                const certificate = context.certificate
                const authorized =
                    context.username === "certificate-user" &&
                    certificate?.data.signatureKey.equals(ca) === true &&
                    certificate.data.principals.includes("certificate-user") &&
                    certificate.data.criticalOptions.length === 0
                if (!context.signature) decision.requestSignature = authorized
                else decision.allowLogin = authorized
            })
            server.hooker.hook("channelOpenRequest", (_hook, channel, decision) => {
                decision.allowOpen = channel instanceof SessionChannel
            })
            server.on("connection", (connection) => {
                connection.on("error", (error) => errors.push(error))
                connection.on("channel", (channel) => {
                    if (!(channel instanceof SessionChannel)) return
                    channel.hooker.hook("execRequest", (_hook, _context, decision) => {
                        decision.success = true
                    })
                    channel.events.on("exec", (_command, shell) => {
                        shell.stdout.write("certificate accepted\n", () => shell.exit(0).end())
                    })
                })
            })
            server.listen({ host: "127.0.0.1", port: 0 })
            await new Promise<void>((resolve) => server.server!.once("listening", resolve))

            const { stdout, stderr } = await execFileAsync(
                "/usr/bin/ssh",
                [
                    "-F",
                    "/dev/null",
                    "-T",
                    "-p",
                    String((server.server!.address() as AddressInfo).port),
                    "-i",
                    identityPath,
                    "-o",
                    `CertificateFile=${identityPath}-cert.pub`,
                    "-o",
                    "IdentitiesOnly=yes",
                    "-o",
                    "PreferredAuthentications=publickey",
                    "-o",
                    "StrictHostKeyChecking=no",
                    "-o",
                    "UserKnownHostsFile=/dev/null",
                    "-o",
                    "LogLevel=ERROR",
                    "certificate-user@127.0.0.1",
                    "certificate-test",
                ],
                { timeout: 10_000 },
            )
            expect(stdout).toBe("certificate accepted\n")
            expect(stderr).toBe("")
            expect(errors).toEqual([])
        } finally {
            for (const connection of server.clients) connection.terminate()
            if (server.server?.listening) {
                await new Promise<void>((resolve, reject) => {
                    server.server!.close((error) => (error ? reject(error) : resolve()))
                })
            }
            await rm(directory, { recursive: true, force: true })
        }
    }, 15_000)
})
