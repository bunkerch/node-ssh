import { execFile } from "node:child_process"
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises"
import { AddressInfo } from "node:net"
import { createConnection } from "node:net"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { promisify } from "node:util"
import SessionChannel from "../../src/channels/SessionChannel.js"
import Client from "../../src/Client.js"
import { SSHAuthenticationMethods } from "../../src/constants.js"
import Server from "../../src/Server.js"
import PrivateKey from "../../src/utils/PrivateKey.js"
import PublicKey, { SSHCertificatePublicKey } from "../../src/utils/PublicKey.js"

const execFileAsync = promisify(execFile)
const imageName = "modernssh-openssh-test:bookworm"

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
        await new Promise<void>((resolve) => setTimeout(resolve, 50))
    }
    throw new Error(`OpenSSH server did not listen on port ${port}`)
}

describe("OpenSSH certificate authentication interoperability", () => {
    test("validates an OpenSSH certificate host through awaited CA policy", async () => {
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
        let client: Client | undefined
        try {
            const { stdout: portOutput } = await execFileAsync("docker", [
                "port",
                containerId,
                "22/tcp",
            ])
            const port = Number(portOutput.trim().match(/:(\d+)$/u)?.[1])
            await waitForPort(port)
            await execFileAsync("docker", [
                "exec",
                containerId,
                "ssh-keygen",
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-f",
                "/tmp/host_ca",
            ])
            await execFileAsync("docker", [
                "exec",
                containerId,
                "ssh-keygen",
                "-q",
                "-s",
                "/tmp/host_ca",
                "-I",
                "openssh-server",
                "-h",
                "-n",
                "127.0.0.1",
                "-V",
                "-1m:+1h",
                "/etc/ssh/ssh_host_ed25519_key.pub",
            ])
            await execFileAsync("docker", [
                "exec",
                containerId,
                "sh",
                "-c",
                "echo 'HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub' >> /etc/ssh/sshd_config",
            ])
            await execFileAsync("docker", ["exec", containerId, "pkill", "-HUP", "sshd"])
            const { stdout: caLine } = await execFileAsync("docker", [
                "exec",
                containerId,
                "cat",
                "/tmp/host_ca.pub",
            ])
            const ca = PublicKey.parseString(caLine)
            let policyCalls = 0
            client = new Client({
                hostname: "127.0.0.1",
                port,
                username: "interop",
                password: "correct-horse-battery-staple",
                authenticationMethodsOrder: [SSHAuthenticationMethods.Password],
            })
            client.hooker.hook("hostKey", async (_hook, decision, key) => {
                await Promise.resolve()
                policyCalls++
                const certificate = key.data.algorithm
                decision.allowHostKey =
                    certificate instanceof SSHCertificatePublicKey &&
                    certificate.data.signatureKey.equals(ca) &&
                    certificate.data.principals.includes("127.0.0.1")
            })
            await client.connect()
            const session = await client.exec("printf openssh-host-certificate-ok")
            const output: Buffer[] = []
            session.on("data", (data: Buffer) => output.push(data))
            await new Promise<void>((resolve) => session.once("close", resolve))
            expect(Buffer.concat(output).toString()).toBe("openssh-host-certificate-ok")
            expect(client.negotiatedAlgorithms?.srvHostKey).toBe("ssh-ed25519-cert-v01@openssh.com")
            expect(policyCalls).toBe(1)
        } finally {
            client?.destroy()
            await execFileAsync("docker", ["rm", "--force", containerId]).catch(() => undefined)
        }
    }, 30_000)

    test("trusts a certificate host key from the library server", async () => {
        const directory = await mkdtemp(join(tmpdir(), "modernssh-openssh-host-certificate-"))
        let server: Server | undefined
        try {
            const caPath = join(directory, "host_ca")
            const hostPath = join(directory, "host")
            const knownHostsPath = join(directory, "known_hosts")
            await execFileAsync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", caPath])
            await execFileAsync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", hostPath])
            await execFileAsync("ssh-keygen", [
                "-q",
                "-s",
                caPath,
                "-I",
                "library-host",
                "-h",
                "-n",
                "127.0.0.1",
                "-V",
                "-1m:+1h",
                hostPath + ".pub",
            ])
            const caLine = (await readFile(caPath + ".pub", "utf8")).trim()
            await writeFile(knownHostsPath, `@cert-authority 127.0.0.1 ${caLine}\n`)
            server = new Server({
                hostKeys: [PrivateKey.fromString(await readFile(hostPath, "utf8"))],
                hostCertificates: [await readFile(hostPath + "-cert.pub")],
                sendAllHostKeys: false,
            })
            server.hooker.hook("noneAuthentication", (_hook, _context, decision) => {
                decision.allowLogin = true
            })
            server.hooker.hook("channelOpenRequest", (_hook, channel, decision) => {
                decision.allowOpen = channel instanceof SessionChannel
            })
            server.on("connection", (connection) => {
                connection.on("channel", (channel) => {
                    if (!(channel instanceof SessionChannel)) return
                    channel.hooker.hook("execRequest", (_hook, _context, decision) => {
                        decision.success = true
                    })
                    channel.events.on("exec", (_command, shell) => {
                        shell.stdout.write("host certificate accepted\n", () =>
                            shell.exit(0).close(),
                        )
                    })
                })
            })
            server.listen({ host: "127.0.0.1", port: 0 })
            await new Promise<void>((resolve) => server!.server!.once("listening", resolve))

            const { stdout, stderr } = await execFileAsync(
                "/usr/bin/ssh",
                [
                    "-F",
                    "/dev/null",
                    "-T",
                    "-p",
                    String((server.server!.address() as AddressInfo).port),
                    "-o",
                    "PreferredAuthentications=none",
                    "-o",
                    "StrictHostKeyChecking=yes",
                    "-o",
                    `UserKnownHostsFile=${knownHostsPath}`,
                    "-o",
                    "LogLevel=ERROR",
                    "host-test@127.0.0.1",
                    "host-certificate-test",
                ],
                { timeout: 10_000 },
            )
            expect(stdout).toBe("host certificate accepted\n")
            expect(stderr).toBe("")
        } finally {
            if (server) {
                for (const connection of server.clients) connection.terminate()
                if (server.server?.listening) {
                    await new Promise<void>((resolve, reject) => {
                        server!.server!.close((error) => (error ? reject(error) : resolve()))
                    })
                }
            }
            await rm(directory, { recursive: true, force: true })
        }
    }, 15_000)

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
                        shell.stdout.write("certificate accepted\n", () => shell.exit(0).close())
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
