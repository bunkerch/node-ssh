import { execFile, spawn, type ChildProcess } from "node:child_process"
import { once } from "node:events"
import { existsSync } from "node:fs"
import { access, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { promisify } from "node:util"

import {
    SSHAgentProtocolClient,
    SSHAgentProtocolError,
} from "../../src/publickey/SSHAgentProtocol.js"
import SSHAgent from "../../src/publickey/SSHAgent.js"

const execFileAsync = promisify(execFile)
const providerPaths = [
    "/usr/lib/softhsm/libsofthsm2.so",
    "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
    "/usr/lib64/pkcs11/libsofthsm2.so",
]
const providerPath = providerPaths.find(existsSync)
const systemFixtureAvailable =
    process.platform !== "win32" &&
    providerPath !== undefined &&
    existsSync("/usr/bin/softhsm2-util") &&
    existsSync("/usr/bin/openssl") &&
    existsSync("/usr/bin/ssh-agent")

async function waitForSocket(socketPath: string, process: ChildProcess): Promise<void> {
    for (let attempt = 0; attempt < 100; attempt++) {
        if (process.exitCode !== null) {
            throw new Error(`System SSH agent exited before creating ${socketPath}`)
        }
        try {
            await access(socketPath)
            return
        } catch {
            await new Promise<void>((resolve) => setTimeout(resolve, 10))
        }
    }
    throw new Error(`System SSH agent did not create ${socketPath}`)
}

describe("system SSH agent token interoperability", () => {
    test.skipIf(!systemFixtureAvailable)(
        "loads, signs with, and removes a constrained SoftHSM token",
        async () => {
            if (providerPath === undefined) throw new Error("SoftHSM provider is unavailable")
            const provider = providerPath

            const directory = await mkdtemp(join(tmpdir(), "modernssh-agent-token-"))
            const tokenDirectory = join(directory, "tokens")
            const configurationPath = join(directory, "softhsm2.conf")
            const privateKeyPath = join(directory, "token-key.pem")
            const socketPath = join(directory, "agent.sock")
            const pin = "1234"
            let agentProcess: ChildProcess | undefined
            let client: SSHAgentProtocolClient | undefined
            let tokenLoaded = false
            const stderr: Buffer[] = []

            try {
                await writeFile(
                    configurationPath,
                    [
                        `directories.tokendir = ${tokenDirectory}`,
                        "objectstore.backend = file",
                        "log.level = ERROR",
                        "slots.removable = false",
                        "",
                    ].join("\n"),
                )
                await mkdir(tokenDirectory, { mode: 0o700 })
                const environment = { ...process.env, SOFTHSM2_CONF: configurationPath }
                await execFileAsync(
                    "softhsm2-util",
                    [
                        "--init-token",
                        "--free",
                        "--label",
                        "modernssh-test",
                        "--so-pin",
                        "12345678",
                        "--pin",
                        pin,
                    ],
                    { env: environment },
                )
                await execFileAsync(
                    "openssl",
                    [
                        "genpkey",
                        "-algorithm",
                        "RSA",
                        "-pkeyopt",
                        "rsa_keygen_bits:2048",
                        "-out",
                        privateKeyPath,
                    ],
                    { env: environment },
                )
                await execFileAsync(
                    "softhsm2-util",
                    [
                        "--import",
                        privateKeyPath,
                        "--token",
                        "modernssh-test",
                        "--label",
                        "modernssh-token-key",
                        "--id",
                        "01",
                        "--pin",
                        pin,
                    ],
                    { env: environment },
                )

                agentProcess = spawn("ssh-agent", ["-D", "-a", socketPath], {
                    env: environment,
                    stdio: ["ignore", "ignore", "pipe"],
                })
                agentProcess.stderr?.on("data", (data: Buffer) => stderr.push(Buffer.from(data)))
                await waitForSocket(socketPath, agentProcess)

                const stream = await new SSHAgent(socketPath).getStream()
                client = new SSHAgentProtocolClient(stream, { requestTimeout: 5_000 })
                expect(await client.getPublicKeys()).toEqual([])

                await client.addToken(provider, pin, {
                    constraints: [{ type: "lifetime", seconds: 60 }],
                })
                tokenLoaded = true

                const identities = await client.getPublicKeys()
                expect(identities).toHaveLength(1)
                const [id, publicKey] = identities[0]
                expect(publicKey.data.alg).toBe("ssh-rsa")
                expect(publicKey.data.comment).toBe("modernssh-token-key")

                const message = Buffer.from("RFC 9987 SoftHSM signing interoperability")
                const signature = await client.sign(id, message, "rsa-sha2-512")
                expect(signature.data.alg).toBe("rsa-sha2-512")
                expect(publicKey.verifySignature(message, signature)).toBe(true)

                await client.removeToken(provider, pin)
                tokenLoaded = false
                expect(await client.getPublicKeys()).toEqual([])
            } finally {
                if (client !== undefined) {
                    if (tokenLoaded) {
                        await client.removeToken(provider, pin).catch((error: unknown) => {
                            if (!(error instanceof SSHAgentProtocolError)) throw error
                        })
                    }
                    client.destroy()
                }
                if (agentProcess !== undefined && agentProcess.exitCode === null) {
                    const closed = once(agentProcess, "close")
                    agentProcess.kill()
                    await closed
                }
                await rm(directory, { recursive: true, force: true })
            }

            expect(Buffer.concat(stderr).toString()).toBe("")
        },
        20_000,
    )
})
