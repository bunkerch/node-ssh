import { execFile, spawn } from "node:child_process"
import { once } from "node:events"
import { access, mkdtemp, rm } from "node:fs/promises"
import { createServer, type Socket } from "node:net"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { promisify } from "node:util"
import Client from "../../src/Client.js"
import { createSocketAgent } from "../../src/publickey/SocketAgent.js"
import SSHAgent from "../../src/publickey/SSHAgent.js"

const execFileAsync = promisify(execFile)
const requestIdentities = Buffer.from("000000010b", "hex")
const identitiesAnswer = Buffer.from(
    "000000470c00000001000000330000000b7373682d6564323535313900000020" +
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
        "0000000766697874757265",
    "hex",
)
const signRequest = Buffer.from(
    "000000430d000000330000000b7373682d6564323535313900000020" +
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
        "0000000361626300000000",
    "hex",
)
const signAnswer = Buffer.from(
    "000000580e000000530000000b7373682d6564323535313900000040" +
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f" +
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf",
    "hex",
)

async function writeFragmented(socket: Socket, response: Buffer): Promise<void> {
    socket.write(response.subarray(0, 2))
    await new Promise<void>((resolve) => setTimeout(resolve, 1))
    socket.write(response.subarray(2, 9))
    await new Promise<void>((resolve) => setTimeout(resolve, 1))
    socket.end(response.subarray(9))
}

describe("SSHAgent", () => {
    test("rejects invalid explicit socket paths during construction", () => {
        for (const socketPath of ["", "agent\0socket", 42, null] as unknown[]) {
            expect(() => new SSHAgent(socketPath as string)).toThrow(
                "SSH agent socket path must be a non-empty string without NUL bytes",
            )
        }
    })

    test("validates and snapshots socket timeout options", () => {
        const options = { timeout: 25 }
        const agent = new SSHAgent("/tmp/modernssh-agent", options)
        options.timeout = 50

        expect(agent.options).toEqual({ timeout: 25 })
        expect(Object.isFrozen(agent.options)).toBe(true)
        expect(new SSHAgent("/tmp/modernssh-agent").options.timeout).toBe(10_000)
        expect(new SSHAgent("/tmp/modernssh-agent", { timeout: 0 }).options.timeout).toBe(0)

        for (const timeout of [-1, 1.5, Number.NaN, 0x8000_0000]) {
            expect(() => new SSHAgent("/tmp/modernssh-agent", { timeout })).toThrow(
                "SSH agent timeout must be an integer between zero and 2147483647",
            )
        }
        expect(() => new SSHAgent("/tmp/modernssh-agent", null as never)).toThrow(
            "SSH agent options must be an object",
        )
    })

    test("bounds an idle agent request and closes its socket", async () => {
        const directory = await mkdtemp(join(tmpdir(), "modernssh-agent-timeout-"))
        const socketPath = join(directory, "agent.sock")
        let reportClosed!: () => void
        const closed = new Promise<void>((resolve) => {
            reportClosed = resolve
        })
        const server = createServer((socket) => {
            socket.once("close", reportClosed)
        })
        server.listen(socketPath)
        await once(server, "listening")

        try {
            const agent = new SSHAgent(socketPath, { timeout: 25 })
            await expect(agent.getPublicKeys()).rejects.toThrow("SSH agent request timed out")
            await closed
        } finally {
            await new Promise<void>((resolve, reject) => {
                server.close((error) => (error ? reject(error) : resolve()))
            })
            await rm(directory, { recursive: true, force: true })
        }
    })

    test("defers path availability to connection time and accepts named pipes", async () => {
        const directory = await mkdtemp(join(tmpdir(), "modernssh-late-agent-"))
        const socketPath = join(directory, "agent.sock")
        const agent = new SSHAgent(socketPath, { timeout: 25 })
        const server = createServer()
        expect(agent.socketPath).toBe(socketPath)
        expect(createSocketAgent(socketPath)).toBeInstanceOf(SSHAgent)
        expect(new SSHAgent("\\\\.\\pipe\\modernssh-agent").socketPath).toBe(
            "\\\\.\\pipe\\modernssh-agent",
        )

        try {
            server.listen(socketPath)
            await new Promise<void>((resolve) => server.once("listening", resolve))
            const socket = await agent.getStream()
            await new Promise<void>((resolve) => setTimeout(resolve, 50))
            expect(socket.destroyed).toBe(false)
            socket.destroy()
        } finally {
            await new Promise<void>((resolve, reject) => {
                server.close((error) => (error ? reject(error) : resolve()))
            })
            await rm(directory, { recursive: true, force: true })
        }
    })

    test("uses fixed RFC 9987 identity and signing packets across fragmented reads", async () => {
        const directory = await mkdtemp(join(tmpdir(), "modernssh-agent-vector-"))
        const socketPath = join(directory, "agent.sock")
        const requests: Buffer[] = []
        const server = createServer((socket) => {
            let raw = Buffer.alloc(0)
            socket.on("data", (data: Buffer) => {
                raw = Buffer.concat([raw, data])
                if (raw.length < 4 || raw.length < raw.readUInt32BE(0) + 4) return
                requests.push(raw)
                const response = raw.equals(requestIdentities)
                    ? identitiesAnswer
                    : raw.equals(signRequest)
                      ? signAnswer
                      : Buffer.from("0000000105", "hex")
                void writeFragmented(socket, response)
            })
        })
        server.listen(socketPath)
        await new Promise<void>((resolve) => server.once("listening", resolve))

        try {
            const agent = createSocketAgent(socketPath)
            const client = new Client({ username: "test", agent })
            expect(agent).toBeInstanceOf(SSHAgent)
            expect((agent as SSHAgent).socketPath).toBe(socketPath)
            expect("options" in client).toBe(false)
            const identities = await agent.getPublicKeys()
            expect(identities).toHaveLength(1)
            const [id, publicKey] = identities[0]
            expect(publicKey.data.alg).toBe("ssh-ed25519")
            expect(publicKey.data.comment).toBe("fixture")
            expect((await agent.getPublicKey(id)).equals(publicKey)).toBe(true)

            const signature = await agent.sign(id, Buffer.from("abc"))
            expect(signature.data.alg).toBe("ssh-ed25519")
            expect(signature.data.data).toEqual(Buffer.from(signAnswer.subarray(-64)))
            expect(requests).toEqual([
                requestIdentities,
                requestIdentities,
                requestIdentities,
                signRequest,
            ])
        } finally {
            await new Promise<void>((resolve, reject) => {
                server.close((error) => (error ? reject(error) : resolve()))
            })
            await rm(directory, { recursive: true, force: true })
        }
    })

    test("owns signing data before the asynchronous identity lookup", async () => {
        const directory = await mkdtemp(join(tmpdir(), "modernssh-agent-sign-ownership-"))
        const socketPath = join(directory, "agent.sock")
        const keyLength = signRequest.readUInt32BE(5)
        const id = signRequest.subarray(9, 9 + keyLength).toString("base64")
        let releaseIdentity!: () => void
        const identityReleased = new Promise<void>((resolve) => {
            releaseIdentity = resolve
        })
        let reportIdentity!: () => void
        const identityReceived = new Promise<void>((resolve) => {
            reportIdentity = resolve
        })
        let receivedSignRequest: Buffer | undefined
        const server = createServer((socket) => {
            socket.once("data", (request) => {
                if (request.equals(requestIdentities)) {
                    reportIdentity()
                    void identityReleased
                        .then(() => writeFragmented(socket, identitiesAnswer))
                        .catch((error: unknown) =>
                            socket.destroy(
                                error instanceof Error ? error : new Error(String(error)),
                            ),
                        )
                    return
                }
                receivedSignRequest = Buffer.from(request)
                void writeFragmented(socket, signAnswer).catch((error: unknown) =>
                    socket.destroy(error instanceof Error ? error : new Error(String(error))),
                )
            })
        })
        server.listen(socketPath)
        await once(server, "listening")

        try {
            const data = Buffer.from("abc")
            const signing = new SSHAgent(socketPath).sign(id, data)
            await identityReceived
            data.fill(0x7a)
            releaseIdentity()
            await signing

            expect(receivedSignRequest).toEqual(signRequest)
        } finally {
            releaseIdentity()
            await new Promise<void>((resolve, reject) => {
                server.close((error) => (error ? reject(error) : resolve()))
            })
            await rm(directory, { recursive: true, force: true })
        }
    })

    test("rejects a malformed UTF-8 identity comment", async () => {
        const directory = await mkdtemp(join(tmpdir(), "modernssh-agent-utf8-"))
        const socketPath = join(directory, "agent.sock")
        const malformed = Buffer.from(identitiesAnswer)
        malformed[malformed.length - 1] = 0xff
        const server = createServer((socket) => {
            socket.once("data", () => socket.end(malformed))
        })
        server.listen(socketPath)
        await new Promise<void>((resolve) => server.once("listening", resolve))

        try {
            await expect(new SSHAgent(socketPath).getPublicKeys()).rejects.toThrow(
                "invalid identities response",
            )
        } finally {
            await new Promise<void>((resolve, reject) => {
                server.close((error) => (error ? reject(error) : resolve()))
            })
            await rm(directory, { recursive: true, force: true })
        }
    })

    test("rejects trailing fields in a generic failure response", async () => {
        const directory = await mkdtemp(join(tmpdir(), "modernssh-agent-failure-"))
        const socketPath = join(directory, "agent.sock")
        const server = createServer((socket) => {
            socket.once("data", () => socket.end(Buffer.from("000000020500", "hex")))
        })
        server.listen(socketPath)
        await new Promise<void>((resolve) => server.once("listening", resolve))

        try {
            await expect(new SSHAgent(socketPath).getPublicKeys()).rejects.toThrow(
                "malformed failure response",
            )
        } finally {
            await new Promise<void>((resolve, reject) => {
                server.close((error) => (error ? reject(error) : resolve()))
            })
            await rm(directory, { recursive: true, force: true })
        }
    })

    test("rejects response bytes beyond the absolute frame bound", async () => {
        const directory = await mkdtemp(join(tmpdir(), "modernssh-agent-overflow-"))
        const socketPath = join(directory, "agent.sock")
        let reportClosed!: () => void
        const closed = new Promise<void>((resolve) => {
            reportClosed = resolve
        })
        const maximumLength = 256 * 1024
        const oversized = Buffer.alloc(maximumLength + 5)
        oversized.writeUInt32BE(maximumLength, 0)
        oversized[4] = 12
        const server = createServer((socket) => {
            socket.once("close", reportClosed)
            socket.once("data", () => socket.end(oversized))
        })
        server.listen(socketPath)
        await once(server, "listening")

        try {
            await expect(new SSHAgent(socketPath).getPublicKeys()).rejects.toThrow(
                "response exceeds the configured limit",
            )
            await closed
        } finally {
            await new Promise<void>((resolve, reject) => {
                server.close((error) => (error ? reject(error) : resolve()))
            })
            await rm(directory, { recursive: true, force: true })
        }
    })

    test("lists and signs with a real OpenSSH agent", async () => {
        const directory = await mkdtemp(join(tmpdir(), "modernssh-openssh-agent-"))
        const socketPath = join(directory, "agent.sock")
        const keyPath = join(directory, "id_rsa")
        const caPath = join(directory, "ca")
        const process = spawn("ssh-agent", ["-D", "-a", socketPath], { stdio: "ignore" })

        try {
            for (let attempt = 0; attempt < 100; attempt++) {
                try {
                    await access(socketPath)
                    break
                } catch {
                    await new Promise<void>((resolve) => setTimeout(resolve, 20))
                }
            }
            await access(socketPath)
            await execFileAsync("ssh-keygen", [
                "-q",
                "-t",
                "rsa",
                "-b",
                "2048",
                "-N",
                "",
                "-C",
                "modernssh-agent-test",
                "-f",
                keyPath,
            ])
            await execFileAsync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", caPath])
            await execFileAsync("ssh-keygen", [
                "-q",
                "-s",
                caPath,
                "-I",
                "agent-certificate",
                "-n",
                "agent-user",
                "-V",
                "-1m:+1h",
                keyPath + ".pub",
            ])
            await execFileAsync("ssh-add", [keyPath], {
                env: { ...globalThis.process.env, SSH_AUTH_SOCK: socketPath },
            })

            const agent = new SSHAgent(socketPath)
            const identities = await agent.getPublicKeys()
            const plainIdentity = identities.find(([, key]) => key.data.alg === "ssh-rsa")
            const certificateIdentity = identities.find(([, key]) =>
                key.data.alg.endsWith("-cert-v01@openssh.com"),
            )
            expect(plainIdentity?.[1].data.comment).toBe("modernssh-agent-test")
            expect(certificateIdentity?.[1].data.comment).toBe("modernssh-agent-test")
            const data = Buffer.from("signed through the OpenSSH agent")
            for (const algorithm of ["rsa-sha2-256", "rsa-sha2-512"] as const) {
                const signature = await agent.sign(plainIdentity![0], data, algorithm)
                expect(signature.data.alg).toBe(algorithm)
                expect(plainIdentity![1].verifySignature(data, signature)).toBe(true)
            }
            const certificateSignature = await agent.sign(
                certificateIdentity![0],
                data,
                "rsa-sha2-512-cert-v01@openssh.com",
            )
            expect(certificateSignature.data.alg).toBe("rsa-sha2-512")
            expect(certificateIdentity![1].verifySignature(data, certificateSignature)).toBe(true)
        } finally {
            process.kill("SIGTERM")
            await new Promise<void>((resolve) => {
                if (process.exitCode !== null || process.signalCode !== null) resolve()
                else process.once("close", () => resolve())
            })
            await rm(directory, { recursive: true, force: true })
        }
    }, 15_000)
})
