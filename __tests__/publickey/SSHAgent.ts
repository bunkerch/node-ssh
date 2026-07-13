import { execFile, spawn } from "node:child_process"
import { access, mkdtemp, rm } from "node:fs/promises"
import { createServer, type Socket } from "node:net"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { promisify } from "node:util"
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
            const agent = new SSHAgent(socketPath)
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

    test("lists and signs with a real OpenSSH agent", async () => {
        const directory = await mkdtemp(join(tmpdir(), "modernssh-openssh-agent-"))
        const socketPath = join(directory, "agent.sock")
        const keyPath = join(directory, "id_ed25519")
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
                "ed25519",
                "-N",
                "",
                "-C",
                "modernssh-agent-test",
                "-f",
                keyPath,
            ])
            await execFileAsync("ssh-add", [keyPath], {
                env: { ...globalThis.process.env, SSH_AUTH_SOCK: socketPath },
            })

            const agent = new SSHAgent(socketPath)
            const identities = await agent.getPublicKeys()
            expect(identities).toHaveLength(1)
            expect(identities[0][1].data.comment).toBe("modernssh-agent-test")
            const data = Buffer.from("signed through the OpenSSH agent")
            const signature = await agent.sign(identities[0][0], data)
            expect(identities[0][1].verifySignature(data, signature)).toBe(true)
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
