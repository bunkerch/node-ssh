import { spawn } from "node:child_process"
import { once } from "node:events"
import { access, mkdtemp, rm } from "node:fs/promises"
import { createConnection } from "node:net"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { Duplex } from "node:stream"
import {
    SSHAgentProtocolClient,
    SSHAgentProtocolServer,
    type SSHAgentConstraint,
} from "../../src/publickey/SSHAgentProtocol.js"
import PrivateKey, { SSHED25519SecurityKeyPrivateKey } from "../../src/utils/PrivateKey.js"

const publicKey = Buffer.from(
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    "hex",
)
const providerAddFrame = Buffer.from(
    "000000a0" +
        "19" +
        "0000001a736b2d7373682d65643235353139406f70656e7373682e636f6d" +
        "00000020d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a" +
        "000000087373683a74657374" +
        "01" +
        "000000080102030405060708" +
        "00000000" +
        "0000001473656375726974792d6b65792066697874757265" +
        "ff" +
        "00000017736b2d70726f7669646572406f70656e7373682e636f6d" +
        "00000008696e7465726e616c",
    "hex",
)
const successFrame = Buffer.from("0000000106", "hex")
const ordinaryProviderFrame = Buffer.from(
    "000000ab" +
        "19" +
        "0000000b7373682d65643235353139" +
        "00000020d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a" +
        "000000409d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60" +
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a" +
        "0000000766697874757265" +
        "ff00000017736b2d70726f7669646572406f70656e7373682e636f6d" +
        "00000008696e7465726e616c",
    "hex",
)
const failureFrame = Buffer.from("0000000105", "hex")

function streamPair(): [Duplex, Duplex] {
    class MemoryDuplex extends Duplex {
        peer!: MemoryDuplex

        _read(): void {
            // The peer drives readable data through push().
        }

        _write(
            chunk: Buffer,
            _encoding: BufferEncoding,
            callback: (error?: Error | null) => void,
        ): void {
            this.peer.push(Buffer.from(chunk))
            callback()
        }

        _final(callback: (error?: Error | null) => void): void {
            this.peer.push(null)
            callback()
        }
    }
    const left = new MemoryDuplex()
    const right = new MemoryDuplex()
    left.peer = right
    right.peer = left
    return [left, right]
}

function securityKey(): PrivateKey {
    const algorithm = new SSHED25519SecurityKeyPrivateKey({
        publicKey,
        application: "ssh:test",
        flags: 1,
        keyHandle: Buffer.from("0102030405060708", "hex"),
        reserved: Buffer.alloc(0),
    })
    return new PrivateKey({
        alg: SSHED25519SecurityKeyPrivateKey.alg_name,
        publicKey: algorithm.getPublicKey(),
        algorithm,
        comment: "security-key fixture",
    })
}

describe("security-key agent identities", () => {
    test("client writes the fixed provider-constrained identity frame", async () => {
        const [clientStream, fixtureStream] = streamPair()
        const fixture = (async () => {
            const result = await fixtureStream[Symbol.asyncIterator]().next()
            if (result.done) throw new Error("Agent client closed before its request")
            expect(Buffer.from(result.value as Buffer)).toEqual(providerAddFrame)
            fixtureStream.write(successFrame)
        })()
        const client = new SSHAgentProtocolClient(clientStream)
        const constraint: SSHAgentConstraint = {
            type: "openssh-security-key-provider",
            provider: "internal",
        }

        await client.addIdentity(securityKey(), { constraints: [constraint] })
        await fixture
        client.destroy()
        fixtureStream.destroy()
    })

    test("server parses the fixed provider constraint through its awaited hook", async () => {
        const [fixtureStream, serverStream] = streamPair()
        const server = new SSHAgentProtocolServer()
        let calls = 0
        server.hooker.hook("addIdentity", async (_hook, request, decision) => {
            await Promise.resolve()
            calls++
            expect(
                request.privateKey.data.publicKey.equals(securityKey().data.publicKey),
            ).toBeTrue()
            expect(request.constraints).toEqual([
                {
                    type: "openssh-security-key-provider",
                    provider: "internal",
                },
            ])
            decision.success = true
        })
        const serving = server.serve(serverStream)
        const response = (async () => {
            const result = await fixtureStream[Symbol.asyncIterator]().next()
            if (result.done) throw new Error("Agent server closed before its response")
            return Buffer.from(result.value as Buffer)
        })()

        fixtureStream.write(providerAddFrame)
        expect(await response).toEqual(successFrame)
        expect(calls).toBe(1)
        fixtureStream.end()
        await serving
        fixtureStream.destroy()
        serverStream.destroy()
    })

    test("server rejects a provider constraint on an ordinary identity before policy", async () => {
        const [fixtureStream, serverStream] = streamPair()
        const server = new SSHAgentProtocolServer()
        let calls = 0
        server.hooker.hook("addIdentity", (_hook, _request, decision) => {
            calls++
            decision.success = true
        })
        const serving = server.serve(serverStream)
        const response = (async () => {
            const result = await fixtureStream[Symbol.asyncIterator]().next()
            if (result.done) throw new Error("Agent server closed before its response")
            return Buffer.from(result.value as Buffer)
        })()

        fixtureStream.write(ordinaryProviderFrame)
        expect(await response).toEqual(failureFrame)
        expect(calls).toBe(0)
        fixtureStream.end()
        await serving
        fixtureStream.destroy()
        serverStream.destroy()
    })

    test("client validates provider constraint ownership and encoding", async () => {
        const [clientStream, fixtureStream] = streamPair()
        const client = new SSHAgentProtocolClient(clientStream)
        const provider = {
            type: "openssh-security-key-provider" as const,
            provider: "internal",
        }

        await expect(client.addIdentity(securityKey())).rejects.toThrow(
            "require one provider constraint",
        )
        await expect(
            client.addIdentity(PrivateKey.generateSync("ssh-ed25519"), {
                constraints: [provider],
            }),
        ).rejects.toThrow("require a security-key identity")
        await expect(
            client.addToken("provider", Buffer.alloc(0), { constraints: [provider] }),
        ).rejects.toThrow("require an identity")
        await expect(
            client.addIdentity(securityKey(), {
                constraints: [{ ...provider, provider: "" }],
            }),
        ).rejects.toThrow("must be non-empty")
        await expect(
            client.addIdentity(securityKey(), {
                constraints: [{ ...provider, provider: "bad\0provider" }],
            }),
        ).rejects.toThrow("without NUL")
        await expect(
            client.addIdentity(securityKey(), {
                constraints: [
                    {
                        type: "extension",
                        name: "sk-provider@openssh.com",
                        data: Buffer.alloc(0),
                    },
                ],
            }),
        ).rejects.toThrow("typed representation")
        await expect(
            client.addIdentity(securityKey(), { constraints: [provider, provider] }),
        ).rejects.toThrow("duplicate")

        client.destroy()
        fixtureStream.destroy()
    })

    test("keeps a following constraint parseable after the provider path", async () => {
        const [clientStream, serverStream] = streamPair()
        const server = new SSHAgentProtocolServer()
        server.hooker.hook("addIdentity", async (_hook, request, decision) => {
            await Promise.resolve()
            expect(request.constraints).toEqual([
                { type: "openssh-security-key-provider", provider: "internal" },
                { type: "confirm" },
            ])
            decision.success = true
        })
        const serving = server.serve(serverStream)
        const client = new SSHAgentProtocolClient(clientStream)
        await client.addIdentity(securityKey(), {
            constraints: [
                { type: "openssh-security-key-provider", provider: "internal" },
                { type: "confirm" },
            ],
        })

        clientStream.end()
        await serving
        clientStream.destroy()
        serverStream.destroy()
    })

    test("adds and lists a provider-constrained identity through the system agent", async () => {
        const directory = await mkdtemp(join(tmpdir(), "modernssh-security-key-agent-"))
        const socketPath = join(directory, "agent.sock")
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
            const socket = createConnection(socketPath)
            await once(socket, "connect")
            const client = new SSHAgentProtocolClient(socket)
            const identity = securityKey()
            await client.addIdentity(identity, {
                constraints: [
                    {
                        type: "openssh-security-key-provider",
                        provider: "internal",
                    },
                ],
            })

            const identities = await client.getPublicKeys()
            expect(identities).toHaveLength(1)
            expect(identities[0][1].equals(identity.data.publicKey)).toBeTrue()
            expect(identities[0][1].data.comment).toBe("security-key fixture")
            await client.removeIdentity(identity.data.publicKey)
            expect(await client.getPublicKeys()).toHaveLength(0)
            client.destroy()
        } finally {
            process.kill("SIGTERM")
            if (process.exitCode === null && process.signalCode === null) {
                await once(process, "close")
            }
            await rm(directory, { recursive: true, force: true })
        }
    }, 15_000)
})
