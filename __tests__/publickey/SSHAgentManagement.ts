import { spawn } from "node:child_process"
import { once } from "node:events"
import { access, mkdtemp, rm } from "node:fs/promises"
import { createConnection } from "node:net"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { Duplex } from "node:stream"

import {
    SSHAgentExtensionFailureError,
    SSHAgentProtocolClient,
    SSHAgentProtocolServer,
} from "../../src/publickey/SSHAgentProtocol.js"
import PrivateKey, {
    SSHDSSPrivateKey,
    SSHED25519PrivateKey,
    SSHED448PrivateKey,
    SSHRSAPrivateKey,
} from "../../src/utils/PrivateKey.js"
import { rfc6979DSAParameters } from "../fixtures/DSAParameters.js"

const seed = Buffer.from("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", "hex")
const publicBytes = Buffer.from(
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    "hex",
)
const keyBlob = Buffer.from(
    "0000000b7373682d6564323535313900000020" + publicBytes.toString("hex"),
    "hex",
)
const privateFields =
    "00000020" +
    publicBytes.toString("hex") +
    "00000040" +
    seed.toString("hex") +
    publicBytes.toString("hex")
const addIdentityFrame = Buffer.from(
    "00000083" + "11" + "0000000b7373682d65643235353139" + privateFields + "0000000766697874757265",
    "hex",
)
const addConstrainedIdentityFrame = Buffer.from(
    "0000009f" +
        "19" +
        "0000000b7373682d65643235353139" +
        privateFields +
        "0000000766697874757265" +
        "010000003c02ff0000000f666f6f406578616d706c652e636f6d0102",
    "hex",
)
const addTokenFrame = Buffer.from(
    "00000018" + "1a" + "00000005746f6b656e" + "0000000431323334" + "010000003c02",
    "hex",
)
const removeIdentityFrame = Buffer.from(
    "00000038" + "12" + "00000033" + keyBlob.toString("hex"),
    "hex",
)
const removeAllFrame = Buffer.from("0000000113", "hex")
const removeTokenFrame = Buffer.from("0000000e" + "15" + "00000005746f6b656e" + "00000000", "hex")
const lockFrame = Buffer.from("0000000b1600000006736563726574", "hex")
const unlockFrame = Buffer.from("0000000b1700000006736563726574", "hex")
const extensionFrame = Buffer.from(
    "00000017" + "1b" + "000000106563686f406578616d706c652e636f6d" + "0102",
    "hex",
)
const extensionResponseFrame = Buffer.from(
    "00000017" + "1d" + "000000106563686f406578616d706c652e636f6d" + "0304",
    "hex",
)
const queryFrame = Buffer.from("0000000a1b000000057175657279", "hex")
const queryResponseFrame = Buffer.from(
    "00000030" +
        "1d000000057175657279" +
        "0000000f6f6e65406578616d706c652e636f6d" +
        "0000000f74776f406578616d706c652e636f6d",
    "hex",
)
const successFrame = Buffer.from("0000000106", "hex")

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

function fixedPrivateKey(): PrivateKey {
    const algorithm = new SSHED25519PrivateKey({
        publicKey: publicBytes,
        privateKey: Buffer.concat([seed, publicBytes]),
    })
    return new PrivateKey({
        alg: "ssh-ed25519",
        publicKey: algorithm.getPublicKey(),
        algorithm,
        comment: "fixture",
    })
}

describe("SSH agent management protocol", () => {
    test("client matches fixed RFC 9987 management frames", async () => {
        const [clientStream, fixtureStream] = streamPair()
        const expected = [
            addIdentityFrame,
            addConstrainedIdentityFrame,
            addTokenFrame,
            removeIdentityFrame,
            removeAllFrame,
            removeTokenFrame,
            lockFrame,
            unlockFrame,
            extensionFrame,
            queryFrame,
        ]
        const replies = [
            successFrame,
            successFrame,
            successFrame,
            successFrame,
            successFrame,
            successFrame,
            successFrame,
            successFrame,
            extensionResponseFrame,
            queryResponseFrame,
        ]
        const requests: Buffer[] = []
        const fixture = (async () => {
            const iterator = fixtureStream[Symbol.asyncIterator]()
            for (const reply of replies) {
                const result = await iterator.next()
                if (result.done) throw new Error("Agent client closed before sending every request")
                requests.push(Buffer.from(result.value as Buffer))
                fixtureStream.write(reply)
            }
        })()
        const client = new SSHAgentProtocolClient(clientStream)
        const privateKey = fixedPrivateKey()

        await client.addIdentity(privateKey)
        await client.addIdentity(privateKey, {
            constraints: [
                { type: "lifetime", seconds: 60 },
                { type: "confirm" },
                { type: "extension", name: "foo@example.com", data: Buffer.from([1, 2]) },
            ],
        })
        await client.addToken("token", "1234", {
            constraints: [{ type: "lifetime", seconds: 60 }, { type: "confirm" }],
        })
        await client.removeIdentity(privateKey.data.publicKey)
        await client.removeAllIdentities()
        await client.removeToken("token")
        await client.lock("secret")
        await client.unlock("secret")
        expect(await client.extension("echo@example.com", Buffer.from([1, 2]))).toEqual({
            kind: "response",
            contents: Buffer.from([3, 4]),
        })
        expect(await client.queryExtensions()).toEqual(["one@example.com", "two@example.com"])
        expect(requests).toEqual(expected)

        client.destroy()
        fixtureStream.destroy()
        await fixture
    })

    test("server parses management requests and awaits hooks in wire order", async () => {
        const [clientStream, serverStream] = streamPair()
        const server = new SSHAgentProtocolServer()
        const calls: string[] = []
        let retainedPin: Buffer | undefined

        server.hooker.hook("addIdentity", async (_hook, request, decision) => {
            await Promise.resolve()
            calls.push(
                `add:${request.privateKey.data.alg}:${request.comment}:${request.constraints.length}`,
            )
            expect(request.privateKey.sign(Buffer.alloc(0)).data.data).toHaveLength(64)
            decision.success = true
        })
        server.hooker.hook("addToken", async (_hook, request, decision) => {
            await Promise.resolve()
            calls.push(`token:${request.tokenId.toString()}:${request.pin.toString()}`)
            retainedPin = request.pin
            decision.success = true
        })
        server.hooker.hook("removeIdentity", async (_hook, request, decision) => {
            await Promise.resolve()
            calls.push(`remove:${request.publicKey.data.alg}`)
            decision.success = true
        })
        server.hooker.hook("removeAllIdentities", async (_hook, decision) => {
            await Promise.resolve()
            calls.push("remove-all")
            decision.success = true
        })
        server.hooker.hook("removeToken", async (_hook, request, decision) => {
            await Promise.resolve()
            calls.push(`remove-token:${request.tokenId}`)
            decision.success = true
        })
        server.hooker.hook("extension", async (_hook, request, decision) => {
            await Promise.resolve()
            calls.push(`extension:${request.type}:${request.contents.toString("hex")}`)
            decision.result = { kind: "response", contents: Buffer.from([3, 4]) }
        })
        server.hooker.hook("queryExtensions", async (_hook, decision) => {
            await Promise.resolve()
            calls.push("query")
            decision.extensions = ["one@example.com", "two@example.com"]
        })

        const serving = server.serve(serverStream)
        const client = new SSHAgentProtocolClient(clientStream)
        const privateKey = fixedPrivateKey()
        await client.addIdentity(privateKey, {
            constraints: [{ type: "confirm" }],
        })
        await client.addToken("token", "1234")
        expect(retainedPin).toEqual(Buffer.alloc(4))
        await client.removeIdentity(privateKey.data.publicKey)
        await client.removeAllIdentities()
        await client.removeToken("token")
        await client.extension("echo@example.com", Buffer.from([1, 2]))
        await client.queryExtensions()

        clientStream.end()
        await serving
        expect(calls).toEqual([
            "add:ssh-ed25519:fixture:1",
            "token:token:1234",
            "remove:ssh-ed25519",
            "remove-all",
            "remove-token:token",
            "extension:echo@example.com:0102",
            "query",
        ])
        clientStream.destroy()
        serverStream.destroy()
    })

    test("round-trips every RFC 9987 private-key layout through the server", async () => {
        const keys = [
            fixedPrivateKey(),
            SSHED448PrivateKey.generateSync(),
            PrivateKey.generateSync("ecdsa-sha2-nistp256"),
            PrivateKey.generateSync("ecdsa-sha2-nistp384"),
            PrivateKey.generateSync("ecdsa-sha2-nistp521"),
            SSHRSAPrivateKey.generateSync(1024),
            (() => {
                const algorithm = new SSHDSSPrivateKey(rfc6979DSAParameters)
                return new PrivateKey({
                    alg: "ssh-dss",
                    publicKey: algorithm.getPublicKey(),
                    algorithm,
                })
            })(),
        ]
        const [clientStream, serverStream] = streamPair()
        const server = new SSHAgentProtocolServer()
        const received: PrivateKey[] = []
        server.hooker.hook("addIdentity", async (_hook, request, decision) => {
            await Promise.resolve()
            received.push(request.privateKey)
            decision.success = true
        })
        const serving = server.serve(serverStream)
        const client = new SSHAgentProtocolClient(clientStream)

        for (const key of keys) await client.addIdentity(key)
        expect(received.map((key) => key.data.alg)).toEqual(keys.map((key) => key.data.alg))
        for (let index = 0; index < keys.length; index++) {
            const message = Buffer.from(`agent key layout ${index}`)
            expect(received[index].data.publicKey.equals(keys[index].data.publicKey)).toBeTrue()
            expect(
                received[index].data.publicKey.verifySignature(
                    message,
                    received[index].sign(message),
                ),
            ).toBeTrue()
        }

        clientStream.end()
        await serving
        clientStream.destroy()
        serverStream.destroy()
    }, 15_000)

    test("lock state blocks signatures until the matching passphrase is approved", async () => {
        const [clientStream, serverStream] = streamPair()
        const server = new SSHAgentProtocolServer()
        const privateKey = fixedPrivateKey()
        let signs = 0
        let unlocks = 0
        let retainedPassphrase: Buffer | undefined
        server.hooker.hook("identities", (_hook, decision) => {
            decision.identities = [{ publicKey: privateKey.data.publicKey }]
        })
        server.hooker.hook("sign", (_hook, request, decision) => {
            signs++
            decision.signature = privateKey.sign(request.data, request.algorithm)
        })
        server.hooker.hook("lock", async (_hook, request, decision) => {
            await Promise.resolve()
            retainedPassphrase = request.passphrase
            request.passphrase.fill(0x78)
            decision.success = true
        })
        server.hooker.hook("unlock", async (_hook, _request, decision) => {
            await Promise.resolve()
            unlocks++
            decision.success = true
        })
        const serving = server.serve(serverStream)
        const client = new SSHAgentProtocolClient(clientStream)
        const id = privateKey.data.publicKey.serialize().toString("base64")

        await client.sign(id, Buffer.from("before"))
        await client.lock("secret")
        expect(server.locked).toBeTrue()
        expect(retainedPassphrase).toEqual(Buffer.alloc(6))
        await expect(client.sign(id, Buffer.from("blocked"))).rejects.toThrow("refused")
        await expect(client.unlock("wrong")).rejects.toThrow("refused")
        expect(unlocks).toBe(0)
        await client.unlock("secret")
        expect(server.locked).toBeFalse()
        await client.sign(id, Buffer.from("after"))
        expect(signs).toBe(2)
        expect(unlocks).toBe(1)

        clientStream.end()
        await serving
        clientStream.destroy()
        serverStream.destroy()
    })

    test("orders lock state ahead of later requests on another served stream", async () => {
        const [firstClientStream, firstServerStream] = streamPair()
        const [secondClientStream, secondServerStream] = streamPair()
        const server = new SSHAgentProtocolServer()
        const privateKey = fixedPrivateKey()
        let releaseLock!: () => void
        let reportLockStarted!: () => void
        const lockStarted = new Promise<void>((resolve) => {
            reportLockStarted = resolve
        })
        const lockGate = new Promise<void>((resolve) => {
            releaseLock = resolve
        })
        let signs = 0
        server.hooker.hook("identities", (_hook, decision) => {
            decision.identities = [{ publicKey: privateKey.data.publicKey }]
        })
        server.hooker.hook("sign", (_hook, request, decision) => {
            signs++
            decision.signature = privateKey.sign(request.data, request.algorithm)
        })
        server.hooker.hook("lock", async (_hook, _request, decision) => {
            reportLockStarted()
            await lockGate
            decision.success = true
        })
        const servings = [server.serve(firstServerStream), server.serve(secondServerStream)]
        const firstClient = new SSHAgentProtocolClient(firstClientStream)
        const secondClient = new SSHAgentProtocolClient(secondClientStream)
        const id = privateKey.data.publicKey.serialize().toString("base64")

        const locking = firstClient.lock("secret")
        await lockStarted
        const signing = secondClient.sign(id, Buffer.from("must follow lock"))
        await Promise.resolve()
        releaseLock()
        await locking
        await expect(signing).rejects.toThrow("refused")
        expect(signs).toBe(0)

        firstClientStream.end()
        secondClientStream.end()
        await Promise.all(servings)
        firstClientStream.destroy()
        firstServerStream.destroy()
        secondClientStream.destroy()
        secondServerStream.destroy()
    })

    test("rejects malformed constraints and distinguishes extension failure", async () => {
        const [clientStream, serverStream] = streamPair()
        const server = new SSHAgentProtocolServer()
        let addCalls = 0
        server.hooker.hook("addIdentity", (_hook, _request, decision) => {
            addCalls++
            decision.success = true
        })
        server.hooker.hook("extension", (_hook, _request, decision) => {
            decision.result = { kind: "failure" }
        })
        const serving = server.serve(serverStream)
        const client = new SSHAgentProtocolClient(clientStream)

        await expect(client.extension("fail@example.com")).rejects.toBeInstanceOf(
            SSHAgentExtensionFailureError,
        )
        await expect(
            client.addIdentity(fixedPrivateKey(), {
                constraints: [
                    { type: "extension", name: "final@example.com", data: Buffer.alloc(0) },
                    { type: "confirm" },
                ],
            }),
        ).rejects.toThrow("final constraint")
        await expect(
            client.addIdentity(fixedPrivateKey(), {
                constraints: [{ type: "extension", name: "", data: Buffer.alloc(0) }],
            }),
        ).rejects.toThrow("must not be empty")

        clientStream.end()
        await serving
        clientStream.destroy()
        serverStream.destroy()

        const [malformedClient, malformedServerStream] = streamPair()
        const malformedServer = new SSHAgentProtocolServer()
        malformedServer.hooker.hook("addIdentity", (_hook, _request, decision) => {
            addCalls++
            decision.success = true
        })
        const malformedServing = malformedServer.serve(malformedServerStream)
        const malformed = Buffer.from(addConstrainedIdentityFrame)
        malformed[malformed.length - 28] = 3
        malformedClient.write(malformed)
        const iterator = malformedClient[Symbol.asyncIterator]()
        const response = await iterator.next()
        expect(response.value).toEqual(Buffer.from("0000000105", "hex"))
        expect(addCalls).toBe(0)

        malformedClient.end()
        await malformedServing
        malformedClient.destroy()
        malformedServerStream.destroy()
    })

    test("adds, locks, unlocks, signs, and removes through a real OpenSSH agent", async () => {
        const directory = await mkdtemp(join(tmpdir(), "modernssh-agent-management-"))
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
            const privateKeys = [
                fixedPrivateKey(),
                PrivateKey.generateSync("ecdsa-sha2-nistp256"),
                SSHRSAPrivateKey.generateSync(1024),
            ]
            for (let index = 0; index < privateKeys.length; index++) {
                await client.addIdentity(privateKeys[index], {
                    comment: `management-test-${index}`,
                })
            }
            const identities = await client.getPublicKeys()
            expect(identities).toHaveLength(privateKeys.length)
            const message = Buffer.from("real agent management")
            for (let index = 0; index < privateKeys.length; index++) {
                const identity = identities.find(
                    ([, publicKey]) => publicKey.data.comment === `management-test-${index}`,
                )
                expect(identity).toBeDefined()
                expect(
                    identity![1].verifySignature(message, await client.sign(identity![0], message)),
                ).toBeTrue()
            }
            await client.lock("secret")
            await expect(client.sign(identities[0][0], message)).rejects.toThrow()
            await expect(client.unlock("wrong")).rejects.toThrow("refused")
            await client.unlock("secret")
            for (const [, publicKey] of identities) await client.removeIdentity(publicKey)
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
