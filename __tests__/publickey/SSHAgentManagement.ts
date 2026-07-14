import { execFile, spawn } from "node:child_process"
import { once } from "node:events"
import { access, mkdtemp, readFile, rm } from "node:fs/promises"
import { createConnection } from "node:net"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { Duplex } from "node:stream"
import { promisify } from "node:util"

import {
    OPENSSH_AGENT_SESSION_BIND,
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
import PublicKey from "../../src/utils/PublicKey.js"
import EncodedSignature from "../../src/utils/Signature.js"
import { rfc6979DSAParameters } from "../fixtures/DSAParameters.js"

const execFileAsync = promisify(execFile)

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
const destinationConstraint = Buffer.from(
    "ff0000002472657374726963742d64657374696e6174696f6e2d763030406f70656e7373682e636f6d" +
        "000000730000006f0000000c000000000000000000000000" +
        "0000005700000005616c6963650000000e7461726765742e6578616d706c65" +
        "0000000000000033" +
        keyBlob.toString("hex") +
        "0000000000",
    "hex",
)
const destinationAddFrame = Buffer.from(
    "00000123" +
        "19" +
        "0000000b7373682d65643235353139" +
        privateFields +
        "0000000766697874757265" +
        destinationConstraint.toString("hex"),
    "hex",
)
const sessionIdentifier = Buffer.alloc(32, 0x42)
const sessionSignature = Buffer.from(
    "0000000b7373682d6564323535313900000040" +
        "ddf3b5189c51feb459b936620288eb6c9b69ea64e9759d0f0f8b089f912d4" +
        "4839265cab067922b1ded4507883bfb3b914a6a06b3632e700c72062ba9f412000a",
    "hex",
)
const sessionBindFrame = Buffer.from(
    "000000d0" +
        "1b0000001873657373696f6e2d62696e64406f70656e7373682e636f6d" +
        "00000033" +
        keyBlob.toString("hex") +
        "00000020" +
        sessionIdentifier.toString("hex") +
        "00000053" +
        sessionSignature.toString("hex") +
        "01",
    "hex",
)

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
            destinationAddFrame,
            sessionBindFrame,
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
            successFrame,
            successFrame,
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
        await client.addIdentity(privateKey, {
            constraints: [
                {
                    type: "openssh-restrict-destination",
                    destinations: [
                        {
                            to: {
                                username: "alice",
                                hostname: "target.example",
                                hostKeys: [{ publicKey: privateKey.data.publicKey }],
                            },
                        },
                    ],
                },
            ],
        })
        await client.opensshSessionBind({
            hostKey: privateKey.data.publicKey,
            sessionIdentifier,
            signature: privateKey.sign(sessionIdentifier),
            forwarding: true,
        })
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
        let destinationHostname: string | undefined

        server.hooker.hook("addIdentity", async (_hook, request, decision) => {
            await Promise.resolve()
            calls.push(
                `add:${request.privateKey.data.alg}:${request.comment}:${request.constraints.length}`,
            )
            const destination = request.constraints.find(
                (constraint) => constraint.type === "openssh-restrict-destination",
            )
            if (destination?.type === "openssh-restrict-destination") {
                destinationHostname = destination.destinations[0].to.hostname
            }
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
            constraints: [
                {
                    type: "openssh-restrict-destination",
                    destinations: [
                        {
                            to: {
                                hostname: "target.example",
                                hostKeys: [{ publicKey: privateKey.data.publicKey }],
                            },
                        },
                    ],
                },
                { type: "confirm" },
            ],
        })
        expect(destinationHostname).toBe("target.example")
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
            "add:ssh-ed25519:fixture:2",
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

    test("server does not retain add-identity approval after a later policy failure", async () => {
        const [clientStream, serverStream] = streamPair()
        const server = new SSHAgentProtocolServer()
        const hookErrors: Error[] = []
        server.hooker.on("uncaughtException", (_event, error) => hookErrors.push(error))
        server.hooker.hook("addIdentity", (_hook, _request, decision) => {
            decision.success = true
        })
        server.hooker.hook("addIdentity", async () => {
            await Promise.resolve()
            throw new Error("identity storage backend failed")
        })
        const serving = server.serve(serverStream)
        const client = new SSHAgentProtocolClient(clientStream)

        await expect(client.addIdentity(fixedPrivateKey())).rejects.toThrow("refused")
        expect(hookErrors.map((error) => error.message)).toEqual([
            "identity storage backend failed",
        ])

        clientStream.end()
        await serving
        client.destroy()
        serverStream.destroy()
    })

    test("server does not retain add-token approval after a later policy failure", async () => {
        const [clientStream, serverStream] = streamPair()
        const server = new SSHAgentProtocolServer()
        const hookErrors: Error[] = []
        server.hooker.on("uncaughtException", (_event, error) => hookErrors.push(error))
        server.hooker.hook("addToken", (_hook, _request, decision) => {
            decision.success = true
        })
        server.hooker.hook("addToken", async () => {
            await Promise.resolve()
            throw new Error("token storage backend failed")
        })
        const serving = server.serve(serverStream)
        const client = new SSHAgentProtocolClient(clientStream)

        await expect(client.addToken("provider", "1234")).rejects.toThrow("refused")
        expect(hookErrors.map((error) => error.message)).toEqual(["token storage backend failed"])

        clientStream.end()
        await serving
        client.destroy()
        serverStream.destroy()
    })

    test("server does not retain remove-identity approval after a later policy failure", async () => {
        const [clientStream, serverStream] = streamPair()
        const server = new SSHAgentProtocolServer()
        const hookErrors: Error[] = []
        server.hooker.on("uncaughtException", (_event, error) => hookErrors.push(error))
        server.hooker.hook("removeIdentity", (_hook, _request, decision) => {
            decision.success = true
        })
        server.hooker.hook("removeIdentity", async () => {
            await Promise.resolve()
            throw new Error("identity removal backend failed")
        })
        const serving = server.serve(serverStream)
        const client = new SSHAgentProtocolClient(clientStream)

        await expect(client.removeIdentity(fixedPrivateKey().data.publicKey)).rejects.toThrow(
            "refused",
        )
        expect(hookErrors.map((error) => error.message)).toEqual([
            "identity removal backend failed",
        ])

        clientStream.end()
        await serving
        client.destroy()
        serverStream.destroy()
    })

    test("server does not retain remove-all approval after a later policy failure", async () => {
        const [clientStream, serverStream] = streamPair()
        const server = new SSHAgentProtocolServer()
        const hookErrors: Error[] = []
        server.hooker.on("uncaughtException", (_event, error) => hookErrors.push(error))
        server.hooker.hook("removeAllIdentities", (_hook, decision) => {
            decision.success = true
        })
        server.hooker.hook("removeAllIdentities", async () => {
            await Promise.resolve()
            throw new Error("bulk identity removal backend failed")
        })
        const serving = server.serve(serverStream)
        const client = new SSHAgentProtocolClient(clientStream)

        await expect(client.removeAllIdentities()).rejects.toThrow("refused")
        expect(hookErrors.map((error) => error.message)).toEqual([
            "bulk identity removal backend failed",
        ])

        clientStream.end()
        await serving
        client.destroy()
        serverStream.destroy()
    })

    test("server does not retain remove-token approval after a later policy failure", async () => {
        const [clientStream, serverStream] = streamPair()
        const server = new SSHAgentProtocolServer()
        const hookErrors: Error[] = []
        server.hooker.on("uncaughtException", (_event, error) => hookErrors.push(error))
        server.hooker.hook("removeToken", (_hook, _request, decision) => {
            decision.success = true
        })
        server.hooker.hook("removeToken", async () => {
            await Promise.resolve()
            throw new Error("token removal backend failed")
        })
        const serving = server.serve(serverStream)
        const client = new SSHAgentProtocolClient(clientStream)

        await expect(client.removeToken("provider", "1234")).rejects.toThrow("refused")
        expect(hookErrors.map((error) => error.message)).toEqual(["token removal backend failed"])

        clientStream.end()
        await serving
        client.destroy()
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

    test("validates and records OpenSSH session bindings per served connection", async () => {
        const [clientStream, serverStream] = streamPair()
        const server = new SSHAgentProtocolServer()
        const privateKey = fixedPrivateKey()
        const priorBindingCounts: number[] = []
        let observedBindings = 0
        let observedAttempt = false
        let retainedFirstByte = 0
        server.hooker.hook("sessionBind", async (_hook, binding, decision, connection) => {
            await Promise.resolve()
            expect(binding.hostKey.equals(privateKey.data.publicKey)).toBeTrue()
            expect(
                binding.hostKey.verifySignature(binding.sessionIdentifier, binding.signature),
            ).toBeTrue()
            priorBindingCounts.push(connection.sessionBindings.length)
            decision.success = true
        })
        server.hooker.hook("identities", (_hook, decision, connection) => {
            observedBindings = connection.sessionBindings.length
            observedAttempt = connection.sessionBindAttempted
            connection.sessionBindings[0].sessionIdentifier.fill(0)
            retainedFirstByte = connection.sessionBindings[0].sessionIdentifier[0]
            decision.identities = []
        })
        const serving = server.serve(serverStream)
        const client = new SSHAgentProtocolClient(clientStream)
        const forwardedIdentifier = Buffer.alloc(32, 0x41)
        const authenticationIdentifier = Buffer.alloc(32, 0x42)

        expect(await client.queryExtensions()).toEqual([OPENSSH_AGENT_SESSION_BIND])
        await expect(client.extension(OPENSSH_AGENT_SESSION_BIND)).rejects.toBeInstanceOf(
            SSHAgentExtensionFailureError,
        )
        await client.opensshSessionBind({
            hostKey: privateKey.data.publicKey,
            sessionIdentifier: forwardedIdentifier,
            signature: privateKey.sign(forwardedIdentifier),
            forwarding: true,
        })
        await expect(
            client.opensshSessionBind({
                hostKey: privateKey.data.publicKey,
                sessionIdentifier: forwardedIdentifier,
                signature: privateKey.sign(forwardedIdentifier),
                forwarding: true,
            }),
        ).rejects.toBeInstanceOf(SSHAgentExtensionFailureError)
        await client.opensshSessionBind({
            hostKey: privateKey.data.publicKey,
            sessionIdentifier: authenticationIdentifier,
            signature: privateKey.sign(authenticationIdentifier),
            forwarding: false,
        })
        await client.getPublicKeys()
        expect(observedBindings).toBe(2)
        expect(observedAttempt).toBeTrue()
        expect(retainedFirstByte).toBe(0x41)
        expect(priorBindingCounts).toEqual([0, 1])

        const laterIdentifier = Buffer.alloc(32, 0x43)
        await expect(
            client.opensshSessionBind({
                hostKey: privateKey.data.publicKey,
                sessionIdentifier: laterIdentifier,
                signature: privateKey.sign(laterIdentifier),
                forwarding: true,
            }),
        ).rejects.toBeInstanceOf(SSHAgentExtensionFailureError)
        const invalidSignature = new EncodedSignature({
            alg: "ssh-ed25519",
            data: Buffer.alloc(64),
        })
        await expect(
            client.opensshSessionBind({
                hostKey: privateKey.data.publicKey,
                sessionIdentifier: Buffer.alloc(32),
                signature: invalidSignature,
                forwarding: true,
            }),
        ).rejects.toThrow("signature is invalid")

        clientStream.end()
        await serving
        clientStream.destroy()
        serverStream.destroy()
    })

    test("passes OpenSSH token certificate constraints through awaited policy", async () => {
        const directory = await mkdtemp(join(tmpdir(), "modernssh-agent-certificate-"))
        try {
            const caPath = join(directory, "ca")
            const subjectPath = join(directory, "subject")
            await execFileAsync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", caPath])
            await execFileAsync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", subjectPath])
            await execFileAsync("ssh-keygen", [
                "-q",
                "-s",
                caPath,
                "-I",
                "agent-token@example.test",
                "-n",
                "alice",
                `${subjectPath}.pub`,
            ])
            const certificate = PublicKey.parseString(
                await readFile(`${subjectPath}-cert.pub`, "utf8"),
            )
            const [clientStream, serverStream] = streamPair()
            const server = new SSHAgentProtocolServer()
            let policyCalls = 0
            server.hooker.hook("addToken", async (_hook, request, decision) => {
                await Promise.resolve()
                policyCalls++
                expect(request.constraints).toHaveLength(2)
                const associated = request.constraints[1]
                expect(associated.type).toBe("openssh-associated-certificates")
                if (associated.type !== "openssh-associated-certificates") return
                expect(associated.certificatesOnly).toBeTrue()
                expect(associated.certificates).toHaveLength(1)
                expect(associated.certificates[0].equals(certificate)).toBeTrue()
                decision.success = true
            })
            const serving = server.serve(serverStream)
            const client = new SSHAgentProtocolClient(clientStream)

            await client.addToken("provider", Buffer.alloc(0), {
                constraints: [
                    {
                        type: "openssh-restrict-destination",
                        destinations: [
                            {
                                to: {
                                    hostname: "target.example",
                                    hostKeys: [{ publicKey: fixedPrivateKey().data.publicKey }],
                                },
                            },
                        ],
                    },
                    {
                        type: "openssh-associated-certificates",
                        certificatesOnly: true,
                        certificates: [certificate],
                    },
                ],
            })
            expect(policyCalls).toBe(1)

            clientStream.end()
            await serving
            clientStream.destroy()
            serverStream.destroy()
        } finally {
            await rm(directory, { recursive: true, force: true })
        }
    })

    test("isolates session-binding state between served connections", async () => {
        const [firstClientStream, firstServerStream] = streamPair()
        const [secondClientStream, secondServerStream] = streamPair()
        const server = new SSHAgentProtocolServer()
        const observations: [number, boolean][] = []
        server.hooker.hook("sessionBind", (_hook, _binding, decision) => {
            decision.success = true
        })
        server.hooker.hook("identities", (_hook, decision, connection) => {
            observations.push([connection.sessionBindings.length, connection.sessionBindAttempted])
            decision.identities = []
        })
        const firstServing = server.serve(firstServerStream)
        const secondServing = server.serve(secondServerStream)
        const firstClient = new SSHAgentProtocolClient(firstClientStream)
        const secondClient = new SSHAgentProtocolClient(secondClientStream)
        const privateKey = fixedPrivateKey()
        const identifier = Buffer.alloc(32, 0x66)

        await firstClient.opensshSessionBind({
            hostKey: privateKey.data.publicKey,
            sessionIdentifier: identifier,
            signature: privateKey.sign(identifier),
            forwarding: true,
        })
        await firstClient.getPublicKeys()
        await secondClient.getPublicKeys()
        expect(observations).toEqual([
            [1, true],
            [0, false],
        ])

        firstClientStream.end()
        secondClientStream.end()
        await Promise.all([firstServing, secondServing])
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
        await expect(
            client.addIdentity(fixedPrivateKey(), {
                constraints: [
                    { type: "lifetime", seconds: 1 },
                    { type: "lifetime", seconds: 2 },
                ],
            }),
        ).rejects.toThrow("duplicate")
        const destination = {
            type: "openssh-restrict-destination" as const,
            destinations: [
                {
                    to: {
                        hostname: "target.example",
                        hostKeys: [{ publicKey: fixedPrivateKey().data.publicKey }],
                    },
                },
            ],
        }
        await expect(
            client.addIdentity(fixedPrivateKey(), {
                constraints: [destination, destination],
            }),
        ).rejects.toThrow("duplicate")

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

        const duplicatePayload = Buffer.concat([
            destinationAddFrame.subarray(4),
            destinationConstraint,
        ])
        const duplicateLength = Buffer.alloc(4)
        duplicateLength.writeUInt32BE(duplicatePayload.length)
        malformedClient.write(Buffer.concat([duplicateLength, duplicatePayload]))
        const duplicateResponse = await iterator.next()
        expect(duplicateResponse.value).toEqual(Buffer.from("0000000105", "hex"))
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

            const destinationKey = PrivateKey.generateSync("ssh-ed25519")
            await client.addIdentity(destinationKey, {
                comment: "destination-constrained",
                constraints: [
                    {
                        type: "openssh-restrict-destination",
                        destinations: [
                            {
                                to: {
                                    username: "alice",
                                    hostname: "target.example",
                                    hostKeys: [{ publicKey: privateKeys[0].data.publicKey }],
                                },
                            },
                        ],
                    },
                ],
            })
            expect(
                (await client.getPublicKeys()).some(
                    ([, publicKey]) => publicKey.data.comment === "destination-constrained",
                ),
            ).toBeTrue()
            await client.removeAllIdentities()
            expect(await client.getPublicKeys()).toHaveLength(0)

            const boundSocket = createConnection(socketPath)
            await once(boundSocket, "connect")
            const boundClient = new SSHAgentProtocolClient(boundSocket)
            const boundIdentifier = Buffer.alloc(32, 0x55)
            await boundClient.opensshSessionBind({
                hostKey: privateKeys[0].data.publicKey,
                sessionIdentifier: boundIdentifier,
                signature: privateKeys[0].sign(boundIdentifier),
                forwarding: true,
            })
            boundClient.destroy()
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
