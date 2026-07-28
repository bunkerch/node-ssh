import { execFile, spawn } from "node:child_process"
import { once } from "node:events"
import { access, mkdtemp, rm } from "node:fs/promises"
import { createConnection } from "node:net"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { Duplex } from "node:stream"
import { promisify } from "node:util"

import {
    SSHAgentProtocolClient,
    SSHAgentProtocolServer,
} from "../../src/publickey/SSHAgentProtocol.js"
import PrivateKey, { SSHED25519PrivateKey } from "../../src/utils/PrivateKey.js"

const execFileAsync = promisify(execFile)
const seed = Buffer.from("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", "hex")
const publicBytes = Buffer.from(
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    "hex",
)
const signatureBytes = Buffer.from(
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" +
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    "hex",
)
const keyBlob = Buffer.from(
    "0000000b7373682d6564323535313900000020" + publicBytes.toString("hex"),
    "hex",
)
const requestIdentities = Buffer.from("000000010b", "hex")
const identitiesAnswer = Buffer.from(
    "000000470c0000000100000033" + keyBlob.toString("hex") + "0000000766697874757265",
    "hex",
)
const signRequest = Buffer.from(
    "000000400d00000033" + keyBlob.toString("hex") + "0000000000000000",
    "hex",
)
const signABCRequest = Buffer.from(
    "000000430d00000033" + keyBlob.toString("hex") + "0000000361626300000000",
    "hex",
)
const signAnswer = Buffer.from(
    "000000580e000000530000000b7373682d6564323535313900000040" + signatureBytes.toString("hex"),
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

class HangingCloseStream extends Duplex {
    _read(): void {
        // The fixture intentionally never ends the readable side.
    }

    _write(
        _chunk: Buffer,
        _encoding: BufferEncoding,
        callback: (error?: Error | null) => void,
    ): void {
        callback()
    }
}

class BlockedWriteStream extends Duplex {
    _read(): void {
        // Tests inject request bytes directly into the readable side.
    }

    _write(
        _chunk: Buffer,
        _encoding: BufferEncoding,
        callback: (error?: Error | null) => void,
    ): void {
        void callback
    }
}

async function readFrames(stream: Duplex, count: number): Promise<Buffer[]> {
    const frames: Buffer[] = []
    let buffered = Buffer.alloc(0)
    const iterator = stream[Symbol.asyncIterator]()
    while (true) {
        const result = await iterator.next()
        if (result.done) break
        buffered = Buffer.concat([buffered, result.value as Buffer])
        while (buffered.length >= 4) {
            const length = buffered.readUInt32BE(0)
            if (buffered.length < length + 4) break
            frames.push(Buffer.from(buffered.subarray(0, length + 4)))
            buffered = buffered.subarray(length + 4)
            if (frames.length === count) return frames
        }
    }
    throw new Error("Agent stream ended before every expected frame arrived")
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
    })
}

describe("SSH agent protocol", () => {
    test("client matches fixed identity and signing frames across fragmented replies", async () => {
        const [clientStream, fixtureStream] = streamPair()
        const requests: Buffer[] = []
        const fixture = (async () => {
            const iterator = fixtureStream[Symbol.asyncIterator]()
            while (requests.length < 3) {
                const result = await iterator.next()
                if (result.done) throw new Error("Agent client ended before sending every request")
                const raw = result.value as Buffer
                requests.push(Buffer.from(raw))
                const response = raw.equals(requestIdentities) ? identitiesAnswer : signAnswer
                fixtureStream.write(response.subarray(0, 2))
                fixtureStream.write(response.subarray(2, 17))
                fixtureStream.write(response.subarray(17))
            }
        })()
        const client = new SSHAgentProtocolClient(clientStream)

        try {
            const identities = await client.getPublicKeys()
            expect(identities).toHaveLength(1)
            expect(identities[0][0]).toBe(keyBlob.toString("base64"))
            expect(identities[0][1].data.comment).toBe("fixture")
            const signature = await client.sign(identities[0][0], Buffer.alloc(0))
            expect(signature.data.alg).toBe("ssh-ed25519")
            expect(signature.data.data).toEqual(signatureBytes)
            expect(requests).toEqual([requestIdentities, requestIdentities, signRequest])
        } finally {
            client.destroy()
            await fixture
            fixtureStream.destroy()
        }
    })

    test("client owns signing data before the asynchronous identity request", async () => {
        const [clientStream, fixtureStream] = streamPair()
        let releaseIdentity!: () => void
        const identityReleased = new Promise<void>((resolve) => {
            releaseIdentity = resolve
        })
        let reportIdentity!: () => void
        const identityReceived = new Promise<void>((resolve) => {
            reportIdentity = resolve
        })
        let receivedSignRequest: Buffer | undefined
        const fixture = (async () => {
            expect(await readFrames(fixtureStream, 1)).toEqual([requestIdentities])
            reportIdentity()
            await identityReleased
            fixtureStream.write(identitiesAnswer)
            ;[receivedSignRequest] = await readFrames(fixtureStream, 1)
            fixtureStream.write(signAnswer)
        })()
        const client = new SSHAgentProtocolClient(clientStream)

        try {
            const data = Buffer.from("abc")
            const signing = client.sign(keyBlob.toString("base64"), data)
            await identityReceived
            data.fill(0x7a)
            releaseIdentity()
            await signing
            await fixture

            expect(receivedSignRequest).toEqual(signABCRequest)
        } finally {
            releaseIdentity()
            client.destroy()
            fixtureStream.destroy()
        }
    })

    test("server awaits policy and matches fixed coalesced request vectors", async () => {
        const [clientStream, serverStream] = streamPair()
        const privateKey = fixedPrivateKey()
        const server = new SSHAgentProtocolServer()
        const calls: string[] = []
        server.hooker.hook("identities", async (_hook, decision) => {
            await Promise.resolve()
            calls.push("identities")
            decision.identities = [{ publicKey: privateKey.data.publicKey, comment: "fixture" }]
        })
        server.hooker.hook("sign", async (_hook, context, decision) => {
            await Promise.resolve()
            calls.push(`sign:${context.algorithm}:${context.flags}`)
            decision.signature = privateKey.sign(context.data, context.algorithm)
        })
        const serving = server.serve(serverStream)
        const responses = readFrames(clientStream, 2)

        clientStream.end(Buffer.concat([requestIdentities, signRequest]))
        expect(await responses).toEqual([identitiesAnswer, signAnswer])
        await serving
        expect(calls).toEqual(["identities", "sign:ssh-ed25519:0"])
        clientStream.destroy()
        serverStream.destroy()
    })

    test("server does not retain identities after a later policy failure", async () => {
        const [clientStream, serverStream] = streamPair()
        const privateKey = fixedPrivateKey()
        const server = new SSHAgentProtocolServer()
        const hookErrors: Error[] = []
        server.hooker.on("uncaughtException", (_event, error) => hookErrors.push(error))
        server.hooker.hook("identities", (_hook, decision) => {
            decision.identities = [{ publicKey: privateKey.data.publicKey, comment: "fixture" }]
        })
        server.hooker.hook("identities", async () => {
            await Promise.resolve()
            throw new Error("identity policy backend failed")
        })
        const serving = server.serve(serverStream)
        const response = readFrames(clientStream, 1)

        clientStream.end(requestIdentities)
        expect(await response).toEqual([Buffer.from("0000000105", "hex")])
        await serving
        expect(hookErrors.map((error) => error.message)).toEqual(["identity policy backend failed"])
        clientStream.destroy()
        serverStream.destroy()
    })

    test("server does not retain a signature after a later policy failure", async () => {
        const [clientStream, serverStream] = streamPair()
        const privateKey = fixedPrivateKey()
        const server = new SSHAgentProtocolServer()
        const hookErrors: Error[] = []
        server.hooker.on("uncaughtException", (_event, error) => hookErrors.push(error))
        server.hooker.hook("sign", (_hook, context, decision) => {
            decision.signature = privateKey.sign(context.data, context.algorithm)
        })
        server.hooker.hook("sign", async () => {
            await Promise.resolve()
            throw new Error("signing policy backend failed")
        })
        const serving = server.serve(serverStream)
        const response = readFrames(clientStream, 1)

        clientStream.end(signRequest)
        expect(await response).toEqual([Buffer.from("0000000105", "hex")])
        await serving
        expect(hookErrors.map((error) => error.message)).toEqual(["signing policy backend failed"])
        clientStream.destroy()
        serverStream.destroy()
    })

    test("denies missing policy and unsupported requests, and rejects malformed framing", async () => {
        const [clientStream, serverStream] = streamPair()
        const server = new SSHAgentProtocolServer()
        const serving = server.serve(serverStream)
        const responses = readFrames(clientStream, 2)
        clientStream.end(Buffer.concat([requestIdentities, Buffer.from("000000010f", "hex")]))
        expect(await responses).toEqual([
            Buffer.from("0000000105", "hex"),
            Buffer.from("0000000105", "hex"),
        ])
        await serving
        clientStream.destroy()
        serverStream.destroy()

        const [malformedClient, malformedServer] = streamPair()
        const rejected = server.serve(malformedServer)
        malformedClient.end(Buffer.from("00000000", "hex"))
        await expect(rejected).rejects.toThrow("invalid length")
        malformedClient.destroy()
        malformedServer.destroy()
    })

    test("closes after response framing violations and validates resource limits", async () => {
        expect(() => new SSHAgentProtocolServer({ maxMessageLength: 0 })).toThrow("positive uint32")
        expect(() => new SSHAgentProtocolServer(null as never)).toThrow(
            "SSH agent protocol server options must be an object",
        )
        expect(() => new SSHAgentProtocolServer({ maxMessageLength: null as never })).toThrow(
            "positive uint32",
        )
        expect(() => new SSHAgentProtocolServer({ requestTimeout: null as never })).toThrow(
            "integer between one and 2147483647",
        )
        expect(() => new SSHAgentProtocolServer({ requestTimeout: 0 })).toThrow(
            "integer between one and 2147483647",
        )
        const [validationStream, validationPeer] = streamPair()
        expect(() => new SSHAgentProtocolClient(validationStream, { requestTimeout: 0.5 })).toThrow(
            "integer between zero and 2147483647",
        )
        expect(() => new SSHAgentProtocolClient(validationStream, null as never)).toThrow(
            "SSH agent protocol client options must be an object",
        )
        expect(
            () =>
                new SSHAgentProtocolClient(validationStream, {
                    maxMessageLength: null as never,
                }),
        ).toThrow("positive uint32")
        expect(
            () =>
                new SSHAgentProtocolClient(validationStream, {
                    requestTimeout: null as never,
                }),
        ).toThrow("integer between zero and 2147483647")
        validationStream.destroy()
        validationPeer.destroy()

        const violations = [
            {
                response: Buffer.from("00000000", "hex"),
                message: "response has an invalid length",
            },
            {
                response: Buffer.from("000000020500", "hex"),
                message: "malformed failure response",
            },
            {
                response: Buffer.concat([identitiesAnswer, Buffer.from([0])]),
                message: "unsolicited response data",
            },
        ]
        for (const violation of violations) {
            const [clientStream, fixtureStream] = streamPair()
            const fixture = (async () => {
                await readFrames(fixtureStream, 1)
                fixtureStream.end(violation.response)
            })()
            const client = new SSHAgentProtocolClient(clientStream)

            await expect(client.getPublicKeys()).rejects.toThrow(violation.message)
            expect(clientStream.destroyed).toBeTrue()
            await expect(client.getPublicKeys()).rejects.toThrow(
                "SSH agent protocol client is closed",
            )
            fixtureStream.destroy()
            await fixture
        }
    })

    test("converts an oversized policy response into a bounded failure", async () => {
        const [clientStream, serverStream] = streamPair()
        const server = new SSHAgentProtocolServer({ maxMessageLength: 4 })
        server.hooker.hook("identities", (_hook, decision) => {
            decision.identities = []
        })
        const serving = server.serve(serverStream)
        const response = readFrames(clientStream, 1)

        clientStream.end(requestIdentities)
        expect(await response).toEqual([Buffer.from("0000000105", "hex")])
        await serving
        clientStream.destroy()
        serverStream.destroy()
    })

    test("settles a request deadline and closes the unusable stream", async () => {
        const [clientStream, fixtureStream] = streamPair()
        const request = readFrames(fixtureStream, 1)
        const client = new SSHAgentProtocolClient(clientStream, { requestTimeout: 20 })

        await expect(client.getPublicKeys()).rejects.toThrow("did not reply within 20 milliseconds")
        expect(await request).toEqual([requestIdentities])
        expect(clientStream.destroyed).toBeTrue()
        fixtureStream.destroy()
    })

    test("bounds a server response blocked by stream flow control", async () => {
        const stream = new BlockedWriteStream()
        const server = new SSHAgentProtocolServer({ requestTimeout: 20 })
        server.hooker.hook("identities", (_hook, decision) => {
            decision.identities = []
        })
        const serving = server.serve(stream)

        stream.push(requestIdentities)

        await expect(serving).rejects.toThrow(
            "Timed out waiting for SSH agent server response write",
        )
        expect(stream.destroyed).toBe(true)
    })

    test("aborts timed-out policy, suppresses late lock state, and releases the shared queue", async () => {
        const [firstClientStream, firstServerStream] = streamPair()
        const [secondClientStream, secondServerStream] = streamPair()
        const server = new SSHAgentProtocolServer({ requestTimeout: 50 })
        let policySignal!: AbortSignal
        let policyPassphrase!: Buffer
        let startedResolve!: () => void
        const started = new Promise<void>((resolve) => {
            startedResolve = resolve
        })
        let abortedResolve!: () => void
        const aborted = new Promise<void>((resolve) => {
            abortedResolve = resolve
        })
        let releasePolicy!: () => void
        const policyReleased = new Promise<void>((resolve) => {
            releasePolicy = resolve
        })
        server.hooker.hook("lock", async (_hook, context, decision, connection) => {
            policySignal = connection.signal
            policyPassphrase = context.passphrase
            startedResolve()
            await once(connection.signal, "abort")
            abortedResolve()
            await policyReleased
            decision.success = true
        })
        server.hooker.hook("identities", (_hook, decision) => {
            decision.identities = []
        })
        const firstServing = server.serve(firstServerStream)
        const secondServing = server.serve(secondServerStream)
        void firstServing.catch(() => undefined)
        const firstClient = new SSHAgentProtocolClient(firstClientStream, { requestTimeout: 100 })
        const secondClient = new SSHAgentProtocolClient(secondClientStream, { requestTimeout: 500 })

        try {
            const locking = firstClient.lock("secret")
            await started
            await new Promise<void>((resolve) => setImmediate(resolve))
            const identities = secondClient.getPublicKeys()

            await expect(firstServing).rejects.toThrow(
                "Timed out waiting for SSH agent server request",
            )
            await aborted
            expect(policySignal.aborted).toBe(true)
            expect((policySignal.reason as Error).message).toBe(
                "Timed out waiting for SSH agent server request",
            )
            expect(policyPassphrase).toEqual(Buffer.alloc("secret".length))
            expect(server.locked).toBe(false)
            expect(await identities).toEqual([])

            releasePolicy()
            await new Promise<void>((resolve) => setImmediate(resolve))
            expect(server.locked).toBe(false)
            firstClient.destroy()
            await expect(locking).rejects.toBeInstanceOf(Error)
            secondClientStream.end()
            await secondServing
        } finally {
            releasePolicy()
            firstClient.destroy()
            secondClient.destroy()
            firstServerStream.destroy()
            secondServerStream.destroy()
        }
    })

    test("drains queued work before closing and rejects later requests", async () => {
        const [clientStream, serverStream] = streamPair()
        const server = new SSHAgentProtocolServer()
        let release!: () => void
        const released = new Promise<void>((resolve) => {
            release = resolve
        })
        let reportRequest!: () => void
        const requested = new Promise<void>((resolve) => {
            reportRequest = resolve
        })
        server.hooker.hook("identities", async (_hook, decision) => {
            reportRequest()
            await released
            decision.identities = []
        })
        const serving = server.serve(serverStream)
        const client = new SSHAgentProtocolClient(clientStream)

        try {
            const identities = client.getPublicKeys()
            await requested
            const firstClose = client.close()
            const secondClose = client.close()

            expect(secondClose).toBe(firstClose)
            expect(clientStream.writableEnded).toBe(false)
            await expect(client.getPublicKeys()).rejects.toThrow(
                "SSH agent protocol client is closed",
            )

            release()
            expect(await identities).toEqual([])
            await serving
            clientStream.destroy()
            await firstClose
            expect(clientStream.destroyed).toBe(true)
            await client[Symbol.asyncDispose]()
        } finally {
            release()
            client.destroy()
            serverStream.destroy()
        }
    })

    test("bounds terminal agent stream closure when a peer ignores EOF", async () => {
        const stream = new HangingCloseStream()
        const client = new SSHAgentProtocolClient(stream, { requestTimeout: 20 })

        const firstClose = client.close()
        expect(client.close()).toBe(firstClose)
        await expect(firstClose).rejects.toThrow(
            "SSH agent stream did not close within 20 milliseconds",
        )
        expect(stream.destroyed).toBe(true)
        await expect(client[Symbol.asyncDispose]()).rejects.toThrow(
            "SSH agent stream did not close within 20 milliseconds",
        )
    })

    test("lists and signs through one persistent real agent connection", async () => {
        const directory = await mkdtemp(join(tmpdir(), "modernssh-agent-protocol-"))
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
                "protocol-test",
                "-f",
                keyPath,
            ])
            await execFileAsync("ssh-add", [keyPath], {
                env: { ...globalThis.process.env, SSH_AUTH_SOCK: socketPath },
            })
            const socket = createConnection(socketPath)
            await once(socket, "connect")
            const client = new SSHAgentProtocolClient(socket)
            const identities = await client.getPublicKeys()
            expect(identities).toHaveLength(1)
            expect(identities[0][1].data.comment).toBe("protocol-test")
            const message = Buffer.from("persistent agent protocol")
            const signature = await client.sign(identities[0][0], message)
            expect(identities[0][1].verifySignature(message, signature)).toBeTrue()
            await client.close()
        } finally {
            process.kill("SIGTERM")
            if (process.exitCode === null && process.signalCode === null)
                await once(process, "close")
            await rm(directory, { recursive: true, force: true })
        }
    }, 15_000)
})
