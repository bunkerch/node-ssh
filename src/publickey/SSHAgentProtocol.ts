import { once } from "node:events"
import type { Duplex } from "node:stream"

import { decodeSSHUTF8, encodeSSHUTF8 } from "../utils/SSHText.js"
import {
    readNextBuffer,
    readNextUint32,
    serializeBuffer,
    serializeUint32,
} from "../utils/Buffer.js"
import { Hooker } from "../utils/Hooker.js"
import PublicKey from "../utils/PublicKey.js"
import EncodedSignature from "../utils/Signature.js"
import Agent, { AgentError, AgentType } from "./Agent.js"

export const MAX_SSH_AGENT_MESSAGE_LENGTH = 256 * 1024

export enum SSHAgentMessageType {
    Failure = 5,
    Success = 6,
    RequestIdentities = 11,
    IdentitiesAnswer = 12,
    SignRequest = 13,
    SignResponse = 14,
}

const SSH_AGENT_RSA_SHA2_256 = 2
const SSH_AGENT_RSA_SHA2_512 = 4

export interface SSHAgentProtocolOptions {
    /** Maximum payload length accepted from the peer. */
    maxMessageLength?: number
    /** Maximum milliseconds for a client request. Zero disables the deadline. */
    requestTimeout?: number
}

export interface SSHAgentProtocolServerOptions {
    /** Maximum payload length accepted from the peer or returned by policy. */
    maxMessageLength?: number
}

export interface SSHAgentIdentity {
    publicKey: PublicKey
    comment?: string
}

export interface SSHAgentServerIdentitiesController {
    /** Leave undefined to deny the request with SSH_AGENT_FAILURE. */
    identities: readonly Readonly<SSHAgentIdentity>[] | undefined
}

export type SSHAgentServerSignContext = Readonly<{
    publicKey: PublicKey
    data: Buffer
    /** Exact signature algorithm requested by the agent protocol flags. */
    algorithm: string
    flags: number
}>

export interface SSHAgentServerSignController {
    /** Leave undefined to deny the request with SSH_AGENT_FAILURE. */
    signature: EncodedSignature | undefined
}

// eslint-disable-next-line @typescript-eslint/consistent-type-definitions
export type SSHAgentServerHooker = {
    identities: [controller: SSHAgentServerIdentitiesController]
    sign: [context: SSHAgentServerSignContext, controller: SSHAgentServerSignController]
}

function validateOptions(options: SSHAgentProtocolOptions): Required<SSHAgentProtocolOptions> {
    const maxMessageLength = options.maxMessageLength ?? MAX_SSH_AGENT_MESSAGE_LENGTH
    const requestTimeout = options.requestTimeout ?? 10_000
    if (
        !Number.isSafeInteger(maxMessageLength) ||
        maxMessageLength < 1 ||
        maxMessageLength > 0xffff_ffff
    ) {
        throw new RangeError("SSH agent maximum message length must be a positive uint32")
    }
    if (
        !Number.isSafeInteger(requestTimeout) ||
        requestTimeout < 0 ||
        requestTimeout > 0x7fff_ffff
    ) {
        throw new RangeError(
            "SSH agent request timeout must be an integer between zero and 2147483647",
        )
    }
    return { maxMessageLength, requestTimeout }
}

function frame(payload: Buffer, maxMessageLength: number): Buffer {
    if (!Buffer.isBuffer(payload) || payload.length < 1 || payload.length > maxMessageLength) {
        throw new SSHAgentProtocolError("SSH agent message has an invalid length")
    }
    return Buffer.concat([serializeUint32(payload.length), payload])
}

async function writeFrame(
    stream: Duplex,
    payload: Buffer,
    maxMessageLength: number,
): Promise<void> {
    if (stream.destroyed || !stream.writable) {
        throw new SSHAgentProtocolError("SSH agent stream is not writable")
    }
    if (!stream.write(frame(payload, maxMessageLength))) await once(stream, "drain")
}

function parseIdentityAnswer(payload: Buffer): [string, PublicKey][] {
    if (payload[0] !== SSHAgentMessageType.IdentitiesAnswer) {
        throw new SSHAgentProtocolError("SSH agent returned an unexpected identities response")
    }
    try {
        let raw = payload.subarray(1)
        const [count, afterCount] = readNextUint32(raw)
        raw = afterCount
        const identities: [string, PublicKey][] = []
        for (let index = 0; index < count; index++) {
            let keyBlob: Buffer
            let comment: Buffer
            ;[keyBlob, raw] = readNextBuffer(raw)
            ;[comment, raw] = readNextBuffer(raw)
            const publicKey = PublicKey.parse(keyBlob)
            publicKey.data.comment =
                comment.length === 0
                    ? undefined
                    : decodeSSHUTF8(comment, "SSH agent identity comment")
            identities.push([keyBlob.toString("base64"), publicKey])
        }
        if (raw.length !== 0) throw new Error("trailing data")
        return identities
    } catch (error) {
        throw new SSHAgentProtocolError("SSH agent returned an invalid identities response", {
            cause: error,
        })
    }
}

function signatureAlgorithmForFlags(publicKey: PublicKey, flags: number): string {
    if (!Number.isInteger(flags) || flags < 0 || flags > 0xffff_ffff) {
        throw new SSHAgentProtocolError("SSH agent signature flags must be a uint32")
    }
    if ((flags & ~(SSH_AGENT_RSA_SHA2_256 | SSH_AGENT_RSA_SHA2_512)) !== 0) {
        throw new SSHAgentProtocolError("SSH agent signature request contains unknown flags")
    }
    if (flags === (SSH_AGENT_RSA_SHA2_256 | SSH_AGENT_RSA_SHA2_512)) {
        throw new SSHAgentProtocolError("SSH agent signature request selects multiple hashes")
    }
    let requestedAlgorithm = publicKey.data.alg
    if (flags !== 0) {
        const rsa = publicKey.data.alg === "ssh-rsa" || publicKey.data.alg.includes("rsa-")
        if (!rsa) {
            throw new SSHAgentProtocolError("SSH agent RSA SHA-2 flags require an RSA key")
        }
        const hash = flags === SSH_AGENT_RSA_SHA2_512 ? "rsa-sha2-512" : "rsa-sha2-256"
        requestedAlgorithm = publicKey.data.alg.includes("-cert-")
            ? `${hash}-cert-v01@openssh.com`
            : hash
    }
    if (!publicKey.supportsSignatureAlgorithm(requestedAlgorithm)) {
        throw new SSHAgentProtocolError(`SSH agent key does not support ${requestedAlgorithm}`)
    }
    return publicKey.signatureAlgorithmFor(requestedAlgorithm)
}

/** A Promise-based client for one already-connected agent protocol stream. */
export class SSHAgentProtocolClient extends Agent<string> {
    readonly type = AgentType.NonInteractive
    readonly stream: Duplex
    readonly options: Readonly<Required<SSHAgentProtocolOptions>>
    readonly #iterator: AsyncIterator<unknown>
    #buffer = Buffer.alloc(0)
    #queue: Promise<void> = Promise.resolve()

    constructor(stream: Duplex, options: SSHAgentProtocolOptions = {}) {
        super()
        if (
            typeof stream !== "object" ||
            stream === null ||
            typeof stream.write !== "function" ||
            typeof stream[Symbol.asyncIterator] !== "function"
        ) {
            throw new TypeError("SSH agent protocol client requires a Duplex stream")
        }
        this.stream = stream
        this.options = Object.freeze(validateOptions(options))
        this.#iterator = stream[Symbol.asyncIterator]()
    }

    getPublicKeys(): Promise<[string, PublicKey][]> {
        return this.#request(Buffer.from([SSHAgentMessageType.RequestIdentities])).then((payload) =>
            parseIdentityAnswer(payload),
        )
    }

    async getPublicKey(id: string): Promise<PublicKey> {
        const identity = (await this.getPublicKeys()).find(([candidate]) => candidate === id)
        if (!identity) throw new SSHAgentProtocolError("SSH agent identity is no longer available")
        return identity[1]
    }

    async sign(id: string, data: Buffer, algorithm?: string): Promise<EncodedSignature> {
        if (!Buffer.isBuffer(data)) throw new TypeError("SSH agent signing data must be a buffer")
        const publicKey = await this.getPublicKey(id)
        const requestedAlgorithm = algorithm ?? publicKey.data.alg
        if (!publicKey.supportsSignatureAlgorithm(requestedAlgorithm)) {
            throw new SSHAgentProtocolError(
                `Signature algorithm ${requestedAlgorithm} is incompatible with ${publicKey.data.alg}`,
            )
        }
        const signatureAlgorithm = publicKey.signatureAlgorithmFor(requestedAlgorithm)
        const flags =
            signatureAlgorithm === "rsa-sha2-512"
                ? SSH_AGENT_RSA_SHA2_512
                : signatureAlgorithm === "rsa-sha2-256"
                  ? SSH_AGENT_RSA_SHA2_256
                  : 0
        const response = await this.#request(
            Buffer.concat([
                Buffer.from([SSHAgentMessageType.SignRequest]),
                serializeBuffer(publicKey.serialize()),
                serializeBuffer(Buffer.from(data)),
                serializeUint32(flags),
            ]),
        )
        if (response[0] !== SSHAgentMessageType.SignResponse) {
            throw new SSHAgentProtocolError("SSH agent returned an unexpected signing response")
        }
        try {
            const [signature, remaining] = readNextBuffer(response.subarray(1))
            if (remaining.length !== 0) throw new Error("trailing data")
            const encoded = EncodedSignature.parse(signature)
            if (encoded.data.alg !== signatureAlgorithm) {
                throw new Error(
                    `agent returned ${encoded.data.alg} instead of ${signatureAlgorithm}`,
                )
            }
            return encoded
        } catch (error) {
            throw new SSHAgentProtocolError("SSH agent returned an invalid signature response", {
                cause: error,
            })
        }
    }

    destroy(error?: Error): void {
        this.stream.destroy(error)
    }

    #request(payload: Buffer): Promise<Buffer> {
        const operation = this.#queue.then(() => this.#requestNow(payload))
        this.#queue = operation.then(
            () => undefined,
            () => undefined,
        )
        return operation
    }

    async #requestNow(payload: Buffer): Promise<Buffer> {
        let timer: ReturnType<typeof setTimeout> | undefined
        try {
            const response = (async (): Promise<Buffer> => {
                await writeFrame(this.stream, payload, this.options.maxMessageLength)
                return this.#readFrame()
            })()
            if (this.options.requestTimeout === 0) return await response
            const deadline = new Promise<never>((_resolve, reject) => {
                timer = setTimeout(() => {
                    const error = new SSHAgentProtocolError(
                        `SSH agent did not reply within ${this.options.requestTimeout} milliseconds`,
                    )
                    this.stream.destroy(error)
                    reject(error)
                }, this.options.requestTimeout)
                timer.unref()
            })
            return await Promise.race([response, deadline])
        } finally {
            if (timer) clearTimeout(timer)
        }
    }

    async #readFrame(): Promise<Buffer> {
        while (this.#buffer.length < 4) await this.#readChunk()
        const length = this.#buffer.readUInt32BE(0)
        if (length < 1 || length > this.options.maxMessageLength) {
            throw new SSHAgentProtocolError("SSH agent response has an invalid length")
        }
        while (this.#buffer.length < length + 4) await this.#readChunk()
        const payload = Buffer.from(this.#buffer.subarray(4, length + 4))
        this.#buffer = this.#buffer.subarray(length + 4)
        if (this.#buffer.length !== 0) {
            throw new SSHAgentProtocolError("SSH agent sent unsolicited response data")
        }
        if (payload[0] === SSHAgentMessageType.Failure) {
            if (payload.length !== 1) {
                throw new SSHAgentProtocolError("SSH agent returned a malformed failure response")
            }
            throw new SSHAgentProtocolError("SSH agent refused the request")
        }
        return payload
    }

    async #readChunk(): Promise<void> {
        const result = await this.#iterator.next()
        if (result.done) throw new SSHAgentProtocolError("SSH agent closed before replying")
        if (!Buffer.isBuffer(result.value)) {
            throw new SSHAgentProtocolError("SSH agent stream returned non-buffer data")
        }
        this.#buffer = Buffer.concat([this.#buffer, result.value])
        if (this.#buffer.length > this.options.maxMessageLength + 4) {
            throw new SSHAgentProtocolError("SSH agent response exceeds the configured limit")
        }
    }
}

/** An awaited, deny-by-default agent protocol endpoint for a Duplex stream. */
export class SSHAgentProtocolServer {
    readonly hooker = new Hooker<SSHAgentServerHooker>()
    readonly options: Readonly<Required<SSHAgentProtocolServerOptions>>
    readonly #activeStreams = new WeakSet<Duplex>()

    constructor(options: SSHAgentProtocolServerOptions = {}) {
        const { maxMessageLength } = validateOptions({ ...options, requestTimeout: 0 })
        this.options = Object.freeze({ maxMessageLength })
    }

    async serve(stream: Duplex): Promise<void> {
        if (
            typeof stream !== "object" ||
            stream === null ||
            typeof stream.write !== "function" ||
            typeof stream[Symbol.asyncIterator] !== "function"
        ) {
            throw new TypeError("SSH agent protocol server requires a Duplex stream")
        }
        if (this.#activeStreams.has(stream)) {
            throw new Error("SSH agent protocol stream is already being served")
        }
        this.#activeStreams.add(stream)
        let buffered = Buffer.alloc(0)
        try {
            for await (const chunk of stream) {
                if (!Buffer.isBuffer(chunk)) {
                    throw new SSHAgentProtocolError("SSH agent stream returned non-buffer data")
                }
                buffered = Buffer.concat([buffered, chunk])
                while (buffered.length >= 4) {
                    const length = buffered.readUInt32BE(0)
                    if (length < 1 || length > this.options.maxMessageLength) {
                        throw new SSHAgentProtocolError("SSH agent request has an invalid length")
                    }
                    if (buffered.length < length + 4) break
                    const payload = Buffer.from(buffered.subarray(4, length + 4))
                    buffered = buffered.subarray(length + 4)
                    const response = await this.#handleRequest(payload)
                    await writeFrame(stream, response, this.options.maxMessageLength)
                }
                if (buffered.length > this.options.maxMessageLength + 4) {
                    throw new SSHAgentProtocolError(
                        "SSH agent request exceeds the configured limit",
                    )
                }
            }
            if (buffered.length !== 0) {
                throw new SSHAgentProtocolError("SSH agent stream ended with a truncated request")
            }
            if (stream.writable && !stream.writableEnded) stream.end()
        } catch (error) {
            stream.destroy(error as Error)
            throw error
        } finally {
            this.#activeStreams.delete(stream)
        }
    }

    async #handleRequest(payload: Buffer): Promise<Buffer> {
        if (payload[0] === SSHAgentMessageType.RequestIdentities && payload.length === 1) {
            const controller: SSHAgentServerIdentitiesController = { identities: undefined }
            await this.hooker.triggerHook("identities", controller)
            if (controller.identities === undefined) return this.#failure()
            try {
                const identities = controller.identities.map((identity) => {
                    if (!(identity.publicKey instanceof PublicKey)) {
                        throw new TypeError("SSH agent identity must contain a PublicKey")
                    }
                    return Buffer.concat([
                        serializeBuffer(identity.publicKey.serialize()),
                        serializeBuffer(
                            encodeSSHUTF8(identity.comment ?? "", "SSH agent identity comment"),
                        ),
                    ])
                })
                return this.#boundedResponse(
                    Buffer.concat([
                        Buffer.from([SSHAgentMessageType.IdentitiesAnswer]),
                        serializeUint32(identities.length),
                        ...identities,
                    ]),
                )
            } catch {
                return this.#failure()
            }
        }
        if (payload[0] === SSHAgentMessageType.SignRequest) {
            try {
                let raw = payload.subarray(1)
                const [keyBlob, afterKey] = readNextBuffer(raw)
                const [data, afterData] = readNextBuffer(afterKey)
                const [flags, remaining] = readNextUint32(afterData)
                raw = remaining
                if (raw.length !== 0) throw new Error("trailing data")
                const publicKey = PublicKey.parse(keyBlob)
                const algorithm = signatureAlgorithmForFlags(publicKey, flags)
                const context: SSHAgentServerSignContext = Object.freeze({
                    publicKey,
                    data: Buffer.from(data),
                    algorithm,
                    flags,
                })
                const controller: SSHAgentServerSignController = { signature: undefined }
                await this.hooker.triggerHook("sign", context, controller)
                const signature = controller.signature
                if (
                    !signature ||
                    signature.data.alg !== algorithm ||
                    !publicKey.verifySignature(data, signature)
                ) {
                    return this.#failure()
                }
                return this.#boundedResponse(
                    Buffer.concat([
                        Buffer.from([SSHAgentMessageType.SignResponse]),
                        serializeBuffer(signature.serialize()),
                    ]),
                )
            } catch {
                return this.#failure()
            }
        }
        return this.#failure()
    }

    #failure(): Buffer {
        return Buffer.from([SSHAgentMessageType.Failure])
    }

    #boundedResponse(payload: Buffer): Buffer {
        return payload.length <= this.options.maxMessageLength ? payload : this.#failure()
    }
}

export class SSHAgentProtocolError extends AgentError {
    name = "SSHAgentProtocolError"
}
