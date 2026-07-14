import { randomBytes, scrypt, timingSafeEqual } from "node:crypto"
import type { Duplex } from "node:stream"

import { decodeSSHUTF8, encodeSSHUTF8 } from "../utils/SSHText.js"
import { decodeSSHName, encodeSSHName } from "../utils/SSHName.js"
import {
    readNextBuffer,
    readNextUint32,
    serializeBuffer,
    serializeUint32,
} from "../utils/Buffer.js"
import { Hooker } from "../utils/Hooker.js"
import PrivateKey from "../utils/PrivateKey.js"
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
    AddIdentity = 17,
    RemoveIdentity = 18,
    RemoveAllIdentities = 19,
    AddToken = 20,
    RemoveToken = 21,
    Lock = 22,
    Unlock = 23,
    AddConstrainedIdentity = 25,
    AddConstrainedToken = 26,
    Extension = 27,
    ExtensionFailure = 28,
    ExtensionResponse = 29,
}

export enum SSHAgentConstraintType {
    Lifetime = 1,
    Confirm = 2,
    Extension = 255,
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

export type SSHAgentConstraint =
    | Readonly<{ type: "lifetime"; seconds: number }>
    | Readonly<{ type: "confirm" }>
    | Readonly<{ type: "extension"; name: string; data: Buffer }>

export interface SSHAgentAddIdentityOptions {
    comment?: string
    constraints?: readonly SSHAgentConstraint[]
}

export interface SSHAgentAddTokenOptions {
    constraints?: readonly SSHAgentConstraint[]
}

export type SSHAgentExtensionResult =
    | Readonly<{ kind: "success" }>
    | Readonly<{ kind: "response"; contents: Buffer }>

export type SSHAgentServerExtensionResult = SSHAgentExtensionResult | Readonly<{ kind: "failure" }>

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

export interface SSHAgentServerSuccessController {
    /** Set to true to accept the request. Undefined and false deny it. */
    success: boolean | undefined
}

export type SSHAgentServerAddIdentityContext = Readonly<{
    privateKey: PrivateKey
    comment: string
    constraints: readonly SSHAgentConstraint[]
}>

export type SSHAgentServerAddTokenContext = Readonly<{
    /** Opaque token identifier copied from the request. */
    tokenId: Buffer
    /** Ephemeral PIN bytes. Do not retain this buffer after the hook returns. */
    pin: Buffer
    constraints: readonly SSHAgentConstraint[]
}>

export type SSHAgentServerRemoveIdentityContext = Readonly<{
    publicKey: PublicKey
}>

export type SSHAgentServerRemoveTokenContext = Readonly<{
    tokenId: string
    /** Ephemeral UTF-8 PIN bytes. Do not retain this buffer after the hook returns. */
    pin: Buffer
}>

export type SSHAgentServerPassphraseContext = Readonly<{
    /** Ephemeral passphrase bytes. Do not retain this buffer after the hook returns. */
    passphrase: Buffer
}>

export type SSHAgentServerExtensionContext = Readonly<{
    type: string
    contents: Buffer
}>

export interface SSHAgentServerExtensionController {
    /** Undefined means the extension is unsupported and returns SSH_AGENT_FAILURE. */
    result: SSHAgentServerExtensionResult | undefined
}

export interface SSHAgentServerQueryExtensionsController {
    /** Undefined means the query extension is unsupported. */
    extensions: readonly string[] | undefined
}

// eslint-disable-next-line @typescript-eslint/consistent-type-definitions
export type SSHAgentServerHooker = {
    identities: [controller: SSHAgentServerIdentitiesController]
    sign: [context: SSHAgentServerSignContext, controller: SSHAgentServerSignController]
    addIdentity: [
        context: SSHAgentServerAddIdentityContext,
        controller: SSHAgentServerSuccessController,
    ]
    addToken: [context: SSHAgentServerAddTokenContext, controller: SSHAgentServerSuccessController]
    removeIdentity: [
        context: SSHAgentServerRemoveIdentityContext,
        controller: SSHAgentServerSuccessController,
    ]
    removeAllIdentities: [controller: SSHAgentServerSuccessController]
    removeToken: [
        context: SSHAgentServerRemoveTokenContext,
        controller: SSHAgentServerSuccessController,
    ]
    lock: [context: SSHAgentServerPassphraseContext, controller: SSHAgentServerSuccessController]
    unlock: [context: SSHAgentServerPassphraseContext, controller: SSHAgentServerSuccessController]
    extension: [
        context: SSHAgentServerExtensionContext,
        controller: SSHAgentServerExtensionController,
    ]
    queryExtensions: [controller: SSHAgentServerQueryExtensionsController]
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
    const output = frame(payload, maxMessageLength)
    try {
        await new Promise<void>((resolve, reject) => {
            stream.write(output, (error) => (error ? reject(error) : resolve()))
        })
    } finally {
        output.fill(0)
    }
}

function encodeOpaqueString(value: string | Buffer, description: string): Buffer {
    if (typeof value === "string") return encodeSSHUTF8(value, description)
    if (!Buffer.isBuffer(value)) throw new TypeError(`${description} must be a string or buffer`)
    return Buffer.from(value)
}

function serializeConstraints(constraints: readonly SSHAgentConstraint[]): Buffer {
    if (!Array.isArray(constraints)) {
        throw new TypeError("SSH agent constraints must be an array")
    }
    const serialized: Buffer[] = []
    constraints.forEach((constraint, index) => {
        if (typeof constraint !== "object" || constraint === null) {
            throw new TypeError("SSH agent constraint must be an object")
        }
        if (constraint.type === "lifetime") {
            if (
                !Number.isSafeInteger(constraint.seconds) ||
                constraint.seconds < 0 ||
                constraint.seconds > 0xffff_ffff
            ) {
                throw new RangeError("SSH agent constraint lifetime must be a uint32")
            }
            serialized.push(
                Buffer.from([SSHAgentConstraintType.Lifetime]),
                serializeUint32(constraint.seconds),
            )
            return
        }
        if (constraint.type === "confirm") {
            serialized.push(Buffer.from([SSHAgentConstraintType.Confirm]))
            return
        }
        if (constraint.type === "extension") {
            if (index !== constraints.length - 1) {
                throw new SSHAgentProtocolError(
                    "SSH agent extension constraint must be the final constraint",
                )
            }
            if (!Buffer.isBuffer(constraint.data)) {
                throw new TypeError("SSH agent constraint extension data must be a buffer")
            }
            const encodedName = encodeSSHUTF8(
                constraint.name,
                "SSH agent constraint extension name",
            )
            if (encodedName.length === 0) {
                throw new SSHAgentProtocolError(
                    "SSH agent constraint extension name must not be empty",
                )
            }
            serialized.push(
                Buffer.from([SSHAgentConstraintType.Extension]),
                serializeBuffer(encodedName),
                Buffer.from(constraint.data),
            )
            return
        }
        throw new SSHAgentProtocolError("SSH agent constraint has an unsupported type")
    })
    return Buffer.concat(serialized)
}

function parseConstraints(raw: Buffer): readonly SSHAgentConstraint[] {
    const constraints: SSHAgentConstraint[] = []
    while (raw.length !== 0) {
        const type = raw[0]
        raw = raw.subarray(1)
        if (type === SSHAgentConstraintType.Lifetime) {
            let seconds: number
            ;[seconds, raw] = readNextUint32(raw)
            constraints.push(Object.freeze({ type: "lifetime", seconds }))
            continue
        }
        if (type === SSHAgentConstraintType.Confirm) {
            constraints.push(Object.freeze({ type: "confirm" }))
            continue
        }
        if (type === SSHAgentConstraintType.Extension) {
            let name: Buffer
            ;[name, raw] = readNextBuffer(raw)
            if (name.length === 0) {
                throw new SSHAgentProtocolError(
                    "SSH agent constraint extension name must not be empty",
                )
            }
            constraints.push(
                Object.freeze({
                    type: "extension",
                    name: decodeSSHUTF8(name, "SSH agent constraint extension name"),
                    data: Buffer.from(raw),
                }),
            )
            raw = Buffer.alloc(0)
            continue
        }
        throw new SSHAgentProtocolError("SSH agent request contains an unknown constraint")
    }
    return Object.freeze(constraints)
}

function serializePrivateKeyRequest(
    privateKey: PrivateKey,
    options: SSHAgentAddIdentityOptions,
): Buffer {
    if (!(privateKey instanceof PrivateKey)) {
        throw new TypeError("SSH agent identity must be a PrivateKey")
    }
    const underlyingPublicKey = privateKey.data.algorithm.getPublicKey()
    if (privateKey.data.alg !== underlyingPublicKey.data.alg) {
        throw new SSHAgentProtocolError("SSH agent cannot add a certificate as a private key")
    }
    if (!PrivateKey.algorithms.has(privateKey.data.alg)) {
        throw new SSHAgentProtocolError(
            `SSH agent does not support private key type ${privateKey.data.alg}`,
        )
    }
    const constraints = options.constraints ?? []
    const keyData = privateKey.data.algorithm.serialize()
    try {
        return Buffer.concat([
            Buffer.from([
                constraints.length === 0
                    ? SSHAgentMessageType.AddIdentity
                    : SSHAgentMessageType.AddConstrainedIdentity,
            ]),
            serializeBuffer(encodeSSHName(privateKey.data.alg, "SSH agent private key type")),
            keyData,
            serializeBuffer(
                encodeSSHUTF8(
                    options.comment ?? privateKey.data.comment ?? "",
                    "SSH agent identity comment",
                ),
            ),
            serializeConstraints(constraints),
        ])
    } finally {
        keyData.fill(0)
    }
}

function parsePrivateKeyRequest(
    payload: Buffer,
    constrained: boolean,
): SSHAgentServerAddIdentityContext {
    let raw = payload.subarray(1)
    const [encodedAlgorithm, afterAlgorithm] = readNextBuffer(raw)
    raw = afterAlgorithm
    const algorithmName = decodeSSHName(encodedAlgorithm, "SSH agent private key type")
    const Algorithm = PrivateKey.algorithms.get(algorithmName)
    if (!Algorithm) throw new SSHAgentProtocolError("Unsupported SSH agent private key type")
    const [algorithm, afterKey] = Algorithm.parse(raw) as [InstanceType<typeof Algorithm>, Buffer]
    raw = afterKey
    const [encodedComment, afterComment] = readNextBuffer(raw)
    raw = afterComment
    const comment = decodeSSHUTF8(encodedComment, "SSH agent identity comment")
    const constraints = constrained ? parseConstraints(raw) : Object.freeze([])
    if (!constrained && raw.length !== 0) throw new Error("trailing data")
    const publicKey = algorithm.getPublicKey()
    if (publicKey.data.alg !== algorithmName) throw new Error("private key type mismatch")
    return Object.freeze({
        privateKey: new PrivateKey({
            alg: algorithmName,
            publicKey,
            algorithm,
            comment: comment.length === 0 ? undefined : comment,
        }),
        comment,
        constraints,
    })
}

function parseExactString(raw: Buffer): Buffer {
    let value: Buffer
    ;[value, raw] = readNextBuffer(raw)
    if (raw.length !== 0) throw new Error("trailing data")
    return value
}

function deriveLockVerifier(passphrase: Buffer, salt: Buffer): Promise<Buffer> {
    return new Promise((resolve, reject) => {
        scrypt(passphrase, salt, 32, (error, derivedKey) => {
            if (error) reject(error)
            else resolve(Buffer.from(derivedKey))
        })
    })
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

    async addIdentity(
        privateKey: PrivateKey,
        options: SSHAgentAddIdentityOptions = {},
    ): Promise<void> {
        const payload = serializePrivateKeyRequest(privateKey, options)
        try {
            this.#expectSuccess(await this.#request(payload))
        } finally {
            payload.fill(0)
        }
    }

    async addToken(
        tokenId: string | Buffer,
        pin: string | Buffer = Buffer.alloc(0),
        options: SSHAgentAddTokenOptions = {},
    ): Promise<void> {
        const constraints = options.constraints ?? []
        const encodedConstraints = serializeConstraints(constraints)
        const encodedTokenId = encodeOpaqueString(tokenId, "SSH agent token identifier")
        const encodedPin = encodeOpaqueString(pin, "SSH agent token PIN")
        let payload: Buffer | undefined
        try {
            payload = Buffer.concat([
                Buffer.from([
                    constraints.length === 0
                        ? SSHAgentMessageType.AddToken
                        : SSHAgentMessageType.AddConstrainedToken,
                ]),
                serializeBuffer(encodedTokenId),
                serializeBuffer(encodedPin),
                encodedConstraints,
            ])
            this.#expectSuccess(await this.#request(payload))
        } finally {
            encodedPin.fill(0)
            payload?.fill(0)
        }
    }

    async removeIdentity(publicKey: PublicKey): Promise<void> {
        if (!(publicKey instanceof PublicKey)) {
            throw new TypeError("SSH agent identity removal requires a PublicKey")
        }
        this.#expectSuccess(
            await this.#request(
                Buffer.concat([
                    Buffer.from([SSHAgentMessageType.RemoveIdentity]),
                    serializeBuffer(publicKey.serialize()),
                ]),
            ),
        )
    }

    async removeAllIdentities(): Promise<void> {
        this.#expectSuccess(
            await this.#request(Buffer.from([SSHAgentMessageType.RemoveAllIdentities])),
        )
    }

    async removeToken(tokenId: string, pin: string | Buffer = Buffer.alloc(0)): Promise<void> {
        const encodedTokenId = encodeSSHUTF8(tokenId, "SSH agent token identifier")
        const encodedPin = encodeOpaqueString(pin, "SSH agent token PIN")
        let payload: Buffer | undefined
        try {
            decodeSSHUTF8(encodedPin, "SSH agent token PIN")
            payload = Buffer.concat([
                Buffer.from([SSHAgentMessageType.RemoveToken]),
                serializeBuffer(encodedTokenId),
                serializeBuffer(encodedPin),
            ])
            this.#expectSuccess(await this.#request(payload))
        } finally {
            encodedPin.fill(0)
            payload?.fill(0)
        }
    }

    async lock(passphrase: string | Buffer): Promise<void> {
        await this.#passphraseRequest(SSHAgentMessageType.Lock, passphrase)
    }

    async unlock(passphrase: string | Buffer): Promise<void> {
        await this.#passphraseRequest(SSHAgentMessageType.Unlock, passphrase)
    }

    async extension(
        type: string,
        contents: Buffer = Buffer.alloc(0),
    ): Promise<SSHAgentExtensionResult> {
        if (!Buffer.isBuffer(contents)) {
            throw new TypeError("SSH agent extension contents must be a buffer")
        }
        const encodedType = encodeSSHUTF8(type, "SSH agent extension type")
        if (encodedType.length === 0) {
            throw new SSHAgentProtocolError("SSH agent extension type must not be empty")
        }
        const response = await this.#request(
            Buffer.concat([
                Buffer.from([SSHAgentMessageType.Extension]),
                serializeBuffer(encodedType),
                Buffer.from(contents),
            ]),
        )
        if (response[0] === SSHAgentMessageType.Success) {
            if (response.length !== 1) {
                throw new SSHAgentProtocolError("SSH agent returned a malformed success response")
            }
            return Object.freeze({ kind: "success" })
        }
        if (response[0] === SSHAgentMessageType.ExtensionFailure) {
            if (response.length !== 1) {
                throw new SSHAgentProtocolError(
                    "SSH agent returned a malformed extension failure response",
                )
            }
            throw new SSHAgentExtensionFailureError("SSH agent extension request failed")
        }
        if (response[0] !== SSHAgentMessageType.ExtensionResponse) {
            throw new SSHAgentProtocolError("SSH agent returned an unexpected extension response")
        }
        try {
            const [encodedResponseType, responseContents] = readNextBuffer(response.subarray(1))
            const responseType = decodeSSHUTF8(
                encodedResponseType,
                "SSH agent extension response type",
            )
            if (responseType !== type) throw new Error("extension response type mismatch")
            return Object.freeze({ kind: "response", contents: Buffer.from(responseContents) })
        } catch (error) {
            throw new SSHAgentProtocolError("SSH agent returned an invalid extension response", {
                cause: error,
            })
        }
    }

    async queryExtensions(): Promise<readonly string[]> {
        const result = await this.extension("query")
        if (result.kind !== "response") {
            throw new SSHAgentProtocolError("SSH agent query did not return an extension list")
        }
        try {
            let raw = result.contents
            const extensions: string[] = []
            while (raw.length !== 0) {
                let encoded: Buffer
                ;[encoded, raw] = readNextBuffer(raw)
                const extension = decodeSSHUTF8(encoded, "SSH agent supported extension type")
                if (extension.length === 0) throw new Error("empty extension type")
                if (extensions.includes(extension)) throw new Error("duplicate extension type")
                extensions.push(extension)
            }
            return Object.freeze(extensions)
        } catch (error) {
            throw new SSHAgentProtocolError("SSH agent returned an invalid extension list", {
                cause: error,
            })
        }
    }

    destroy(error?: Error): void {
        this.stream.destroy(error)
    }

    async #passphraseRequest(
        type: SSHAgentMessageType.Lock | SSHAgentMessageType.Unlock,
        passphrase: string | Buffer,
    ): Promise<void> {
        const encoded = encodeOpaqueString(passphrase, "SSH agent lock passphrase")
        let payload: Buffer | undefined
        try {
            payload = Buffer.concat([Buffer.from([type]), serializeBuffer(encoded)])
            this.#expectSuccess(await this.#request(payload))
        } finally {
            encoded.fill(0)
            payload?.fill(0)
        }
    }

    #expectSuccess(response: Buffer): void {
        if (response.length !== 1 || response[0] !== SSHAgentMessageType.Success) {
            throw new SSHAgentProtocolError("SSH agent returned an unexpected success response")
        }
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
    #requestQueue: Promise<void> = Promise.resolve()
    #lockState: { salt: Buffer; verifier: Buffer } | undefined

    constructor(options: SSHAgentProtocolServerOptions = {}) {
        const { maxMessageLength } = validateOptions({ ...options, requestTimeout: 0 })
        this.options = Object.freeze({ maxMessageLength })
    }

    get locked(): boolean {
        return this.#lockState !== undefined
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
                const previous = buffered
                buffered = Buffer.concat([previous, chunk])
                previous.fill(0)
                while (buffered.length >= 4) {
                    const length = buffered.readUInt32BE(0)
                    if (length < 1 || length > this.options.maxMessageLength) {
                        throw new SSHAgentProtocolError("SSH agent request has an invalid length")
                    }
                    if (buffered.length < length + 4) break
                    const consumed = buffered
                    const payload = Buffer.from(consumed.subarray(4, length + 4))
                    buffered = Buffer.from(consumed.subarray(length + 4))
                    consumed.fill(0)
                    let response: Buffer | undefined
                    try {
                        response = await this.#orderedRequest(payload)
                        await writeFrame(stream, response, this.options.maxMessageLength)
                    } finally {
                        payload.fill(0)
                        response?.fill(0)
                    }
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
            buffered.fill(0)
            this.#activeStreams.delete(stream)
        }
    }

    #orderedRequest(payload: Buffer): Promise<Buffer> {
        const operation = this.#requestQueue.then(() => this.#handleRequest(payload))
        this.#requestQueue = operation.then(
            () => undefined,
            () => undefined,
        )
        return operation
    }

    async #handleRequest(payload: Buffer): Promise<Buffer> {
        const type = payload[0] as SSHAgentMessageType
        if (
            this.locked &&
            (type === SSHAgentMessageType.SignRequest ||
                type === SSHAgentMessageType.AddIdentity ||
                type === SSHAgentMessageType.AddConstrainedIdentity ||
                type === SSHAgentMessageType.AddToken ||
                type === SSHAgentMessageType.AddConstrainedToken ||
                type === SSHAgentMessageType.Extension)
        ) {
            return this.#failure()
        }
        try {
            switch (type) {
                case SSHAgentMessageType.RequestIdentities:
                    return payload.length === 1 ? await this.#handleIdentities() : this.#failure()
                case SSHAgentMessageType.SignRequest:
                    return await this.#handleSign(payload)
                case SSHAgentMessageType.AddIdentity:
                    return await this.#handleAddIdentity(payload, false)
                case SSHAgentMessageType.AddConstrainedIdentity:
                    return await this.#handleAddIdentity(payload, true)
                case SSHAgentMessageType.AddToken:
                    return await this.#handleAddToken(payload, false)
                case SSHAgentMessageType.AddConstrainedToken:
                    return await this.#handleAddToken(payload, true)
                case SSHAgentMessageType.RemoveIdentity:
                    return await this.#handleRemoveIdentity(payload)
                case SSHAgentMessageType.RemoveAllIdentities:
                    return payload.length === 1
                        ? await this.#handleRemoveAllIdentities()
                        : this.#failure()
                case SSHAgentMessageType.RemoveToken:
                    return await this.#handleRemoveToken(payload)
                case SSHAgentMessageType.Lock:
                    return await this.#handleLock(payload)
                case SSHAgentMessageType.Unlock:
                    return await this.#handleUnlock(payload)
                case SSHAgentMessageType.Extension:
                    return await this.#handleExtension(payload)
                default:
                    return this.#failure()
            }
        } catch {
            return this.#failure()
        }
    }

    async #handleIdentities(): Promise<Buffer> {
        const controller: SSHAgentServerIdentitiesController = { identities: undefined }
        await this.hooker.triggerHook("identities", controller)
        if (controller.identities === undefined) return this.#failure()
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
    }

    async #handleSign(payload: Buffer): Promise<Buffer> {
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
    }

    async #handleAddIdentity(payload: Buffer, constrained: boolean): Promise<Buffer> {
        const context = parsePrivateKeyRequest(payload, constrained)
        const controller: SSHAgentServerSuccessController = { success: undefined }
        await this.hooker.triggerHook("addIdentity", context, controller)
        return controller.success === true ? this.#success() : this.#failure()
    }

    async #handleAddToken(payload: Buffer, constrained: boolean): Promise<Buffer> {
        let raw = payload.subarray(1)
        const [tokenId, afterTokenId] = readNextBuffer(raw)
        const [pin, afterPin] = readNextBuffer(afterTokenId)
        raw = afterPin
        const constraints = constrained ? parseConstraints(raw) : Object.freeze([])
        if (!constrained && raw.length !== 0) throw new Error("trailing data")
        const pinCopy = Buffer.from(pin)
        const context: SSHAgentServerAddTokenContext = Object.freeze({
            tokenId: Buffer.from(tokenId),
            pin: pinCopy,
            constraints,
        })
        const controller: SSHAgentServerSuccessController = { success: undefined }
        try {
            await this.hooker.triggerHook("addToken", context, controller)
            return controller.success === true ? this.#success() : this.#failure()
        } finally {
            pinCopy.fill(0)
        }
    }

    async #handleRemoveIdentity(payload: Buffer): Promise<Buffer> {
        const keyBlob = parseExactString(payload.subarray(1))
        const context: SSHAgentServerRemoveIdentityContext = Object.freeze({
            publicKey: PublicKey.parse(keyBlob),
        })
        const controller: SSHAgentServerSuccessController = { success: undefined }
        await this.hooker.triggerHook("removeIdentity", context, controller)
        return controller.success === true ? this.#success() : this.#failure()
    }

    async #handleRemoveAllIdentities(): Promise<Buffer> {
        const controller: SSHAgentServerSuccessController = { success: undefined }
        await this.hooker.triggerHook("removeAllIdentities", controller)
        return controller.success === true ? this.#success() : this.#failure()
    }

    async #handleRemoveToken(payload: Buffer): Promise<Buffer> {
        let raw = payload.subarray(1)
        const [encodedTokenId, afterTokenId] = readNextBuffer(raw)
        const [pin, afterPin] = readNextBuffer(afterTokenId)
        raw = afterPin
        if (raw.length !== 0) throw new Error("trailing data")
        const tokenId = decodeSSHUTF8(encodedTokenId, "SSH agent token identifier")
        decodeSSHUTF8(pin, "SSH agent token PIN")
        const pinCopy = Buffer.from(pin)
        const context: SSHAgentServerRemoveTokenContext = Object.freeze({ tokenId, pin: pinCopy })
        const controller: SSHAgentServerSuccessController = { success: undefined }
        try {
            await this.hooker.triggerHook("removeToken", context, controller)
            return controller.success === true ? this.#success() : this.#failure()
        } finally {
            pinCopy.fill(0)
        }
    }

    async #handleLock(payload: Buffer): Promise<Buffer> {
        const passphrase = Buffer.from(parseExactString(payload.subarray(1)))
        const hookPassphrase = Buffer.from(passphrase)
        try {
            if (this.locked) return this.#failure()
            const context: SSHAgentServerPassphraseContext = Object.freeze({
                passphrase: hookPassphrase,
            })
            const controller: SSHAgentServerSuccessController = { success: undefined }
            await this.hooker.triggerHook("lock", context, controller)
            if (controller.success !== true) return this.#failure()
            const salt = randomBytes(16)
            let verifier: Buffer
            try {
                verifier = await deriveLockVerifier(passphrase, salt)
            } catch (error) {
                salt.fill(0)
                throw error
            }
            this.#lockState = { salt, verifier }
            return this.#success()
        } finally {
            hookPassphrase.fill(0)
            passphrase.fill(0)
        }
    }

    async #handleUnlock(payload: Buffer): Promise<Buffer> {
        const passphrase = Buffer.from(parseExactString(payload.subarray(1)))
        const hookPassphrase = Buffer.from(passphrase)
        try {
            const state = this.#lockState
            if (!state) return this.#failure()
            const candidate = await deriveLockVerifier(passphrase, state.salt)
            const matches = timingSafeEqual(candidate, state.verifier)
            candidate.fill(0)
            if (!matches) return this.#failure()
            const context: SSHAgentServerPassphraseContext = Object.freeze({
                passphrase: hookPassphrase,
            })
            const controller: SSHAgentServerSuccessController = { success: undefined }
            await this.hooker.triggerHook("unlock", context, controller)
            if (controller.success !== true) return this.#failure()
            state.salt.fill(0)
            state.verifier.fill(0)
            this.#lockState = undefined
            return this.#success()
        } finally {
            hookPassphrase.fill(0)
            passphrase.fill(0)
        }
    }

    async #handleExtension(payload: Buffer): Promise<Buffer> {
        let raw = payload.subarray(1)
        const [encodedType, afterType] = readNextBuffer(raw)
        raw = afterType
        const type = decodeSSHUTF8(encodedType, "SSH agent extension type")
        if (type.length === 0) throw new Error("empty extension type")
        if (type === "query" && raw.length === 0) return this.#handleQueryExtensions()
        const context: SSHAgentServerExtensionContext = Object.freeze({
            type,
            contents: Buffer.from(raw),
        })
        const controller: SSHAgentServerExtensionController = { result: undefined }
        await this.hooker.triggerHook("extension", context, controller)
        const result = controller.result
        if (result === undefined) return this.#failure()
        if (result.kind === "failure") {
            return Buffer.from([SSHAgentMessageType.ExtensionFailure])
        }
        if (result.kind === "success") return this.#success()
        if (result.kind !== "response" || !Buffer.isBuffer(result.contents)) {
            return Buffer.from([SSHAgentMessageType.ExtensionFailure])
        }
        return this.#boundedResponse(
            Buffer.concat([
                Buffer.from([SSHAgentMessageType.ExtensionResponse]),
                serializeBuffer(encodeSSHUTF8(type, "SSH agent extension response type")),
                Buffer.from(result.contents),
            ]),
            SSHAgentMessageType.ExtensionFailure,
        )
    }

    async #handleQueryExtensions(): Promise<Buffer> {
        const controller: SSHAgentServerQueryExtensionsController = { extensions: undefined }
        await this.hooker.triggerHook("queryExtensions", controller)
        if (controller.extensions === undefined) return this.#failure()
        if (!Array.isArray(controller.extensions)) return this.#failure()
        const seen = new Set<string>()
        const extensions = controller.extensions.map((extension) => {
            const encoded = encodeSSHUTF8(extension, "SSH agent supported extension type")
            if (encoded.length === 0 || seen.has(extension)) {
                throw new Error("invalid supported extension type")
            }
            seen.add(extension)
            return serializeBuffer(encoded)
        })
        return this.#boundedResponse(
            Buffer.concat([
                Buffer.from([SSHAgentMessageType.ExtensionResponse]),
                serializeBuffer(Buffer.from("query", "ascii")),
                ...extensions,
            ]),
        )
    }

    #failure(): Buffer {
        return Buffer.from([SSHAgentMessageType.Failure])
    }

    #success(): Buffer {
        return Buffer.from([SSHAgentMessageType.Success])
    }

    #boundedResponse(
        payload: Buffer,
        failureType:
            | SSHAgentMessageType.Failure
            | SSHAgentMessageType.ExtensionFailure = SSHAgentMessageType.Failure,
    ): Buffer {
        if (payload.length <= this.options.maxMessageLength) return payload
        payload.fill(0)
        return Buffer.from([failureType])
    }
}

export class SSHAgentProtocolError extends AgentError {
    name = "SSHAgentProtocolError"
}

export class SSHAgentExtensionFailureError extends SSHAgentProtocolError {
    name = "SSHAgentExtensionFailureError"
}
