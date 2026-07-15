import type ClientSessionChannel from "../channels/ClientSessionChannel.js"
import {
    encodePublicKeySubsystemPacket,
    MAX_PUBLIC_KEY_SUBSYSTEM_RESPONSES,
    MAX_PUBLIC_KEY_SUBSYSTEM_RESPONSE_BYTES,
    PUBLIC_KEY_SUBSYSTEM_VERSION,
    PublicKeySubsystemPacketParser,
    PublicKeySubsystemProtocolError,
    PublicKeySubsystemStatusCode,
    validatePublicKeySubsystemAttributes,
    type PublicKeySubsystemAddAttribute,
    type PublicKeySubsystemPacket,
} from "./PublicKeySubsystemCodec.js"
import PublicKey from "../utils/PublicKey.js"
import { encodeSSHName } from "../utils/SSHName.js"
import { encodeSSHUTF8 } from "../utils/SSHText.js"

export interface PublicKeySubsystemAttributeInput {
    readonly name: string
    readonly value: string | Buffer
    readonly critical?: boolean
}

export interface PublicKeySubsystemAddOptions {
    readonly overwrite?: boolean
    readonly attributes?: readonly PublicKeySubsystemAttributeInput[]
}

export interface PublicKeySubsystemClientOptions {
    /** Maximum milliseconds for subsystem initialization or a serialized request reply. */
    requestTimeout?: number
}

export interface PublicKeySubsystemListedAttribute {
    readonly name: string
    readonly value: Buffer
}

export interface PublicKeySubsystemKey {
    readonly key: PublicKey
    readonly attributes: readonly PublicKeySubsystemListedAttribute[]
}

export interface PublicKeySubsystemSupportedAttribute {
    readonly name: string
    readonly compulsory: boolean
}

export class PublicKeySubsystemStatusError extends Error {
    readonly code: number
    readonly languageTag: string

    constructor(code: number, description: string, languageTag: string) {
        super(description || `Public-key subsystem status ${code}`)
        this.name = "PublicKeySubsystemStatusError"
        this.code = code
        this.languageTag = languageTag
    }
}

interface PendingRequest {
    readonly expectedTypes: ReadonlySet<PublicKeySubsystemPacket["type"]>
    readonly responses: PublicKeySubsystemPacket[]
    responseBytes: number
    readonly resolve: (responses: readonly PublicKeySubsystemPacket[]) => void
    readonly reject: (error: Error) => void
}

export default class PublicKeySubsystemClient {
    readonly protocolVersion = PUBLIC_KEY_SUBSYSTEM_VERSION
    readonly channel: ClientSessionChannel
    readonly requestTimeout: number

    private readonly parser = new PublicKeySubsystemPacketParser()
    private initialized = false
    private closed = false
    private readyResolve!: () => void
    private readyReject!: (error: Error) => void
    private readonly ready: Promise<void>
    private pending: PendingRequest | undefined
    private operationTail: Promise<void> = Promise.resolve()

    private constructor(channel: ClientSessionChannel, options: PublicKeySubsystemClientOptions) {
        this.channel = channel
        this.requestTimeout = options.requestTimeout ?? 30_000
        if (!Number.isFinite(this.requestTimeout) || this.requestTimeout <= 0) {
            throw new RangeError("Public-key subsystem request timeout must be a positive number")
        }
        this.ready = new Promise<void>((resolve, reject) => {
            this.readyResolve = resolve
            this.readyReject = reject
        })
        channel.on("data", (data: Buffer) => this.receive(data))
        channel.once("end", () => this.handleEnd())
        channel.once("close", () => this.handleEnd())
        channel.once("error", (error) => this.fail(error))
    }

    static async connect(
        channel: ClientSessionChannel,
        options: PublicKeySubsystemClientOptions = {},
    ): Promise<PublicKeySubsystemClient> {
        const client = new PublicKeySubsystemClient(channel, { ...options })
        try {
            await client.waitForResponse(
                Promise.all([
                    client.writePacket({
                        type: "version",
                        version: PUBLIC_KEY_SUBSYSTEM_VERSION,
                    }),
                    client.ready,
                ]).then(() => undefined),
                "initialization",
            )
            return client
        } catch (error) {
            if (!client.closed) {
                client.destroy(error instanceof Error ? error : new Error(String(error)))
            }
            throw error
        }
    }

    add(key: PublicKey, options: PublicKeySubsystemAddOptions = {}): Promise<void> {
        if (!(key instanceof PublicKey)) {
            return Promise.reject(new TypeError("Public-key subsystem add requires a public key"))
        }
        let packet: Extract<PublicKeySubsystemPacket, { type: "add" }>
        try {
            if (options.overwrite !== undefined && typeof options.overwrite !== "boolean") {
                throw new TypeError("Public-key subsystem overwrite must be a boolean")
            }
            if (options.attributes !== undefined && !Array.isArray(options.attributes)) {
                throw new TypeError("Public-key subsystem attributes must be an array")
            }
            const attributes: PublicKeySubsystemAddAttribute[] = (options.attributes ?? []).map(
                (attribute) => {
                    if (!attribute || typeof attribute.name !== "string") {
                        throw new TypeError("Public-key subsystem attribute name must be a string")
                    }
                    encodeSSHName(attribute.name, "Public-key subsystem attribute name")
                    if (typeof attribute.value !== "string" && !Buffer.isBuffer(attribute.value)) {
                        throw new TypeError(
                            "Public-key subsystem attribute value must be text or a buffer",
                        )
                    }
                    if (
                        attribute.critical !== undefined &&
                        typeof attribute.critical !== "boolean"
                    ) {
                        throw new TypeError(
                            "Public-key subsystem critical attribute flag must be a boolean",
                        )
                    }
                    return {
                        name: attribute.name,
                        value: Buffer.isBuffer(attribute.value)
                            ? Buffer.from(attribute.value)
                            : encodeSSHUTF8(
                                  attribute.value,
                                  "Public-key subsystem attribute value",
                              ),
                        critical: attribute.critical ?? false,
                    }
                },
            )
            validatePublicKeySubsystemAttributes(attributes)
            packet = {
                type: "add",
                algorithm: key.data.alg,
                keyBlob: key.serialize(),
                overwrite: options.overwrite ?? false,
                attributes,
            }
        } catch (error) {
            return Promise.reject(error as Error)
        }
        return this.enqueue(async () => {
            await this.request(packet)
        })
    }

    remove(key: PublicKey): Promise<void> {
        if (!(key instanceof PublicKey)) {
            return Promise.reject(
                new TypeError("Public-key subsystem remove requires a public key"),
            )
        }
        const packet = {
            type: "remove" as const,
            algorithm: key.data.alg,
            keyBlob: key.serialize(),
        }
        return this.enqueue(async () => {
            await this.request(packet)
        })
    }

    list(): Promise<readonly PublicKeySubsystemKey[]> {
        return this.enqueue(async () => {
            const responses = await this.request({ type: "list" }, "publickey")
            try {
                return responses.map((response) => {
                    if (response.type !== "publickey") {
                        throw new PublicKeySubsystemProtocolError(
                            `Unexpected public-key subsystem ${response.type} response`,
                        )
                    }
                    const key = PublicKey.parse(response.keyBlob)
                    if (key.data.alg !== response.algorithm) {
                        throw new PublicKeySubsystemProtocolError(
                            "Public-key subsystem key algorithm does not match its key blob",
                        )
                    }
                    validatePublicKeySubsystemAttributes(response.attributes)
                    return Object.freeze({
                        key,
                        attributes: Object.freeze(
                            response.attributes.map((attribute) =>
                                Object.freeze({
                                    name: attribute.name,
                                    value: Buffer.from(attribute.value),
                                }),
                            ),
                        ),
                    })
                })
            } catch (error) {
                const failure = error instanceof Error ? error : new Error(String(error))
                this.destroy(failure)
                throw failure
            }
        })
    }

    listAttributes(): Promise<readonly PublicKeySubsystemSupportedAttribute[]> {
        return this.enqueue(async () => {
            const responses = await this.request({ type: "listattributes" }, "attribute")
            return responses.map((response) => {
                if (response.type !== "attribute") {
                    throw new PublicKeySubsystemProtocolError(
                        `Unexpected public-key subsystem ${response.type} response`,
                    )
                }
                return Object.freeze({
                    name: response.name,
                    compulsory: response.compulsory,
                })
            })
        })
    }

    end(): void {
        if (!this.closed) this.channel.end()
    }

    destroy(error?: Error): void {
        if (!this.channel.destroyed) this.channel.destroy(error)
        this.fail(error ?? new Error("Public-key subsystem session closed"))
    }

    private writePacket(packet: PublicKeySubsystemPacket): Promise<void> {
        const frame = encodePublicKeySubsystemPacket(packet)
        return new Promise<void>((resolve, reject) => {
            this.channel.write(frame, (error) => (error ? reject(error) : resolve()))
        })
    }

    private enqueue<T>(operation: () => Promise<T>): Promise<T> {
        const result = this.operationTail.then(operation)
        this.operationTail = result.then(
            () => undefined,
            () => undefined,
        )
        return result
    }

    private request(
        packet: PublicKeySubsystemPacket,
        ...expectedTypes: PublicKeySubsystemPacket["type"][]
    ): Promise<readonly PublicKeySubsystemPacket[]> {
        if (!this.initialized) {
            return Promise.reject(new Error("Public-key subsystem client is not initialized"))
        }
        if (this.closed) return Promise.reject(new Error("Public-key subsystem session is closed"))
        if (this.pending) {
            return Promise.reject(
                new PublicKeySubsystemProtocolError(
                    "Public-key subsystem request acknowledgement is still pending",
                ),
            )
        }
        const response = new Promise<readonly PublicKeySubsystemPacket[]>((resolve, reject) => {
            this.pending = {
                expectedTypes: new Set(expectedTypes),
                responses: [],
                responseBytes: 0,
                resolve,
                reject,
            }
        })
        void this.writePacket(packet).catch((error: unknown) => {
            const pending = this.pending
            if (!pending) return
            this.pending = undefined
            pending.reject(error instanceof Error ? error : new Error(String(error)))
        })
        return this.waitForResponse(response, "request reply")
    }

    private async waitForResponse<T>(operation: Promise<T>, description: string): Promise<T> {
        let timer: NodeJS.Timeout | undefined
        const timeout = new Promise<never>((_resolve, reject) => {
            timer = setTimeout(() => {
                const error = new Error(`Timed out waiting for public-key subsystem ${description}`)
                reject(error)
                this.destroy(error)
            }, this.requestTimeout)
            timer.unref()
        })
        try {
            return await Promise.race([operation, timeout])
        } finally {
            if (timer !== undefined) clearTimeout(timer)
        }
    }

    private receive(data: Buffer): void {
        try {
            for (const packet of this.parser.push(data)) this.receivePacket(packet)
        } catch (error) {
            const protocolError = error instanceof Error ? error : new Error(String(error))
            this.fail(protocolError)
            this.channel.destroy(protocolError)
        }
    }

    private receivePacket(packet: PublicKeySubsystemPacket): void {
        if (!this.initialized) {
            if (packet.type !== "version") {
                throw new PublicKeySubsystemProtocolError(
                    "Expected public-key subsystem version packet",
                )
            }
            if (Math.min(packet.version, PUBLIC_KEY_SUBSYSTEM_VERSION) !== this.protocolVersion) {
                const error = new PublicKeySubsystemProtocolError(
                    `Unsupported public-key subsystem version ${packet.version}`,
                )
                this.fail(error)
                void this.writePacket({
                    type: "status",
                    code: PublicKeySubsystemStatusCode.VersionNotSupported,
                    description: error.message,
                    languageTag: "",
                }).then(
                    () => this.channel.destroy(),
                    (writeError: unknown) =>
                        this.channel.destroy(
                            writeError instanceof Error
                                ? writeError
                                : new Error(String(writeError)),
                        ),
                )
                return
            }
            this.initialized = true
            this.readyResolve()
            return
        }
        if (packet.type === "version") {
            throw new PublicKeySubsystemProtocolError(
                "Received duplicate public-key subsystem version packet",
            )
        }
        const pending = this.pending
        if (!pending) {
            throw new PublicKeySubsystemProtocolError(
                `Unexpected public-key subsystem ${packet.type} response`,
            )
        }
        if (packet.type === "status") {
            this.pending = undefined
            if (packet.code === PublicKeySubsystemStatusCode.Success) {
                pending.resolve(pending.responses)
            } else {
                pending.reject(
                    new PublicKeySubsystemStatusError(
                        packet.code,
                        packet.description,
                        packet.languageTag,
                    ),
                )
            }
            return
        }
        if (!pending.expectedTypes.has(packet.type)) {
            throw new PublicKeySubsystemProtocolError(
                `Unexpected public-key subsystem ${packet.type} response`,
            )
        }
        const responseLength = encodePublicKeySubsystemPacket(packet).length
        if (
            pending.responses.length >= MAX_PUBLIC_KEY_SUBSYSTEM_RESPONSES ||
            pending.responseBytes + responseLength > MAX_PUBLIC_KEY_SUBSYSTEM_RESPONSE_BYTES
        ) {
            throw new PublicKeySubsystemProtocolError(
                "Public-key subsystem response exceeds the collection limit",
            )
        }
        pending.responseBytes += responseLength
        pending.responses.push(packet)
    }

    private handleEnd(): void {
        if (this.closed) return
        try {
            this.parser.end()
        } catch (error) {
            this.destroy(error instanceof Error ? error : new Error(String(error)))
            return
        }
        this.fail(new Error("Public-key subsystem channel closed"))
    }

    private fail(error: Error): void {
        if (this.closed) return
        this.closed = true
        if (!this.initialized) this.readyReject(error)
        this.pending?.reject(error)
        this.pending = undefined
    }
}
