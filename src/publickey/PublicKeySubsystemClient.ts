import type ClientSessionChannel from "../channels/ClientSessionChannel.js"
import {
    encodePublicKeySubsystemPacket,
    MAX_PUBLIC_KEY_SUBSYSTEM_RESPONSES,
    MAX_PUBLIC_KEY_SUBSYSTEM_RESPONSE_BYTES,
    MIN_PUBLIC_KEY_SUBSYSTEM_VERSION,
    PUBLIC_KEY_SUBSYSTEM_VERSION,
    publicKeySubsystemNamespace,
    PublicKeySubsystemPacketParser,
    PublicKeySubsystemProtocolError,
    PublicKeySubsystemStatusCode,
    validatePublicKeySubsystemNamespace,
    validatePublicKeySubsystemAttributes,
    type PublicKeySubsystemAddAttribute,
    type PublicKeySubsystemListedAttribute as PublicKeySubsystemCodecListedAttribute,
    type PublicKeySubsystemPacket,
} from "./PublicKeySubsystemCodec.js"
import PublicKey from "../utils/PublicKey.js"
import { encodeSSHName } from "../utils/SSHName.js"
import { encodeSSHUTF8 } from "../utils/SSHText.js"
import { isPlainConfigurationObject } from "../utils/Configuration.js"

export interface PublicKeySubsystemAttributeInput {
    readonly name: string
    readonly value: string | Buffer
    readonly critical?: boolean
}

export interface PublicKeySubsystemAddOptions {
    readonly overwrite?: boolean
    readonly namespace?: string
    readonly attributes?: readonly PublicKeySubsystemAttributeInput[]
}

export interface PublicKeySubsystemRequestOptions {
    readonly namespace?: string
    readonly attributes?: readonly PublicKeySubsystemAttributeInput[]
}

export interface PublicKeySubsystemAddCertificateOptions extends PublicKeySubsystemAddOptions {
    readonly namespace: string
}

export interface PublicKeySubsystemRemoveCertificateOptions
    extends PublicKeySubsystemRequestOptions {
    readonly namespace: string
}

export interface PublicKeySubsystemClientOptions {
    /** Maximum milliseconds for subsystem initialization or a serialized request reply. */
    requestTimeout?: number
}

export function normalizePublicKeySubsystemClientOptions(
    options: PublicKeySubsystemClientOptions,
    defaultRequestTimeout = 30_000,
): Readonly<Required<PublicKeySubsystemClientOptions>> {
    if (!isPlainConfigurationObject(options)) {
        throw new TypeError("Public-key subsystem client options must be an object")
    }
    const requestTimeout =
        options.requestTimeout === undefined ? defaultRequestTimeout : options.requestTimeout
    if (!Number.isFinite(requestTimeout) || requestTimeout <= 0) {
        throw new RangeError("Public-key subsystem request timeout must be a positive number")
    }
    return Object.freeze({ requestTimeout })
}

export interface PublicKeySubsystemListedAttribute {
    readonly name: string
    readonly value: Buffer
}

export interface PublicKeySubsystemKey {
    readonly key: PublicKey
    readonly namespace?: string
    readonly attributes: readonly PublicKeySubsystemListedAttribute[]
}

export interface PublicKeySubsystemCertificate {
    readonly format: string
    readonly certificate: Buffer
    readonly namespace: string
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

function normalizeRequestAttributes(
    options: PublicKeySubsystemRequestOptions,
    operation: string,
): readonly PublicKeySubsystemAddAttribute[] {
    if (!isPlainConfigurationObject(options)) {
        throw new TypeError(`Public-key subsystem ${operation} options must be an object`)
    }
    if (options.namespace !== undefined && typeof options.namespace !== "string") {
        throw new TypeError("Public-key subsystem namespace must be a string")
    }
    if (options.attributes !== undefined && !Array.isArray(options.attributes)) {
        throw new TypeError("Public-key subsystem attributes must be an array")
    }
    const configuredAttributes = options.attributes === undefined ? [] : options.attributes
    const attributes: PublicKeySubsystemAddAttribute[] = configuredAttributes.map((attribute) => {
        if (!isPlainConfigurationObject(attribute)) {
            throw new TypeError("Public-key subsystem attribute must be an object")
        }
        if (typeof attribute.name !== "string") {
            throw new TypeError("Public-key subsystem attribute name must be a string")
        }
        encodeSSHName(attribute.name, "Public-key subsystem attribute name")
        if (typeof attribute.value !== "string" && !Buffer.isBuffer(attribute.value)) {
            throw new TypeError("Public-key subsystem attribute value must be text or a buffer")
        }
        if (attribute.critical !== undefined && typeof attribute.critical !== "boolean") {
            throw new TypeError("Public-key subsystem critical attribute flag must be a boolean")
        }
        return {
            name: attribute.name,
            value: Buffer.isBuffer(attribute.value)
                ? Buffer.from(attribute.value)
                : encodeSSHUTF8(attribute.value, "Public-key subsystem attribute value"),
            critical: attribute.critical === undefined ? false : attribute.critical,
        }
    })
    if (options.namespace !== undefined) {
        validatePublicKeySubsystemNamespace(options.namespace)
        attributes.unshift({
            name: "namespace",
            value: encodeSSHUTF8(options.namespace, "Public-key subsystem namespace"),
            critical: true,
        })
    }
    validatePublicKeySubsystemAttributes(attributes)
    publicKeySubsystemNamespace(attributes)
    return attributes
}

function normalizeListedRequestAttributes(
    options: PublicKeySubsystemRemoveCertificateOptions,
    operation: string,
): readonly PublicKeySubsystemCodecListedAttribute[] {
    if (
        Array.isArray(options?.attributes) &&
        options.attributes.some(
            (attribute) =>
                isPlainConfigurationObject(attribute) && attribute.critical !== undefined,
        )
    ) {
        throw new TypeError(
            `Public-key subsystem ${operation} attributes do not carry critical flags`,
        )
    }
    const attributes = normalizeRequestAttributes(options, operation)
    publicKeySubsystemNamespace(attributes, true)
    return attributes.map(({ name, value }) => ({ name, value }))
}

export default class PublicKeySubsystemClient {
    readonly protocolVersion = PUBLIC_KEY_SUBSYSTEM_VERSION
    readonly channel: ClientSessionChannel
    readonly requestTimeout: number

    private readonly parser = new PublicKeySubsystemPacketParser()
    #negotiatedProtocolVersion: number | undefined
    private initialized = false
    private closed = false
    private readyResolve!: () => void
    private readyReject!: (error: Error) => void
    private readonly ready: Promise<void>
    private pending: PendingRequest | undefined
    private operationTail: Promise<void> = Promise.resolve()

    get negotiatedProtocolVersion(): number | undefined {
        return this.#negotiatedProtocolVersion
    }

    private constructor(channel: ClientSessionChannel, options: PublicKeySubsystemClientOptions) {
        this.channel = channel
        this.requestTimeout = options.requestTimeout!
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
        const client = new PublicKeySubsystemClient(
            channel,
            normalizePublicKeySubsystemClientOptions(options),
        )
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
            const attributes = normalizeRequestAttributes(options, "add")
            if (options.overwrite !== undefined && typeof options.overwrite !== "boolean") {
                throw new TypeError("Public-key subsystem overwrite must be a boolean")
            }
            if (
                publicKeySubsystemNamespace(attributes) !== undefined &&
                this.negotiatedProtocolVersion! < 3
            ) {
                throw new Error("Public-key subsystem namespaces require protocol version 3")
            }
            packet = {
                type: "add",
                algorithm: key.data.alg,
                keyBlob: key.serialize(),
                overwrite: options.overwrite === undefined ? false : options.overwrite,
                attributes,
            }
        } catch (error) {
            return Promise.reject(error as Error)
        }
        return this.enqueue(async () => {
            await this.request(packet)
        })
    }

    remove(key: PublicKey, options: PublicKeySubsystemRequestOptions = {}): Promise<void> {
        if (!(key instanceof PublicKey)) {
            return Promise.reject(
                new TypeError("Public-key subsystem remove requires a public key"),
            )
        }
        let attributes: readonly PublicKeySubsystemAddAttribute[]
        try {
            attributes = normalizeRequestAttributes(options, "remove")
            if (attributes.length > 0 && this.negotiatedProtocolVersion! < 3) {
                throw new Error(
                    publicKeySubsystemNamespace(attributes) === undefined
                        ? "Public-key subsystem remove attributes require protocol version 3"
                        : "Public-key subsystem namespaces require protocol version 3",
                )
            }
        } catch (error) {
            return Promise.reject(error as Error)
        }
        const packet = {
            type: "remove" as const,
            algorithm: key.data.alg,
            keyBlob: key.serialize(),
            ...(this.negotiatedProtocolVersion! >= 3 ? { attributes } : {}),
        }
        return this.enqueue(async () => {
            await this.request(packet)
        })
    }

    list(
        options: PublicKeySubsystemRequestOptions = {},
    ): Promise<readonly PublicKeySubsystemKey[]> {
        let attributes: readonly PublicKeySubsystemAddAttribute[]
        try {
            attributes = normalizeRequestAttributes(options, "list")
            if (attributes.length > 0 && this.negotiatedProtocolVersion! < 3) {
                throw new Error(
                    publicKeySubsystemNamespace(attributes) === undefined
                        ? "Public-key subsystem list attributes require protocol version 3"
                        : "Public-key subsystem namespaces require protocol version 3",
                )
            }
        } catch (error) {
            return Promise.reject(error as Error)
        }
        return this.enqueue(async () => {
            const responses = await this.request(
                {
                    type: "list",
                    ...(this.negotiatedProtocolVersion! >= 3 ? { attributes } : {}),
                },
                "publickey",
            )
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
                    const namespace =
                        this.negotiatedProtocolVersion! >= 3
                            ? (publicKeySubsystemNamespace(response.attributes) ?? "ssh")
                            : undefined
                    return Object.freeze({
                        key,
                        ...(namespace === undefined ? {} : { namespace }),
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

    addCertificate(
        format: string,
        certificate: Buffer,
        options: PublicKeySubsystemAddCertificateOptions,
    ): Promise<void> {
        let packet: Extract<PublicKeySubsystemPacket, { type: "add-certificate" }>
        try {
            this.requireVersion3(
                "Public-key subsystem certificate operations require protocol version 3",
            )
            if (typeof format !== "string") {
                throw new TypeError("Public-key subsystem certificate format must be a string")
            }
            encodeSSHName(format, "Public-key subsystem certificate format")
            if (!Buffer.isBuffer(certificate)) {
                throw new TypeError("Public-key subsystem certificate must be a buffer")
            }
            const attributes = normalizeRequestAttributes(options, "add-certificate")
            publicKeySubsystemNamespace(attributes, true)
            if (options.overwrite !== undefined && typeof options.overwrite !== "boolean") {
                throw new TypeError("Public-key subsystem overwrite must be a boolean")
            }
            packet = {
                type: "add-certificate",
                format,
                certificateBlob: Buffer.from(certificate),
                overwrite: options.overwrite === undefined ? false : options.overwrite,
                attributes,
            }
        } catch (error) {
            return Promise.reject(error as Error)
        }
        return this.enqueue(async () => {
            await this.request(packet)
        })
    }

    removeCertificate(
        format: string,
        certificate: Buffer,
        options: PublicKeySubsystemRemoveCertificateOptions,
    ): Promise<void> {
        let packet: Extract<PublicKeySubsystemPacket, { type: "remove-certificate" }>
        try {
            this.requireVersion3(
                "Public-key subsystem certificate operations require protocol version 3",
            )
            if (typeof format !== "string") {
                throw new TypeError("Public-key subsystem certificate format must be a string")
            }
            encodeSSHName(format, "Public-key subsystem certificate format")
            if (!Buffer.isBuffer(certificate)) {
                throw new TypeError("Public-key subsystem certificate must be a buffer")
            }
            packet = {
                type: "remove-certificate",
                format,
                certificateBlob: Buffer.from(certificate),
                attributes: normalizeListedRequestAttributes(options, "remove-certificate"),
            }
        } catch (error) {
            return Promise.reject(error as Error)
        }
        return this.enqueue(async () => {
            await this.request(packet)
        })
    }

    listCertificates(): Promise<readonly PublicKeySubsystemCertificate[]> {
        try {
            this.requireVersion3(
                "Public-key subsystem certificate operations require protocol version 3",
            )
        } catch (error) {
            return Promise.reject(error as Error)
        }
        return this.enqueue(async () => {
            const responses = await this.request({ type: "list-certificates" }, "certificate")
            try {
                return responses.map((response) => {
                    if (response.type !== "certificate") {
                        throw new PublicKeySubsystemProtocolError(
                            `Unexpected public-key subsystem ${response.type} response`,
                        )
                    }
                    validatePublicKeySubsystemAttributes(response.attributes)
                    const namespace = publicKeySubsystemNamespace(response.attributes, true)!
                    return Object.freeze({
                        format: response.format,
                        certificate: Buffer.from(response.certificateBlob),
                        namespace,
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

    listNamespaces(): Promise<readonly string[]> {
        try {
            this.requireVersion3(
                "Public-key subsystem namespace listing requires protocol version 3",
            )
        } catch (error) {
            return Promise.reject(error as Error)
        }
        return this.enqueue(async () => {
            const responses = await this.request({ type: "list-namespaces" }, "namespace")
            try {
                return responses.map((response) => {
                    if (response.type !== "namespace") {
                        throw new PublicKeySubsystemProtocolError(
                            `Unexpected public-key subsystem ${response.type} response`,
                        )
                    }
                    validatePublicKeySubsystemNamespace(response.name)
                    return response.name
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

    private requireVersion3(message: string): void {
        if (this.negotiatedProtocolVersion! < 3) {
            throw new Error(message)
        }
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
            const negotiatedVersion = Math.min(packet.version, PUBLIC_KEY_SUBSYSTEM_VERSION)
            if (negotiatedVersion < MIN_PUBLIC_KEY_SUBSYSTEM_VERSION) {
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
            this.#negotiatedProtocolVersion = negotiatedVersion
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
