import EventEmitter from "node:events"
import type Shell from "../channels/Session/Shell.js"
import { Hooker } from "../utils/Hooker.js"
import PublicKey from "../utils/PublicKey.js"
import { isPlainConfigurationObject } from "../utils/Configuration.js"
import { encodeSSHName } from "../utils/SSHName.js"
import { encodeSSHUTF8 } from "../utils/SSHText.js"
import { closeStream, normalizeStreamCloseTimeout } from "../utils/StreamClose.js"
import { DEFAULT_OPERATION_TIMEOUT, normalizeTimeout, waitWithTimeout } from "../utils/Timeout.js"
import { makePromise } from "../utils/promise.js"
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
    validatePublicKeySubsystemAttributes,
    validatePublicKeySubsystemNamespace,
    type PublicKeySubsystemAddAttribute,
    type PublicKeySubsystemPacket,
    type PublicKeySubsystemListedAttribute,
    type PublicKeySubsystemPublicKeyPacket,
} from "./PublicKeySubsystemCodec.js"

export interface PublicKeySubsystemSupportedAttribute {
    readonly name: string
    readonly compulsory?: boolean
}

export interface PublicKeySubsystemServerOptions {
    readonly attributes?: readonly PublicKeySubsystemSupportedAttribute[]
    /** Integer milliseconds to wait for close. Defaults to 30000; range: 1 through 2147483647. */
    readonly closeTimeout?: number
    /**
     * Integer milliseconds for initialization, policy, and response writes.
     * Defaults to 30000; range: 1 through 2147483647.
     */
    readonly requestTimeout?: number
}

export interface PublicKeySubsystemServerOperationContext {
    /** Aborted when this request expires or its subsystem channel closes. */
    readonly signal: AbortSignal
}

export interface PublicKeySubsystemServerAddContext {
    readonly key: PublicKey
    readonly overwrite: boolean
    readonly attributes: readonly PublicKeySubsystemAddAttribute[]
    readonly namespace?: string
}

export interface PublicKeySubsystemServerResponseController {
    success: boolean
    failureCode?: number
    description?: string
    languageTag?: string
}

export interface PublicKeySubsystemServerRemoveContext {
    readonly key: PublicKey
    readonly attributes: readonly PublicKeySubsystemAddAttribute[]
    readonly namespace?: string
}

export interface PublicKeySubsystemServerListedAttribute {
    readonly name: string
    readonly value: string | Buffer
}

export interface PublicKeySubsystemServerListedKey {
    readonly key: PublicKey
    readonly attributes?: readonly PublicKeySubsystemServerListedAttribute[]
}

export interface PublicKeySubsystemServerListController
    extends PublicKeySubsystemServerResponseController {
    keys?: readonly PublicKeySubsystemServerListedKey[]
}

export interface PublicKeySubsystemServerListContext {
    readonly attributes: readonly PublicKeySubsystemAddAttribute[]
    readonly namespace?: string
}

export interface PublicKeySubsystemServerAddCertificateContext {
    readonly format: string
    readonly certificate: Buffer
    readonly overwrite: boolean
    readonly namespace: string
    readonly attributes: readonly PublicKeySubsystemAddAttribute[]
}

export interface PublicKeySubsystemServerRemoveCertificateContext {
    readonly format: string
    readonly certificate: Buffer
    readonly namespace: string
    readonly attributes: readonly PublicKeySubsystemListedAttribute[]
}

export interface PublicKeySubsystemServerListedCertificate {
    readonly format: string
    readonly certificate: Buffer
    readonly namespace: string
    readonly attributes?: readonly PublicKeySubsystemServerListedAttribute[]
}

export interface PublicKeySubsystemServerListCertificatesController
    extends PublicKeySubsystemServerResponseController {
    certificates?: readonly PublicKeySubsystemServerListedCertificate[]
}

export interface PublicKeySubsystemServerListNamespacesController
    extends PublicKeySubsystemServerResponseController {
    namespaces?: readonly string[]
}

// eslint-disable-next-line @typescript-eslint/consistent-type-definitions
export type PublicKeySubsystemServerHooker = {
    add: [
        context: Readonly<PublicKeySubsystemServerAddContext>,
        controller: PublicKeySubsystemServerResponseController,
        operation: Readonly<PublicKeySubsystemServerOperationContext>,
    ]
    remove: [
        context: Readonly<PublicKeySubsystemServerRemoveContext>,
        controller: PublicKeySubsystemServerResponseController,
        operation: Readonly<PublicKeySubsystemServerOperationContext>,
    ]
    list: [
        controller: PublicKeySubsystemServerListController,
        context: Readonly<PublicKeySubsystemServerListContext>,
        operation: Readonly<PublicKeySubsystemServerOperationContext>,
    ]
    addCertificate: [
        context: Readonly<PublicKeySubsystemServerAddCertificateContext>,
        controller: PublicKeySubsystemServerResponseController,
        operation: Readonly<PublicKeySubsystemServerOperationContext>,
    ]
    removeCertificate: [
        context: Readonly<PublicKeySubsystemServerRemoveCertificateContext>,
        controller: PublicKeySubsystemServerResponseController,
        operation: Readonly<PublicKeySubsystemServerOperationContext>,
    ]
    listCertificates: [
        controller: PublicKeySubsystemServerListCertificatesController,
        operation: Readonly<PublicKeySubsystemServerOperationContext>,
    ]
    listNamespaces: [
        controller: PublicKeySubsystemServerListNamespacesController,
        operation: Readonly<PublicKeySubsystemServerOperationContext>,
    ]
}

// eslint-disable-next-line @typescript-eslint/consistent-type-definitions
export type PublicKeySubsystemServerEvents = {
    ready: [clientVersion: number]
    close: []
    error: [error: Error]
}

export default class PublicKeySubsystemServer extends EventEmitter<PublicKeySubsystemServerEvents> {
    readonly protocolVersion = PUBLIC_KEY_SUBSYSTEM_VERSION
    readonly stream: Shell
    readonly hooker = new Hooker<PublicKeySubsystemServerHooker>()
    readonly attributes: readonly Readonly<Required<PublicKeySubsystemSupportedAttribute>>[]

    private readonly parser = new PublicKeySubsystemPacketParser()
    readonly #closeTimeout: number
    readonly #requestTimeout: number
    #negotiatedProtocolVersion: number | undefined
    private readonly supportedAttributeNames: ReadonlySet<string>
    private initialized = false
    private closed = false
    private active: Exclude<PublicKeySubsystemPacket, { type: "version" }> | undefined
    private dispatchScheduled = false
    private hookError: Error | undefined
    private closePromise: Promise<void> | undefined
    private requestAbortController: AbortController | undefined

    get negotiatedProtocolVersion(): number | undefined {
        return this.#negotiatedProtocolVersion
    }

    constructor(stream: Shell, options: PublicKeySubsystemServerOptions = {}) {
        super()
        if (!isPlainConfigurationObject(options)) {
            throw new TypeError("Public-key subsystem server options must be an object")
        }
        if (options.attributes !== undefined && !Array.isArray(options.attributes)) {
            throw new TypeError("Public-key subsystem server attributes must be an array")
        }
        const attributes = options.attributes === undefined ? [] : options.attributes
        const normalizedAttributes = attributes.map((attribute) => {
            if (!isPlainConfigurationObject(attribute)) {
                throw new TypeError("Public-key subsystem supported attribute must be an object")
            }
            if (typeof attribute.name !== "string") {
                throw new TypeError(
                    "Public-key subsystem supported attribute name must be a string",
                )
            }
            if (attribute.compulsory !== undefined && typeof attribute.compulsory !== "boolean") {
                throw new TypeError(
                    "Public-key subsystem compulsory attribute flag must be a boolean",
                )
            }
            encodeSSHName(attribute.name, "Public-key subsystem supported attribute")
            return Object.freeze({
                name: attribute.name,
                compulsory: attribute.compulsory === undefined ? false : attribute.compulsory,
            })
        })
        if (!normalizedAttributes.some(({ name }) => name === "namespace")) {
            normalizedAttributes.push(Object.freeze({ name: "namespace", compulsory: false }))
        }
        this.stream = stream
        this.#closeTimeout = normalizeStreamCloseTimeout(
            options.closeTimeout,
            "Public-key subsystem server",
        )
        this.#requestTimeout = normalizeTimeout(
            options.requestTimeout,
            DEFAULT_OPERATION_TIMEOUT,
            "Public-key subsystem server request timeout",
        )
        this.attributes = Object.freeze(normalizedAttributes)
        this.supportedAttributeNames = new Set(this.attributes.map(({ name }) => name))
        this.hooker.on("uncaughtException", (_event, error) => {
            this.hookError = error
        })
        stream.on("data", (data: Buffer) => this.receive(data))
        stream.once("end", () => this.handleEnd())
        stream.once("close", () => this.handleEnd())
        stream.once("error", (error) => this.fail(error))
        void this.waitForRequest(
            this.writePacket({
                type: "version",
                version: PUBLIC_KEY_SUBSYSTEM_VERSION,
            }),
            "public-key subsystem server initialization response",
        ).catch((error: unknown) => {
            const failure = error instanceof Error ? error : new Error(String(error))
            this.destroy(failure)
        })
    }

    destroy(error?: Error): void {
        if (!this.stream.writableEnded) this.stream.end()
        if (!this.stream.destroyed) this.stream.destroy(error)
        this.fail(error ?? new Error("Public-key subsystem server session closed"))
    }

    /** Close the subsystem and settle after its SSH channel closes. */
    close(): Promise<void> {
        if (this.closePromise !== undefined) return this.closePromise
        const [closing, resolve, reject] = makePromise<void>()
        this.closePromise = closing
        this.finish()
        void closeStream(
            this.stream,
            this.#closeTimeout,
            "public-key subsystem server channel",
        ).then(resolve, reject)
        return closing
    }

    [Symbol.asyncDispose](): Promise<void> {
        return this.close()
    }

    private receive(data: Buffer): void {
        try {
            for (const packet of this.parser.push(data)) this.receivePacket(packet)
        } catch (error) {
            const failure = error instanceof Error ? error : new Error(String(error))
            this.destroy(failure)
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
                void this.writePacket({
                    type: "status",
                    code: PublicKeySubsystemStatusCode.VersionNotSupported,
                    description: error.message,
                    languageTag: "",
                }).then(
                    () => this.destroy(error),
                    (writeError: unknown) =>
                        this.destroy(
                            writeError instanceof Error
                                ? writeError
                                : new Error(String(writeError)),
                        ),
                )
                this.fail(error)
                return
            }
            this.#negotiatedProtocolVersion = negotiatedVersion
            this.initialized = true
            this.emit("ready", packet.version)
            return
        }
        if (packet.type === "version") {
            throw new PublicKeySubsystemProtocolError(
                "Received duplicate public-key subsystem version packet",
            )
        }
        if (this.active) {
            throw new PublicKeySubsystemProtocolError(
                "Public-key subsystem client sent a request before acknowledgement",
            )
        }
        const version3Request =
            packet.type === "add-certificate" ||
            packet.type === "remove-certificate" ||
            packet.type === "list-certificates" ||
            packet.type === "list-namespaces"
        if (version3Request && this.negotiatedProtocolVersion! < 3) {
            this.active = packet
            void this.waitForRequest(
                this.respond(
                    PublicKeySubsystemStatusCode.RequestNotSupported,
                    `Public-key subsystem ${packet.type} requires protocol version 3`,
                ),
                `public-key subsystem server ${packet.type}`,
            ).catch((error: unknown) => {
                this.destroy(error instanceof Error ? error : new Error(String(error)))
            })
            return
        }
        if (
            (packet.type === "remove" || packet.type === "list") &&
            (packet.attributes !== undefined) !== this.negotiatedProtocolVersion! >= 3
        ) {
            throw new PublicKeySubsystemProtocolError(
                `Public-key subsystem ${packet.type} layout does not match negotiated version`,
            )
        }
        if (
            packet.type !== "add" &&
            packet.type !== "remove" &&
            packet.type !== "list" &&
            packet.type !== "listattributes" &&
            packet.type !== "add-certificate" &&
            packet.type !== "remove-certificate" &&
            packet.type !== "list-certificates" &&
            packet.type !== "list-namespaces"
        ) {
            this.active = packet
            const requestName = packet.type === "unknown" ? packet.name : packet.type
            void this.waitForRequest(
                this.respond(
                    PublicKeySubsystemStatusCode.RequestNotSupported,
                    `Unsupported public-key subsystem request ${requestName}`,
                ),
                `public-key subsystem server ${requestName}`,
            ).catch((error: unknown) => {
                const failure = error instanceof Error ? error : new Error(String(error))
                this.destroy(failure)
            })
            return
        }
        this.active = packet
        this.scheduleDispatch()
    }

    private scheduleDispatch(): void {
        if (this.dispatchScheduled || !this.active || this.closed) return
        this.dispatchScheduled = true
        queueMicrotask(() => {
            this.dispatchScheduled = false
            const abortController = new AbortController()
            const operation = Object.freeze({ signal: abortController.signal })
            this.requestAbortController = abortController
            void this.waitForRequest(
                this.dispatch(operation),
                `public-key subsystem server ${this.active?.type ?? "request"}`,
                abortController,
            )
                .catch((error: unknown) => {
                    const failure = error instanceof Error ? error : new Error(String(error))
                    this.destroy(failure)
                })
                .finally(() => {
                    if (this.requestAbortController === abortController) {
                        this.requestAbortController = undefined
                    }
                })
        })
    }

    private async dispatch(
        operation: Readonly<PublicKeySubsystemServerOperationContext>,
    ): Promise<void> {
        const packet = this.active
        if (!packet || this.closed) return
        if (packet.type === "listattributes") {
            for (const attribute of this.attributes) {
                await this.writePacket({
                    type: "attribute",
                    name: attribute.name,
                    compulsory: attribute.compulsory,
                })
            }
            await this.respond(PublicKeySubsystemStatusCode.Success)
            return
        }
        if (packet.type === "add-certificate") {
            let request: Readonly<PublicKeySubsystemServerAddCertificateContext>
            try {
                const context = this.requestContext(packet.attributes)
                const namespace = publicKeySubsystemNamespace(packet.attributes, true)!
                request = Object.freeze({
                    format: packet.format,
                    certificate: Buffer.from(packet.certificateBlob),
                    overwrite: packet.overwrite,
                    namespace,
                    attributes: context.attributes,
                })
            } catch (error) {
                await this.respond(
                    PublicKeySubsystemStatusCode.AttributeNotSupported,
                    error instanceof Error ? error.message : "Invalid certificate attribute",
                )
                return
            }
            await this.dispatchPolicy(
                "addCertificate",
                request,
                "certificate add",
                PublicKeySubsystemStatusCode.ActionNotAuthorized,
                operation,
            )
            return
        }
        if (packet.type === "remove-certificate") {
            let request: Readonly<PublicKeySubsystemServerRemoveCertificateContext>
            try {
                validatePublicKeySubsystemAttributes(packet.attributes)
                const namespace = publicKeySubsystemNamespace(packet.attributes, true)!
                request = Object.freeze({
                    format: packet.format,
                    certificate: Buffer.from(packet.certificateBlob),
                    namespace,
                    attributes: Object.freeze(
                        packet.attributes.map((attribute) =>
                            Object.freeze({
                                name: attribute.name,
                                value: Buffer.from(attribute.value),
                            }),
                        ),
                    ),
                })
            } catch (error) {
                await this.respond(
                    PublicKeySubsystemStatusCode.AttributeNotSupported,
                    error instanceof Error ? error.message : "Invalid certificate attribute",
                )
                return
            }
            await this.dispatchPolicy(
                "removeCertificate",
                request,
                "certificate remove",
                PublicKeySubsystemStatusCode.ActionNotAuthorized,
                operation,
            )
            return
        }
        if (packet.type === "list-certificates") {
            await this.dispatchCertificateList(operation)
            return
        }
        if (packet.type === "list-namespaces") {
            await this.dispatchNamespaceList(operation)
            return
        }
        if (packet.type === "list") {
            let context: Readonly<PublicKeySubsystemServerListContext>
            try {
                context = this.requestContext(packet.attributes ?? [])
            } catch (error) {
                await this.respond(
                    PublicKeySubsystemStatusCode.AttributeNotSupported,
                    error instanceof Error ? error.message : "Invalid public-key attribute",
                )
                return
            }
            if (!this.hooker.hasHooks("list")) {
                await this.respond(
                    PublicKeySubsystemStatusCode.RequestNotSupported,
                    "Public-key listing is not supported",
                )
                return
            }
            const controller: PublicKeySubsystemServerListController = { success: false }
            this.hookError = undefined
            await this.hooker.triggerHook("list", controller, context, operation)
            if (this.hookError) {
                await this.respond(
                    PublicKeySubsystemStatusCode.GeneralFailure,
                    "Public-key subsystem list handler failed",
                )
                return
            }
            if (controller.success) {
                let responses: PublicKeySubsystemPublicKeyPacket[]
                try {
                    responses = (controller.keys ?? []).map(({ key, attributes = [] }) => {
                        if (!(key instanceof PublicKey)) {
                            throw new TypeError("Public-key list response requires public keys")
                        }
                        return {
                            type: "publickey",
                            algorithm: key.data.alg,
                            keyBlob: key.serialize(),
                            attributes: attributes.map((attribute) => ({
                                name: attribute.name,
                                value: Buffer.isBuffer(attribute.value)
                                    ? Buffer.from(attribute.value)
                                    : encodeSSHUTF8(
                                          attribute.value,
                                          "Public-key subsystem attribute value",
                                      ),
                            })),
                        }
                    })
                    for (const response of responses) {
                        validatePublicKeySubsystemAttributes(response.attributes)
                    }
                    if (responses.length > MAX_PUBLIC_KEY_SUBSYSTEM_RESPONSES) {
                        throw new RangeError("Public-key list response has too many keys")
                    }
                    let responseBytes = 0
                    for (const response of responses) {
                        responseBytes += encodePublicKeySubsystemPacket(response).length
                        if (responseBytes > MAX_PUBLIC_KEY_SUBSYSTEM_RESPONSE_BYTES) {
                            throw new RangeError("Public-key list response is too large")
                        }
                    }
                } catch {
                    await this.respond(
                        PublicKeySubsystemStatusCode.GeneralFailure,
                        "Invalid public-key list response",
                    )
                    return
                }
                for (const response of responses) await this.writePacket(response)
            }
            await this.respond(
                controller.success
                    ? PublicKeySubsystemStatusCode.Success
                    : (controller.failureCode ?? PublicKeySubsystemStatusCode.RequestNotSupported),
                controller.description ??
                    (controller.success ? "" : "Public-key listing is not supported"),
                controller.languageTag ?? "",
            )
            return
        }
        if (packet.type !== "add" && packet.type !== "remove") {
            throw new PublicKeySubsystemProtocolError(
                `Cannot dispatch public-key subsystem ${packet.type} packet as a request`,
            )
        }
        let key: PublicKey
        try {
            key = PublicKey.parse(packet.keyBlob)
        } catch {
            await this.respond(PublicKeySubsystemStatusCode.KeyNotSupported, "Invalid public key")
            return
        }
        if (key.data.alg !== packet.algorithm) {
            await this.respond(
                PublicKeySubsystemStatusCode.KeyNotSupported,
                "Public key algorithm does not match key blob",
            )
            return
        }
        if (packet.type === "remove") {
            let context: Readonly<PublicKeySubsystemServerRemoveContext>
            try {
                const request = this.requestContext(packet.attributes ?? [])
                context = Object.freeze({ key, ...request })
            } catch (error) {
                await this.respond(
                    PublicKeySubsystemStatusCode.AttributeNotSupported,
                    error instanceof Error ? error.message : "Invalid public-key attribute",
                )
                return
            }
            if (!this.hooker.hasHooks("remove")) {
                await this.respond(this.authorizationFailureCode(), "Action not authorized")
                return
            }
            const controller: PublicKeySubsystemServerResponseController = { success: false }
            this.hookError = undefined
            await this.hooker.triggerHook("remove", context, controller, operation)
            if (this.hookError) {
                await this.respond(
                    PublicKeySubsystemStatusCode.GeneralFailure,
                    "Public-key subsystem remove handler failed",
                )
                return
            }
            await this.respond(
                controller.success
                    ? PublicKeySubsystemStatusCode.Success
                    : (controller.failureCode ?? this.authorizationFailureCode()),
                controller.description ?? (controller.success ? "" : "Action not authorized"),
                controller.languageTag ?? "",
            )
            return
        }
        let request: Omit<PublicKeySubsystemServerAddContext, "key" | "overwrite">
        try {
            request = this.requestContext(packet.attributes)
        } catch (error) {
            await this.respond(
                PublicKeySubsystemStatusCode.AttributeNotSupported,
                error instanceof Error ? error.message : "Invalid public-key attribute",
            )
            return
        }
        if (!this.hooker.hasHooks("add")) {
            await this.respond(this.authorizationFailureCode(), "Action not authorized")
            return
        }
        const context = Object.freeze({
            key,
            overwrite: packet.overwrite,
            ...request,
        })
        const controller: PublicKeySubsystemServerResponseController = { success: false }
        this.hookError = undefined
        await this.hooker.triggerHook("add", context, controller, operation)
        if (this.hookError) {
            await this.respond(
                PublicKeySubsystemStatusCode.GeneralFailure,
                "Public-key subsystem add handler failed",
            )
            return
        }
        await this.respond(
            controller.success
                ? PublicKeySubsystemStatusCode.Success
                : (controller.failureCode ?? this.authorizationFailureCode()),
            controller.description ?? (controller.success ? "" : "Action not authorized"),
            controller.languageTag ?? "",
        )
    }

    private authorizationFailureCode(): number {
        return this.negotiatedProtocolVersion! >= 3
            ? PublicKeySubsystemStatusCode.ActionNotAuthorized
            : PublicKeySubsystemStatusCode.AccessDenied
    }

    private async respond(code: number, description = "", languageTag = ""): Promise<void> {
        if (!this.active) {
            if (this.closed) return
            throw new Error("No public-key subsystem request is awaiting a response")
        }
        this.active = undefined
        await this.writeStatus(code, description, languageTag)
    }

    private async dispatchPolicy<T extends "addCertificate" | "removeCertificate">(
        event: T,
        context: PublicKeySubsystemServerHooker[T][0],
        description: string,
        defaultFailureCode: number,
        operation: Readonly<PublicKeySubsystemServerOperationContext>,
    ): Promise<void> {
        if (!this.hooker.hasHooks(event)) {
            await this.respond(defaultFailureCode, "Action not authorized")
            return
        }
        const controller: PublicKeySubsystemServerResponseController = { success: false }
        this.hookError = undefined
        if (event === "addCertificate") {
            await this.hooker.triggerHook(
                "addCertificate",
                context as Readonly<PublicKeySubsystemServerAddCertificateContext>,
                controller,
                operation,
            )
        } else {
            await this.hooker.triggerHook(
                "removeCertificate",
                context as Readonly<PublicKeySubsystemServerRemoveCertificateContext>,
                controller,
                operation,
            )
        }
        if (this.hookError) {
            await this.respond(
                PublicKeySubsystemStatusCode.GeneralFailure,
                `Public-key subsystem ${description} handler failed`,
            )
            return
        }
        await this.respond(
            controller.success
                ? PublicKeySubsystemStatusCode.Success
                : (controller.failureCode ?? defaultFailureCode),
            controller.description ?? (controller.success ? "" : "Action not authorized"),
            controller.languageTag ?? "",
        )
    }

    private async dispatchCertificateList(
        operation: Readonly<PublicKeySubsystemServerOperationContext>,
    ): Promise<void> {
        if (!this.hooker.hasHooks("listCertificates")) {
            await this.respond(
                PublicKeySubsystemStatusCode.ActionNotAuthorized,
                "Action not authorized",
            )
            return
        }
        const controller: PublicKeySubsystemServerListCertificatesController = { success: false }
        this.hookError = undefined
        await this.hooker.triggerHook("listCertificates", controller, operation)
        if (this.hookError) {
            await this.respond(
                PublicKeySubsystemStatusCode.GeneralFailure,
                "Public-key subsystem certificate list handler failed",
            )
            return
        }
        let responses: Extract<PublicKeySubsystemPacket, { type: "certificate" }>[] = []
        if (controller.success) {
            try {
                responses = (controller.certificates ?? []).map((certificate) => {
                    if (!isPlainConfigurationObject(certificate)) {
                        throw new TypeError(
                            "Public-key certificate list response must contain objects",
                        )
                    }
                    encodeSSHName(certificate.format, "Public-key subsystem certificate format")
                    if (!Buffer.isBuffer(certificate.certificate)) {
                        throw new TypeError(
                            "Public-key certificate list response requires certificate buffers",
                        )
                    }
                    validatePublicKeySubsystemNamespace(certificate.namespace)
                    const attributes = (certificate.attributes ?? []).map((attribute) => ({
                        name: attribute.name,
                        value: Buffer.isBuffer(attribute.value)
                            ? Buffer.from(attribute.value)
                            : encodeSSHUTF8(
                                  attribute.value,
                                  "Public-key subsystem certificate attribute value",
                              ),
                    }))
                    if (attributes.some(({ name }) => name === "namespace")) {
                        const supplied = publicKeySubsystemNamespace(attributes, true)
                        if (supplied !== certificate.namespace) {
                            throw new Error(
                                "Public-key certificate namespace attribute does not match namespace",
                            )
                        }
                    } else {
                        attributes.unshift({
                            name: "namespace",
                            value: encodeSSHUTF8(
                                certificate.namespace,
                                "Public-key subsystem namespace",
                            ),
                        })
                    }
                    validatePublicKeySubsystemAttributes(attributes)
                    publicKeySubsystemNamespace(attributes, true)
                    return {
                        type: "certificate",
                        format: certificate.format,
                        certificateBlob: Buffer.from(certificate.certificate),
                        attributes,
                    }
                })
                this.validateResponseCollection(responses, "certificate list")
            } catch {
                await this.respond(
                    PublicKeySubsystemStatusCode.GeneralFailure,
                    "Invalid public-key certificate list response",
                )
                return
            }
            for (const response of responses) await this.writePacket(response)
        }
        await this.respond(
            controller.success
                ? PublicKeySubsystemStatusCode.Success
                : (controller.failureCode ?? PublicKeySubsystemStatusCode.ActionNotAuthorized),
            controller.description ?? (controller.success ? "" : "Action not authorized"),
            controller.languageTag ?? "",
        )
    }

    private async dispatchNamespaceList(
        operation: Readonly<PublicKeySubsystemServerOperationContext>,
    ): Promise<void> {
        if (!this.hooker.hasHooks("listNamespaces")) {
            await this.respond(
                PublicKeySubsystemStatusCode.ActionNotAuthorized,
                "Action not authorized",
            )
            return
        }
        const controller: PublicKeySubsystemServerListNamespacesController = { success: false }
        this.hookError = undefined
        await this.hooker.triggerHook("listNamespaces", controller, operation)
        if (this.hookError) {
            await this.respond(
                PublicKeySubsystemStatusCode.GeneralFailure,
                "Public-key subsystem namespace list handler failed",
            )
            return
        }
        let responses: Extract<PublicKeySubsystemPacket, { type: "namespace" }>[] = []
        if (controller.success) {
            try {
                responses = (controller.namespaces ?? []).map((name) => {
                    validatePublicKeySubsystemNamespace(name)
                    return { type: "namespace", name }
                })
                this.validateResponseCollection(responses, "namespace list")
            } catch {
                await this.respond(
                    PublicKeySubsystemStatusCode.GeneralFailure,
                    "Invalid public-key namespace list response",
                )
                return
            }
            for (const response of responses) await this.writePacket(response)
        }
        await this.respond(
            controller.success
                ? PublicKeySubsystemStatusCode.Success
                : (controller.failureCode ?? PublicKeySubsystemStatusCode.ActionNotAuthorized),
            controller.description ?? (controller.success ? "" : "Action not authorized"),
            controller.languageTag ?? "",
        )
    }

    private validateResponseCollection(
        responses: readonly PublicKeySubsystemPacket[],
        description: string,
    ): void {
        if (responses.length > MAX_PUBLIC_KEY_SUBSYSTEM_RESPONSES) {
            throw new RangeError(`Public-key ${description} response has too many entries`)
        }
        let responseBytes = 0
        for (const response of responses) {
            responseBytes += encodePublicKeySubsystemPacket(response).length
            if (responseBytes > MAX_PUBLIC_KEY_SUBSYSTEM_RESPONSE_BYTES) {
                throw new RangeError(`Public-key ${description} response is too large`)
            }
        }
    }

    private requestContext(
        attributes: readonly PublicKeySubsystemAddAttribute[],
    ): Readonly<PublicKeySubsystemServerListContext> {
        const unsupported = attributes.find(
            (attribute) => attribute.critical && !this.supportedAttributeNames.has(attribute.name),
        )
        if (unsupported) throw new Error(`Unsupported critical attribute ${unsupported.name}`)
        validatePublicKeySubsystemAttributes(attributes)
        const namespace =
            publicKeySubsystemNamespace(attributes) ??
            (this.negotiatedProtocolVersion! >= 3 ? "ssh" : undefined)
        return Object.freeze({
            attributes: Object.freeze(
                attributes.map((attribute) =>
                    Object.freeze({
                        name: attribute.name,
                        value: Buffer.from(attribute.value),
                        critical: attribute.critical,
                    }),
                ),
            ),
            ...(namespace === undefined ? {} : { namespace }),
        })
    }

    private writeStatus(code: number, description = "", languageTag = ""): Promise<void> {
        return this.writePacket({ type: "status", code, description, languageTag })
    }

    private writePacket(packet: PublicKeySubsystemPacket): Promise<void> {
        if (this.closed) return Promise.resolve()
        const frame = encodePublicKeySubsystemPacket(packet)
        return new Promise<void>((resolve, reject) => {
            this.stream.write(frame, (error) => (error ? reject(error) : resolve()))
        })
    }

    private waitForRequest<T>(
        operation: PromiseLike<T>,
        description: string,
        abortController?: AbortController,
    ): Promise<T> {
        return waitWithTimeout(operation, this.#requestTimeout, description, (error) => {
            if (abortController && !abortController.signal.aborted) abortController.abort(error)
            this.destroy(error)
        })
    }

    private handleEnd(): void {
        if (this.closed) return
        try {
            this.parser.end()
        } catch (error) {
            this.destroy(error instanceof Error ? error : new Error(String(error)))
            return
        }
        this.finish(new PublicKeySubsystemProtocolError("Public-key subsystem channel ended"))
        if (!this.stream.destroyed && !this.stream.writableEnded) this.stream.end()
    }

    private finish(
        reason: Error = new PublicKeySubsystemProtocolError(
            "Public-key subsystem server session closed",
        ),
    ): void {
        if (this.closed) return
        this.closed = true
        if (this.requestAbortController && !this.requestAbortController.signal.aborted) {
            this.requestAbortController.abort(reason)
        }
        this.active = undefined
        this.emit("close")
    }

    private fail(error: Error): void {
        if (this.closed) return
        if (this.listenerCount("error") > 0) this.emit("error", error)
        this.finish(error)
    }
}
