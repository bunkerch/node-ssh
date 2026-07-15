import EventEmitter from "node:events"
import type Shell from "../channels/Session/Shell.js"
import { Hooker } from "../utils/Hooker.js"
import PublicKey from "../utils/PublicKey.js"
import { isPlainConfigurationObject } from "../utils/Configuration.js"
import { encodeSSHName } from "../utils/SSHName.js"
import { encodeSSHUTF8 } from "../utils/SSHText.js"
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
    type PublicKeySubsystemPublicKeyPacket,
} from "./PublicKeySubsystemCodec.js"

export interface PublicKeySubsystemSupportedAttribute {
    readonly name: string
    readonly compulsory?: boolean
}

export interface PublicKeySubsystemServerOptions {
    readonly attributes?: readonly PublicKeySubsystemSupportedAttribute[]
}

export interface PublicKeySubsystemServerAddContext {
    readonly key: PublicKey
    readonly overwrite: boolean
    readonly attributes: readonly PublicKeySubsystemAddAttribute[]
}

export interface PublicKeySubsystemServerResponseController {
    success: boolean
    failureCode?: number
    description?: string
    languageTag?: string
}

export interface PublicKeySubsystemServerRemoveContext {
    readonly key: PublicKey
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

// eslint-disable-next-line @typescript-eslint/consistent-type-definitions
export type PublicKeySubsystemServerHooker = {
    add: [
        context: Readonly<PublicKeySubsystemServerAddContext>,
        controller: PublicKeySubsystemServerResponseController,
    ]
    remove: [
        context: Readonly<PublicKeySubsystemServerRemoveContext>,
        controller: PublicKeySubsystemServerResponseController,
    ]
    list: [controller: PublicKeySubsystemServerListController]
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
    private readonly supportedAttributeNames: ReadonlySet<string>
    private initialized = false
    private closed = false
    private active: Exclude<PublicKeySubsystemPacket, { type: "version" }> | undefined
    private dispatchScheduled = false
    private hookError: Error | undefined

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
        this.stream = stream
        this.attributes = Object.freeze(normalizedAttributes)
        this.supportedAttributeNames = new Set(this.attributes.map(({ name }) => name))
        this.hooker.on("uncaughtException", (_event, error) => {
            this.hookError = error
        })
        stream.on("data", (data: Buffer) => this.receive(data))
        stream.once("end", () => this.handleEnd())
        stream.once("close", () => this.handleEnd())
        stream.once("error", (error) => this.fail(error))
        void this.writePacket({
            type: "version",
            version: PUBLIC_KEY_SUBSYSTEM_VERSION,
        }).catch((error: unknown) => {
            const failure = error instanceof Error ? error : new Error(String(error))
            this.destroy(failure)
        })
    }

    destroy(error?: Error): void {
        if (!this.stream.writableEnded) this.stream.end()
        if (!this.stream.destroyed) this.stream.destroy(error)
        this.fail(error ?? new Error("Public-key subsystem server session closed"))
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
            if (Math.min(packet.version, PUBLIC_KEY_SUBSYSTEM_VERSION) !== this.protocolVersion) {
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
        if (
            packet.type !== "add" &&
            packet.type !== "remove" &&
            packet.type !== "list" &&
            packet.type !== "listattributes"
        ) {
            this.active = packet
            const requestName = packet.type === "unknown" ? packet.name : packet.type
            void this.respond(
                PublicKeySubsystemStatusCode.RequestNotSupported,
                `Unsupported public-key subsystem request ${requestName}`,
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
            void this.dispatch().catch((error: unknown) => {
                const failure = error instanceof Error ? error : new Error(String(error))
                this.destroy(failure)
            })
        })
    }

    private async dispatch(): Promise<void> {
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
        if (packet.type === "list") {
            if (!this.hooker.hasHooks("list")) {
                await this.respond(
                    PublicKeySubsystemStatusCode.RequestNotSupported,
                    "Public-key listing is not supported",
                )
                return
            }
            const controller: PublicKeySubsystemServerListController = { success: false }
            this.hookError = undefined
            await this.hooker.triggerHook("list", controller)
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
            if (!this.hooker.hasHooks("remove")) {
                await this.respond(PublicKeySubsystemStatusCode.AccessDenied, "Access denied")
                return
            }
            const controller: PublicKeySubsystemServerResponseController = { success: false }
            this.hookError = undefined
            await this.hooker.triggerHook("remove", Object.freeze({ key }), controller)
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
                    : (controller.failureCode ?? PublicKeySubsystemStatusCode.AccessDenied),
                controller.description ?? (controller.success ? "" : "Access denied"),
                controller.languageTag ?? "",
            )
            return
        }
        const unsupported = packet.attributes.find(
            (attribute) => attribute.critical && !this.supportedAttributeNames.has(attribute.name),
        )
        if (unsupported) {
            await this.respond(
                PublicKeySubsystemStatusCode.AttributeNotSupported,
                `Unsupported critical attribute ${unsupported.name}`,
            )
            return
        }
        try {
            validatePublicKeySubsystemAttributes(packet.attributes)
        } catch (error) {
            await this.respond(
                PublicKeySubsystemStatusCode.AttributeNotSupported,
                error instanceof Error ? error.message : "Invalid public-key attribute",
            )
            return
        }
        if (!this.hooker.hasHooks("add")) {
            await this.respond(PublicKeySubsystemStatusCode.AccessDenied, "Access denied")
            return
        }
        const context = Object.freeze({
            key,
            overwrite: packet.overwrite,
            attributes: Object.freeze(
                packet.attributes.map((attribute) =>
                    Object.freeze({
                        name: attribute.name,
                        value: Buffer.from(attribute.value),
                        critical: attribute.critical,
                    }),
                ),
            ),
        })
        const controller: PublicKeySubsystemServerResponseController = { success: false }
        this.hookError = undefined
        await this.hooker.triggerHook("add", context, controller)
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
                : (controller.failureCode ?? PublicKeySubsystemStatusCode.AccessDenied),
            controller.description ?? (controller.success ? "" : "Access denied"),
            controller.languageTag ?? "",
        )
    }

    private async respond(code: number, description = "", languageTag = ""): Promise<void> {
        if (!this.active) {
            throw new Error("No public-key subsystem request is awaiting a response")
        }
        this.active = undefined
        await this.writeStatus(code, description, languageTag)
    }

    private writeStatus(code: number, description = "", languageTag = ""): Promise<void> {
        return this.writePacket({ type: "status", code, description, languageTag })
    }

    private writePacket(packet: PublicKeySubsystemPacket): Promise<void> {
        const frame = encodePublicKeySubsystemPacket(packet)
        return new Promise<void>((resolve, reject) => {
            this.stream.write(frame, (error) => (error ? reject(error) : resolve()))
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
        this.closed = true
        this.active = undefined
        this.emit("close")
        if (!this.stream.destroyed && !this.stream.writableEnded) this.stream.end()
    }

    private fail(error: Error): void {
        if (this.closed) return
        this.closed = true
        this.active = undefined
        if (this.listenerCount("error") > 0) this.emit("error", error)
        this.emit("close")
    }
}
