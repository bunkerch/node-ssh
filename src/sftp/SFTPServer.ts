import EventEmitter from "node:events"
import type Shell from "../channels/Session/Shell.js"
import { Hooker } from "../utils/Hooker.js"
import { validateSSHName } from "../utils/SSHName.js"
import { isPlainConfigurationObject } from "../utils/Configuration.js"
import { encodeSFTPPacket, SFTPPacketParser, SFTPProtocolError } from "./codec.js"
import {
    MAX_SFTP_HANDLE_LENGTH,
    MAX_SFTP_PACKET_LENGTH,
    SFTP_VERSION,
    SFTPPacketType,
    SFTPStatusCode,
    validateSFTPOpenFlags,
} from "./constants.js"
import type {
    SFTPAttributes,
    SFTPExtension,
    SFTPExtendedAttribute,
    SFTPNameEntry,
    SFTPPacket,
    SFTPRequestPacket,
} from "./types.js"
import { encodeSFTPLimits } from "./openssh.js"

const MAX_OUTSTANDING_REQUESTS = 1024
const DEFAULT_MAX_CONCURRENT_REQUESTS = 64
const DEFAULT_MAX_OPEN_HANDLES = 256
const DEFAULT_MAX_READ_LENGTH = MAX_SFTP_PACKET_LENGTH - 2048
const DEFAULT_MAX_WRITE_LENGTH = MAX_SFTP_PACKET_LENGTH - 2048
const MAX_READ_LENGTH = MAX_SFTP_PACKET_LENGTH - 9
const MAX_WRITE_LENGTH = MAX_SFTP_PACKET_LENGTH - (1 + 4 + 4 + MAX_SFTP_HANDLE_LENGTH + 8 + 4)
const LIMITS_EXTENSION = "limits@openssh.com"

const STATUS_MESSAGES: Readonly<Record<number, string>> = {
    [SFTPStatusCode.Ok]: "No error",
    [SFTPStatusCode.EOF]: "End of file",
    [SFTPStatusCode.NoSuchFile]: "No such file or directory",
    [SFTPStatusCode.PermissionDenied]: "Permission denied",
    [SFTPStatusCode.Failure]: "Failure",
    [SFTPStatusCode.BadMessage]: "Bad message",
    [SFTPStatusCode.OperationUnsupported]: "Operation unsupported",
    [SFTPStatusCode.InvalidParameter]: "Invalid parameter",
}

export type SFTPRequestOf<T extends SFTPPacketType> = Readonly<SFTPRequestPacket & { type: T }>

// eslint-disable-next-line @typescript-eslint/consistent-type-definitions
export type SFTPServerEvents = {
    ready: [clientVersion: number]
    close: []
    error: [error: Error]
    requestReceived: [request: Readonly<SFTPRequestPacket>]
}

// eslint-disable-next-line @typescript-eslint/consistent-type-definitions
export type SFTPServerHooker = {
    request: [request: Readonly<SFTPRequestPacket>]
    OPEN: [request: SFTPRequestOf<SFTPPacketType.Open>]
    CLOSE: [request: SFTPRequestOf<SFTPPacketType.Close>]
    READ: [request: SFTPRequestOf<SFTPPacketType.Read>]
    WRITE: [request: SFTPRequestOf<SFTPPacketType.Write>]
    LSTAT: [request: SFTPRequestOf<SFTPPacketType.LStat>]
    FSTAT: [request: SFTPRequestOf<SFTPPacketType.FStat>]
    SETSTAT: [request: SFTPRequestOf<SFTPPacketType.SetStat>]
    FSETSTAT: [request: SFTPRequestOf<SFTPPacketType.FSetStat>]
    OPENDIR: [request: SFTPRequestOf<SFTPPacketType.OpenDir>]
    READDIR: [request: SFTPRequestOf<SFTPPacketType.ReadDir>]
    REMOVE: [request: SFTPRequestOf<SFTPPacketType.Remove>]
    MKDIR: [request: SFTPRequestOf<SFTPPacketType.MkDir>]
    RMDIR: [request: SFTPRequestOf<SFTPPacketType.RmDir>]
    REALPATH: [request: SFTPRequestOf<SFTPPacketType.RealPath>]
    STAT: [request: SFTPRequestOf<SFTPPacketType.Stat>]
    RENAME: [request: SFTPRequestOf<SFTPPacketType.Rename>]
    READLINK: [request: SFTPRequestOf<SFTPPacketType.ReadLink>]
    SYMLINK: [request: SFTPRequestOf<SFTPPacketType.SymLink>]
    EXTENDED: [request: SFTPRequestOf<SFTPPacketType.Extended>]
}

export interface SFTPServerOptions {
    extensions?: readonly SFTPExtension[]
    openSSHSymlinkArguments?: boolean
    /** Maximum request hooks allowed to run concurrently. */
    maxConcurrentRequests?: number
    /** Maximum active and pending baseline file or directory handles. */
    maxOpenHandles?: number
    /** Largest READ length passed to application policy. */
    maxReadLength?: number
    /** Largest WRITE data field passed to application policy. */
    maxWriteLength?: number
    /** Advertise and answer the limits extension. Defaults to true when handles are enabled. */
    advertiseLimits?: boolean
}

export interface SFTPSymlinkPaths {
    targetPath: Buffer
    linkPath: Buffer
}

interface ActiveSFTPRequest {
    readonly request: SFTPRequestPacket
    readonly ordering: SFTPRequestOrdering
    reservesHandle?: boolean
    response?: Promise<void>
}

interface SFTPRequestOrdering {
    readonly barrier: boolean
    readonly resources: readonly string[]
}

type SFTPHandleType = "file" | "directory" | "extension"

const REQUEST_HOOK_NAMES = new Map<SFTPPacketType, keyof SFTPServerHooker>([
    [SFTPPacketType.Open, "OPEN"],
    [SFTPPacketType.Close, "CLOSE"],
    [SFTPPacketType.Read, "READ"],
    [SFTPPacketType.Write, "WRITE"],
    [SFTPPacketType.LStat, "LSTAT"],
    [SFTPPacketType.FStat, "FSTAT"],
    [SFTPPacketType.SetStat, "SETSTAT"],
    [SFTPPacketType.FSetStat, "FSETSTAT"],
    [SFTPPacketType.OpenDir, "OPENDIR"],
    [SFTPPacketType.ReadDir, "READDIR"],
    [SFTPPacketType.Remove, "REMOVE"],
    [SFTPPacketType.MkDir, "MKDIR"],
    [SFTPPacketType.RmDir, "RMDIR"],
    [SFTPPacketType.RealPath, "REALPATH"],
    [SFTPPacketType.Stat, "STAT"],
    [SFTPPacketType.Rename, "RENAME"],
    [SFTPPacketType.ReadLink, "READLINK"],
    [SFTPPacketType.SymLink, "SYMLINK"],
    [SFTPPacketType.Extended, "EXTENDED"],
])

export default class SFTPServer extends EventEmitter<SFTPServerEvents> {
    readonly hooker = new Hooker<SFTPServerHooker>()
    readonly protocolVersion = SFTP_VERSION
    readonly stream: Shell
    readonly openSSHSymlinkArguments: boolean

    private readonly parser = new SFTPPacketParser()
    private readonly advertisedExtensions: readonly SFTPExtension[]
    readonly #maxConcurrentRequests: number
    readonly #maxOpenHandles: number
    readonly #maxReadLength: number
    readonly #maxWriteLength: number
    readonly #advertiseLimits: boolean
    private readonly queued: SFTPRequestPacket[] = []
    private readonly requestIds = new Set<number>()
    private readonly active = new Set<ActiveSFTPRequest>()
    private readonly activeRequestIds = new Set<number>()
    private readonly awaitingResponse = new Map<number, ActiveSFTPRequest>()
    private readonly activeResources = new Map<string, number>()
    private readonly handlePathResources = new Map<string, Set<string>>()
    private readonly activeHandleTypes = new Map<string, SFTPHandleType>()
    private readonly pendingHandleKeys = new Set<string>()
    private pendingHandleRequests = 0
    private activeOrderingBarriers = 0
    private initialized = false
    private closed = false
    private dispatchScheduled = false

    constructor(stream: Shell, options: SFTPServerOptions = {}) {
        super()
        if (!isPlainConfigurationObject(options)) {
            throw new TypeError("SFTP server options must be an object")
        }
        if (options.extensions !== undefined && !Array.isArray(options.extensions)) {
            throw new TypeError("SFTP server extensions must be an array")
        }
        if (
            options.openSSHSymlinkArguments !== undefined &&
            typeof options.openSSHSymlinkArguments !== "boolean"
        ) {
            throw new TypeError("SFTP OpenSSH symlink argument option must be a boolean")
        }
        this.stream = stream
        this.openSSHSymlinkArguments =
            options.openSSHSymlinkArguments === undefined ? false : options.openSSHSymlinkArguments
        this.#maxConcurrentRequests =
            options.maxConcurrentRequests === undefined
                ? DEFAULT_MAX_CONCURRENT_REQUESTS
                : options.maxConcurrentRequests
        if (
            !Number.isSafeInteger(this.#maxConcurrentRequests) ||
            this.#maxConcurrentRequests < 1 ||
            this.#maxConcurrentRequests > MAX_OUTSTANDING_REQUESTS
        ) {
            throw new RangeError(
                `SFTP maximum concurrent requests must be between 1 and ${MAX_OUTSTANDING_REQUESTS}`,
            )
        }
        this.#maxOpenHandles =
            options.maxOpenHandles === undefined ? DEFAULT_MAX_OPEN_HANDLES : options.maxOpenHandles
        if (!Number.isSafeInteger(this.#maxOpenHandles) || this.#maxOpenHandles < 0) {
            throw new RangeError("SFTP maximum open handles must be a non-negative safe integer")
        }
        this.#maxReadLength = normalizeTransferLimit(
            options.maxReadLength,
            DEFAULT_MAX_READ_LENGTH,
            MAX_READ_LENGTH,
            "read",
        )
        this.#maxWriteLength = normalizeTransferLimit(
            options.maxWriteLength,
            DEFAULT_MAX_WRITE_LENGTH,
            MAX_WRITE_LENGTH,
            "write",
        )
        if (options.advertiseLimits !== undefined && typeof options.advertiseLimits !== "boolean") {
            throw new TypeError("SFTP advertise-limits option must be a boolean")
        }
        this.#advertiseLimits = options.advertiseLimits ?? this.#maxOpenHandles > 0
        if (this.#advertiseLimits && this.#maxOpenHandles === 0) {
            throw new RangeError("SFTP limits cannot advertise a zero-handle server capacity")
        }
        const configuredExtensions = ownExtensions(
            options.extensions === undefined ? [] : options.extensions,
        )
        if (
            this.#advertiseLimits &&
            configuredExtensions.some(({ name }) => name === LIMITS_EXTENSION)
        ) {
            throw new Error("SFTP limits extension is already provided by the server")
        }
        this.advertisedExtensions = Object.freeze([
            ...configuredExtensions,
            ...(this.#advertiseLimits
                ? [{ name: LIMITS_EXTENSION, data: Buffer.from("1", "ascii") }]
                : []),
        ])
        // Request failures are converted to an SFTP failure response. Applications may add
        // another listener when they also need to observe the contained backend error.
        this.hooker.on("uncaughtException", () => undefined)
        stream.on("data", (data: Buffer) => this.receive(data))
        stream.once("end", () => this.handleEnd())
        stream.once("close", () => this.handleEnd())
        stream.once("error", (error) => this.fail(error))
    }

    get maxConcurrentRequests(): number {
        return this.#maxConcurrentRequests
    }

    get maxOpenHandles(): number {
        return this.#maxOpenHandles
    }

    get maxReadLength(): number {
        return this.#maxReadLength
    }

    get maxWriteLength(): number {
        return this.#maxWriteLength
    }

    get extensions(): readonly SFTPExtension[] {
        return ownExtensions(this.advertisedExtensions)
    }

    status(requestId: number, code: SFTPStatusCode, message = "", languageTag = ""): Promise<void> {
        if (code === SFTPStatusCode.NoConnection || code === SFTPStatusCode.ConnectionLost) {
            throw new Error("SFTP servers must not send client-only connection status codes")
        }
        if (!(code in STATUS_MESSAGES)) throw new Error(`Unknown SFTP status code ${code}`)
        const request = this.requireActive(requestId)
        if (
            code === SFTPStatusCode.EOF &&
            request.type !== SFTPPacketType.Read &&
            request.type !== SFTPPacketType.ReadDir &&
            request.type !== SFTPPacketType.Extended
        ) {
            throw new Error(
                "SFTP EOF status is only valid for READ, READDIR, and EXTENDED requests",
            )
        }
        if (code === SFTPStatusCode.InvalidParameter && request.type !== SFTPPacketType.Extended) {
            throw new Error("SFTP invalid-parameter status is only valid for extension requests")
        }
        if (code === SFTPStatusCode.Ok && !expectsStatus(request.type)) {
            throw new Error(`SFTP request type ${request.type} requires a data response on success`)
        }
        const response = this.respond({
            type: SFTPPacketType.Status,
            requestId,
            code,
            message: message || STATUS_MESSAGES[code] || "",
            languageTag,
        })
        if (request.type === SFTPPacketType.Close) {
            return response.then(() => {
                const handleKey = handleResource(request.handle)
                this.activeHandleTypes.delete(handleKey)
                this.handlePathResources.delete(handleKey)
            })
        }
        return response
    }

    handle(requestId: number, handle: Buffer): Promise<void> {
        const active = this.requireActiveState(requestId)
        const { request } = active
        if (
            request.type !== SFTPPacketType.Open &&
            request.type !== SFTPPacketType.OpenDir &&
            request.type !== SFTPPacketType.Extended
        ) {
            throw new Error("SFTP HANDLE is only valid for OPEN, OPENDIR, and EXTENDED")
        }
        const ownedHandle = ownResponseBuffer(handle, "response handle")
        if (ownedHandle.length > MAX_SFTP_HANDLE_LENGTH) {
            throw new RangeError(`SFTP response handle exceeds ${MAX_SFTP_HANDLE_LENGTH} bytes`)
        }
        const handleKey = handleResource(ownedHandle)
        if (this.activeHandleTypes.has(handleKey) || this.pendingHandleKeys.has(handleKey)) {
            throw new Error("SFTP response handle is already active")
        }
        if (
            request.type === SFTPPacketType.Extended &&
            this.activeHandleTypes.size + this.pendingHandleRequests >= this.#maxOpenHandles
        ) {
            throw new Error("SFTP open handle limit reached")
        }
        const handleType: SFTPHandleType =
            request.type === SFTPPacketType.Open
                ? "file"
                : request.type === SFTPPacketType.OpenDir
                  ? "directory"
                  : "extension"
        const pathKey =
            request.type === SFTPPacketType.Open
                ? pathResource(request.filename)
                : request.type === SFTPPacketType.OpenDir
                  ? pathResource(request.path)
                  : undefined
        this.pendingHandleKeys.add(handleKey)
        let response: Promise<void>
        try {
            response = this.respond({
                type: SFTPPacketType.Handle,
                requestId,
                handle: ownedHandle,
            })
        } catch (error) {
            this.pendingHandleKeys.delete(handleKey)
            throw error
        }
        const tracked = response.then(
            () => {
                this.pendingHandleKeys.delete(handleKey)
                this.activeHandleTypes.set(handleKey, handleType)
                if (pathKey !== undefined) {
                    this.handlePathResources.set(handleKey, new Set([pathKey]))
                }
                this.releaseHandleReservation(active)
            },
            (error: unknown) => {
                this.pendingHandleKeys.delete(handleKey)
                throw error
            },
        )
        active.response = tracked
        return tracked
    }

    data(requestId: number, data: Buffer): Promise<void> {
        const request = this.requireActive(requestId)
        if (request.type !== SFTPPacketType.Read && request.type !== SFTPPacketType.Extended) {
            throw new Error("SFTP DATA is only valid for READ and EXTENDED")
        }
        const ownedData = ownResponseBuffer(data, "DATA")
        if (request.type === SFTPPacketType.Read && ownedData.length === 0) {
            throw new Error("SFTP DATA response to READ must not be empty")
        }
        if (request.type === SFTPPacketType.Read && ownedData.length > request.length) {
            throw new Error("SFTP DATA exceeds the requested read length")
        }
        return this.respond({ type: SFTPPacketType.Data, requestId, data: ownedData })
    }

    name(requestId: number, names: SFTPNameEntry | readonly SFTPNameEntry[]): Promise<void> {
        const request = this.requireActive(requestId)
        const entries = (Array.isArray(names) ? names : [names]).map(ownResponseName)
        if (entries.length === 0 && request.type !== SFTPPacketType.Extended) {
            throw new Error("SFTP baseline NAME must contain at least one entry")
        }
        if (
            request.type !== SFTPPacketType.ReadDir &&
            request.type !== SFTPPacketType.RealPath &&
            request.type !== SFTPPacketType.ReadLink &&
            request.type !== SFTPPacketType.Extended
        ) {
            throw new Error("SFTP NAME is not valid for this request")
        }
        if (
            (request.type === SFTPPacketType.RealPath ||
                request.type === SFTPPacketType.ReadLink) &&
            entries.length !== 1
        ) {
            throw new Error("SFTP REALPATH and READLINK require exactly one name")
        }
        return this.respond({ type: SFTPPacketType.Name, requestId, names: entries })
    }

    attributes(requestId: number, attributes: SFTPAttributes): Promise<void> {
        const request = this.requireActive(requestId)
        if (
            request.type !== SFTPPacketType.Stat &&
            request.type !== SFTPPacketType.LStat &&
            request.type !== SFTPPacketType.FStat &&
            request.type !== SFTPPacketType.Extended
        ) {
            throw new Error("SFTP ATTRS is not valid for this request")
        }
        return this.respond({
            type: SFTPPacketType.Attrs,
            requestId,
            attributes: ownResponseAttributes(attributes),
        })
    }

    extendedReply(requestId: number, data: Buffer): Promise<void> {
        const request = this.requireActive(requestId)
        if (request.type !== SFTPPacketType.Extended) {
            throw new Error("SFTP EXTENDED_REPLY is only valid for EXTENDED requests")
        }
        return this.respond({
            type: SFTPPacketType.ExtendedReply,
            requestId,
            data: ownResponseBuffer(data, "EXTENDED_REPLY data"),
        })
    }

    symlinkPaths(request: SFTPRequestOf<SFTPPacketType.SymLink>): Readonly<SFTPSymlinkPaths> {
        return Object.freeze(
            this.openSSHSymlinkArguments
                ? {
                      targetPath: Buffer.from(request.firstPath),
                      linkPath: Buffer.from(request.secondPath),
                  }
                : {
                      linkPath: Buffer.from(request.firstPath),
                      targetPath: Buffer.from(request.secondPath),
                  },
        )
    }

    destroy(error?: Error): void {
        if (!this.stream.writableEnded) this.stream.end()
        if (!this.stream.destroyed) this.stream.destroy(error)
        this.fail(error ?? new Error("SFTP server session closed"))
    }

    private receive(data: Buffer): void {
        try {
            for (const packet of this.parser.push(data)) this.receivePacket(packet)
        } catch (error) {
            const protocolError = error instanceof Error ? error : new Error(String(error))
            this.destroy(protocolError)
        }
    }

    private receivePacket(packet: SFTPPacket): void {
        if (!this.initialized) {
            if (packet.type !== SFTPPacketType.Init) {
                throw new SFTPProtocolError("Expected SFTP INIT packet")
            }
            if (packet.version < SFTP_VERSION) {
                throw new SFTPProtocolError(`Unsupported SFTP client version ${packet.version}`)
            }
            this.initialized = true
            void this.writePacket({
                type: SFTPPacketType.Version,
                version: SFTP_VERSION,
                extensions: this.advertisedExtensions,
            }).catch((error: unknown) => {
                this.destroy(error instanceof Error ? error : new Error(String(error)))
            })
            this.emit("ready", packet.version)
            return
        }
        if (!isRequest(packet)) {
            throw new SFTPProtocolError(`Unexpected SFTP client packet type ${packet.type}`)
        }
        if (this.requestIds.has(packet.requestId)) {
            throw new SFTPProtocolError(`Duplicate outstanding SFTP request id ${packet.requestId}`)
        }
        if (this.requestIds.size >= MAX_OUTSTANDING_REQUESTS) {
            throw new SFTPProtocolError(
                `SFTP outstanding requests exceed ${MAX_OUTSTANDING_REQUESTS}`,
            )
        }
        this.requestIds.add(packet.requestId)
        this.queued.push(packet)
        if (this.listenerCount("requestReceived") > 0) {
            this.emit("requestReceived", snapshotRequest(packet))
        }
        this.scheduleDispatch()
    }

    private scheduleDispatch(): void {
        if (this.dispatchScheduled || this.closed || this.queued.length === 0) return
        this.dispatchScheduled = true
        queueMicrotask(() => {
            this.dispatchScheduled = false
            this.dispatchAvailable()
        })
    }

    private dispatchAvailable(): void {
        while (
            !this.closed &&
            this.active.size < this.#maxConcurrentRequests &&
            this.queued.length > 0
        ) {
            const queuedIndex = this.findDispatchableRequest()
            if (queuedIndex === -1) return
            const [request] = this.queued.splice(queuedIndex, 1)
            const ordering = this.requestOrdering(request)
            const active: ActiveSFTPRequest = { request, ordering }
            this.active.add(active)
            this.activeRequestIds.add(request.requestId)
            this.acquireOrdering(ordering)
            this.awaitingResponse.set(request.requestId, active)
            void this.dispatch(active).then(
                () => {
                    this.releaseHandleReservation(active)
                    this.active.delete(active)
                    this.activeRequestIds.delete(request.requestId)
                    this.releaseOrdering(ordering)
                    this.scheduleDispatch()
                },
                (error: unknown) => {
                    this.releaseHandleReservation(active)
                    const failure = error instanceof Error ? error : new Error(String(error))
                    this.destroy(failure)
                },
            )
        }
    }

    private findDispatchableRequest(): number {
        const blockedResources = new Set<string>()
        for (let index = 0; index < this.queued.length; index++) {
            const request = this.queued[index]!
            if (this.activeRequestIds.has(request.requestId)) continue
            const ordering = this.requestOrdering(request)
            if (ordering.barrier) return this.active.size === 0 ? index : -1
            if (this.activeOrderingBarriers > 0) return -1
            if (
                ordering.resources.every(
                    (resource) =>
                        !this.activeResources.has(resource) && !blockedResources.has(resource),
                )
            ) {
                return index
            }
            for (const resource of ordering.resources) blockedResources.add(resource)
        }
        return -1
    }

    private requestOrdering(request: SFTPRequestPacket): SFTPRequestOrdering {
        if (request.type === SFTPPacketType.Extended) {
            return { barrier: true, resources: [] }
        }

        const resources: string[] = []
        switch (request.type) {
            case SFTPPacketType.Open:
                resources.push(pathResource(request.filename))
                break
            case SFTPPacketType.Close:
            case SFTPPacketType.FStat:
            case SFTPPacketType.ReadDir:
            case SFTPPacketType.Read:
            case SFTPPacketType.Write:
            case SFTPPacketType.FSetStat: {
                const handleKey = handleResource(request.handle)
                resources.push(handleKey, ...(this.handlePathResources.get(handleKey) ?? []))
                break
            }
            case SFTPPacketType.LStat:
            case SFTPPacketType.OpenDir:
            case SFTPPacketType.Remove:
            case SFTPPacketType.RmDir:
            case SFTPPacketType.RealPath:
            case SFTPPacketType.Stat:
            case SFTPPacketType.ReadLink:
            case SFTPPacketType.SetStat:
            case SFTPPacketType.MkDir:
                resources.push(pathResource(request.path))
                break
            case SFTPPacketType.Rename:
            case SFTPPacketType.SymLink:
                resources.push(pathResource(request.firstPath), pathResource(request.secondPath))
                break
            default: {
                const unsupported: never = request
                throw new SFTPProtocolError(
                    `Cannot order unsupported SFTP request type ${String(unsupported)}`,
                )
            }
        }
        return { barrier: false, resources: [...new Set(resources)] }
    }

    private acquireOrdering(ordering: SFTPRequestOrdering): void {
        if (ordering.barrier) this.activeOrderingBarriers++
        for (const resource of ordering.resources) {
            this.activeResources.set(resource, (this.activeResources.get(resource) ?? 0) + 1)
        }
    }

    private releaseOrdering(ordering: SFTPRequestOrdering): void {
        if (ordering.barrier) this.activeOrderingBarriers--
        for (const resource of ordering.resources) {
            const count = this.activeResources.get(resource)
            if (count === undefined || count <= 1) this.activeResources.delete(resource)
            else this.activeResources.set(resource, count - 1)
        }
    }

    private async dispatch(active: ActiveSFTPRequest): Promise<void> {
        const { request } = active
        if (request.type === SFTPPacketType.Open) {
            try {
                validateSFTPOpenFlags(request.flags)
            } catch (error) {
                await this.status(
                    request.requestId,
                    SFTPStatusCode.BadMessage,
                    error instanceof Error ? error.message : "Invalid SFTP open flags",
                )
                return
            }
        }
        const handleFailure = this.validateRequestHandle(request)
        if (handleFailure !== undefined) {
            await this.status(request.requestId, SFTPStatusCode.Failure, handleFailure)
            return
        }
        if (request.type === SFTPPacketType.Read && request.length > this.#maxReadLength) {
            await this.status(
                request.requestId,
                SFTPStatusCode.Failure,
                "SFTP read length limit exceeded",
            )
            return
        }
        if (request.type === SFTPPacketType.Write && request.data.length > this.#maxWriteLength) {
            await this.status(
                request.requestId,
                SFTPStatusCode.Failure,
                "SFTP write length limit exceeded",
            )
            return
        }
        if (
            this.#advertiseLimits &&
            request.type === SFTPPacketType.Extended &&
            request.request === LIMITS_EXTENSION
        ) {
            if (request.data.length !== 0) {
                await this.status(
                    request.requestId,
                    SFTPStatusCode.BadMessage,
                    "SFTP limits request has trailing data",
                )
                return
            }
            await this.extendedReply(
                request.requestId,
                encodeSFTPLimits({
                    maximumPacketLength: BigInt(MAX_SFTP_PACKET_LENGTH),
                    maximumReadLength: BigInt(this.#maxReadLength),
                    maximumWriteLength: BigInt(this.#maxWriteLength),
                    maximumOpenHandles: BigInt(this.#maxOpenHandles),
                }),
            )
            return
        }
        if (request.type === SFTPPacketType.Open || request.type === SFTPPacketType.OpenDir) {
            if (this.activeHandleTypes.size + this.pendingHandleRequests >= this.#maxOpenHandles) {
                await this.status(
                    request.requestId,
                    SFTPStatusCode.Failure,
                    "SFTP open handle limit reached",
                )
                return
            }
            this.pendingHandleRequests++
            active.reservesHandle = true
        }
        const hookName = REQUEST_HOOK_NAMES.get(request.type)
        if (!hookName) throw new SFTPProtocolError(`Unsupported SFTP request type ${request.type}`)
        let successful = true
        if (this.hooker.hasHooks(hookName)) {
            successful = await this.triggerRequestHook(hookName, request)
        } else if (this.hooker.hasHooks("request")) {
            successful = await this.hooker.triggerHookChecked("request", request)
        } else {
            await this.status(request.requestId, SFTPStatusCode.OperationUnsupported)
            return
        }
        if (active.response) {
            await active.response
            return
        }
        if (!this.active.has(active)) return
        if (!successful) {
            await this.status(
                request.requestId,
                SFTPStatusCode.Failure,
                "SFTP request handler failed",
            )
            return
        }
        await this.status(
            request.requestId,
            SFTPStatusCode.Failure,
            "SFTP request handler returned without a response",
        )
    }

    private releaseHandleReservation(active: ActiveSFTPRequest): void {
        if (!active.reservesHandle) return
        active.reservesHandle = false
        this.pendingHandleRequests--
    }

    private validateRequestHandle(request: SFTPRequestPacket): string | undefined {
        if (
            request.type !== SFTPPacketType.Close &&
            request.type !== SFTPPacketType.FStat &&
            request.type !== SFTPPacketType.ReadDir &&
            request.type !== SFTPPacketType.Read &&
            request.type !== SFTPPacketType.Write &&
            request.type !== SFTPPacketType.FSetStat
        ) {
            return undefined
        }
        const handleType = this.activeHandleTypes.get(handleResource(request.handle))
        if (handleType === undefined) return "SFTP handle is not active"
        if (request.type === SFTPPacketType.ReadDir && handleType === "file") {
            return "SFTP handle is not a directory"
        }
        if (
            (request.type === SFTPPacketType.Read || request.type === SFTPPacketType.Write) &&
            handleType === "directory"
        ) {
            return "SFTP handle is not a file"
        }
        return undefined
    }

    private triggerRequestHook(
        hookName: keyof SFTPServerHooker,
        request: Readonly<SFTPRequestPacket>,
    ): Promise<boolean> {
        // REQUEST_HOOK_NAMES is the single mapping between each discriminated packet and hook.
        return this.hooker.triggerHookChecked(
            hookName,
            request as SFTPServerHooker[typeof hookName][0],
        )
    }

    private requireActive(requestId: number): SFTPRequestPacket {
        return this.requireActiveState(requestId).request
    }

    private requireActiveState(requestId: number): ActiveSFTPRequest {
        if (this.closed) throw new Error("SFTP server session is closed")
        const active = this.awaitingResponse.get(requestId)
        if (!active) {
            throw new Error(`SFTP request ${requestId} is not awaiting a response`)
        }
        if (active.response) {
            throw new Error(`SFTP request ${requestId} already has a response`)
        }
        return active
    }

    private respond(packet: SFTPPacket): Promise<void> {
        if (!("requestId" in packet)) throw new Error("SFTP response has no request id")
        const active = this.requireActiveState(packet.requestId)
        const written = this.writePacket(packet)
        const response = written.then(
            () => {
                if (this.awaitingResponse.get(packet.requestId) === active) {
                    this.awaitingResponse.delete(packet.requestId)
                    this.requestIds.delete(packet.requestId)
                }
            },
            (error: unknown) => {
                const failure = error instanceof Error ? error : new Error(String(error))
                this.destroy(failure)
                throw failure
            },
        )
        active.response = response
        // Dispatch also awaits this Promise after the hook settles. Attach an immediate observer
        // so a handler that starts a response before awaiting other work cannot create a transient
        // unhandled rejection when the channel write fails in the meantime.
        void response.catch(() => undefined)
        return response
    }

    private writePacket(packet: SFTPPacket): Promise<void> {
        const frame = encodeSFTPPacket(packet)
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
        this.active.clear()
        this.activeRequestIds.clear()
        this.activeResources.clear()
        this.handlePathResources.clear()
        this.activeHandleTypes.clear()
        this.pendingHandleKeys.clear()
        this.activeOrderingBarriers = 0
        this.awaitingResponse.clear()
        this.queued.length = 0
        this.requestIds.clear()
        this.emit("close")
        if (!this.stream.destroyed && !this.stream.writableEnded) this.stream.end()
    }

    private fail(error: Error): void {
        if (this.closed) return
        this.closed = true
        this.active.clear()
        this.activeRequestIds.clear()
        this.activeResources.clear()
        this.handlePathResources.clear()
        this.activeHandleTypes.clear()
        this.pendingHandleKeys.clear()
        this.activeOrderingBarriers = 0
        this.awaitingResponse.clear()
        this.queued.length = 0
        this.requestIds.clear()
        if (this.listenerCount("error") > 0) this.emit("error", error)
        this.emit("close")
    }
}

function pathResource(path: Buffer): string {
    return `path:${path.toString("base64")}`
}

function handleResource(handle: Buffer): string {
    return `handle:${handle.toString("base64")}`
}

function isRequest(packet: SFTPPacket): packet is SFTPRequestPacket {
    return REQUEST_HOOK_NAMES.has(packet.type)
}

function ownExtensions(extensions: readonly SFTPExtension[]): readonly SFTPExtension[] {
    return Object.freeze(
        extensions.map((extension) => {
            validateSSHName(extension.name, "SFTP extension name")
            if (!Buffer.isBuffer(extension.data)) {
                throw new TypeError("SFTP extension data must be a buffer")
            }
            return Object.freeze({ name: extension.name, data: Buffer.from(extension.data) })
        }),
    )
}

function normalizeTransferLimit(
    value: number | undefined,
    defaultValue: number,
    maximum: number,
    operation: "read" | "write",
): number {
    const limit = value === undefined ? defaultValue : value
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > maximum) {
        throw new RangeError(`SFTP maximum ${operation} length must be between 1 and ${maximum}`)
    }
    return limit
}

function ownResponseBuffer(value: Buffer, name: string): Buffer {
    if (!Buffer.isBuffer(value)) throw new TypeError(`SFTP ${name} must be a buffer`)
    return Buffer.from(value)
}

function ownResponseAttributes(attributes: SFTPAttributes): Readonly<SFTPAttributes> {
    if (typeof attributes !== "object" || attributes === null || Array.isArray(attributes)) {
        throw new TypeError("SFTP response attributes must be an object")
    }
    if (attributes.extended !== undefined && !Array.isArray(attributes.extended)) {
        throw new TypeError("SFTP extended attributes must be an array")
    }
    return snapshotAttributes(attributes)
}

function ownResponseName(entry: SFTPNameEntry): Readonly<SFTPNameEntry> {
    if (typeof entry !== "object" || entry === null || Array.isArray(entry)) {
        throw new TypeError("SFTP name entry must be an object")
    }
    return Object.freeze({
        filename: ownResponseBuffer(entry.filename, "name filename"),
        longname: ownResponseBuffer(entry.longname, "name longname"),
        attributes: ownResponseAttributes(entry.attributes),
    })
}

function ownExtendedAttribute(attribute: SFTPExtendedAttribute): Readonly<SFTPExtendedAttribute> {
    if (typeof attribute !== "object" || attribute === null || Array.isArray(attribute)) {
        throw new TypeError("SFTP extended attribute must be an object")
    }
    return Object.freeze({
        type: ownResponseBuffer(attribute.type, "extended attribute type"),
        data: ownResponseBuffer(attribute.data, "extended attribute data"),
    })
}

function snapshotAttributes(attributes: SFTPAttributes): Readonly<SFTPAttributes> {
    return Object.freeze({
        ...attributes,
        ...(attributes.extended === undefined
            ? {}
            : {
                  extended: Object.freeze(
                      attributes.extended.map((attribute) => ownExtendedAttribute(attribute)),
                  ),
              }),
    })
}

function snapshotRequest(request: SFTPRequestPacket): Readonly<SFTPRequestPacket> {
    switch (request.type) {
        case SFTPPacketType.Open:
            return Object.freeze({
                ...request,
                filename: Buffer.from(request.filename),
                attributes: snapshotAttributes(request.attributes),
            })
        case SFTPPacketType.Close:
        case SFTPPacketType.FStat:
        case SFTPPacketType.ReadDir:
            return Object.freeze({ ...request, handle: Buffer.from(request.handle) })
        case SFTPPacketType.Read:
            return Object.freeze({ ...request, handle: Buffer.from(request.handle) })
        case SFTPPacketType.Write:
            return Object.freeze({
                ...request,
                handle: Buffer.from(request.handle),
                data: Buffer.from(request.data),
            })
        case SFTPPacketType.LStat:
        case SFTPPacketType.OpenDir:
        case SFTPPacketType.Remove:
        case SFTPPacketType.RmDir:
        case SFTPPacketType.RealPath:
        case SFTPPacketType.Stat:
        case SFTPPacketType.ReadLink:
            return Object.freeze({ ...request, path: Buffer.from(request.path) })
        case SFTPPacketType.SetStat:
        case SFTPPacketType.MkDir:
            return Object.freeze({
                ...request,
                path: Buffer.from(request.path),
                attributes: snapshotAttributes(request.attributes),
            })
        case SFTPPacketType.FSetStat:
            return Object.freeze({
                ...request,
                handle: Buffer.from(request.handle),
                attributes: snapshotAttributes(request.attributes),
            })
        case SFTPPacketType.Rename:
        case SFTPPacketType.SymLink:
            return Object.freeze({
                ...request,
                firstPath: Buffer.from(request.firstPath),
                secondPath: Buffer.from(request.secondPath),
            })
        case SFTPPacketType.Extended:
            return Object.freeze({ ...request, data: Buffer.from(request.data) })
        default: {
            const unsupported: never = request
            throw new SFTPProtocolError(
                `Cannot snapshot unsupported SFTP request type ${String(unsupported)}`,
            )
        }
    }
}

function expectsStatus(type: SFTPPacketType): boolean {
    return (
        type === SFTPPacketType.Close ||
        type === SFTPPacketType.Write ||
        type === SFTPPacketType.SetStat ||
        type === SFTPPacketType.FSetStat ||
        type === SFTPPacketType.Remove ||
        type === SFTPPacketType.MkDir ||
        type === SFTPPacketType.RmDir ||
        type === SFTPPacketType.Rename ||
        type === SFTPPacketType.SymLink ||
        type === SFTPPacketType.Extended
    )
}
