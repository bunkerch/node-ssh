import EventEmitter from "node:events"
import type Shell from "../channels/Session/Shell.js"
import { Hooker } from "../utils/Hooker.js"
import { validateSSHName } from "../utils/SSHName.js"
import { encodeSFTPPacket, SFTPPacketParser, SFTPProtocolError } from "./codec.js"
import { SFTP_VERSION, SFTPPacketType, SFTPStatusCode } from "./constants.js"
import type {
    SFTPAttributes,
    SFTPExtension,
    SFTPNameEntry,
    SFTPPacket,
    SFTPRequestPacket,
} from "./types.js"

const MAX_OUTSTANDING_REQUESTS = 1024
const DEFAULT_MAX_CONCURRENT_REQUESTS = 64

const STATUS_MESSAGES: Readonly<Record<number, string>> = {
    [SFTPStatusCode.Ok]: "No error",
    [SFTPStatusCode.EOF]: "End of file",
    [SFTPStatusCode.NoSuchFile]: "No such file or directory",
    [SFTPStatusCode.PermissionDenied]: "Permission denied",
    [SFTPStatusCode.Failure]: "Failure",
    [SFTPStatusCode.BadMessage]: "Bad message",
    [SFTPStatusCode.OperationUnsupported]: "Operation unsupported",
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
}

export interface SFTPSymlinkPaths {
    targetPath: Buffer
    linkPath: Buffer
}

interface ActiveSFTPRequest {
    readonly request: SFTPRequestPacket
    response?: Promise<void>
}

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
    private readonly queued: SFTPRequestPacket[] = []
    private readonly requestIds = new Set<number>()
    private readonly active = new Set<ActiveSFTPRequest>()
    private readonly activeRequestIds = new Set<number>()
    private readonly awaitingResponse = new Map<number, ActiveSFTPRequest>()
    private initialized = false
    private closed = false
    private dispatchScheduled = false

    constructor(stream: Shell, options: SFTPServerOptions = {}) {
        super()
        this.stream = stream
        this.advertisedExtensions = ownExtensions(options.extensions ?? [])
        this.openSSHSymlinkArguments = options.openSSHSymlinkArguments ?? false
        this.#maxConcurrentRequests =
            options.maxConcurrentRequests ?? DEFAULT_MAX_CONCURRENT_REQUESTS
        if (
            !Number.isSafeInteger(this.#maxConcurrentRequests) ||
            this.#maxConcurrentRequests < 1 ||
            this.#maxConcurrentRequests > MAX_OUTSTANDING_REQUESTS
        ) {
            throw new RangeError(
                `SFTP maximum concurrent requests must be between 1 and ${MAX_OUTSTANDING_REQUESTS}`,
            )
        }
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

    get extensions(): readonly SFTPExtension[] {
        return ownExtensions(this.advertisedExtensions)
    }

    status(requestId: number, code: SFTPStatusCode, message = "", languageTag = ""): Promise<void> {
        if (code === SFTPStatusCode.NoConnection || code === SFTPStatusCode.ConnectionLost) {
            throw new Error("SFTP servers must not send client-only connection status codes")
        }
        if (!(code in STATUS_MESSAGES)) throw new Error(`Unknown SFTP v3 status code ${code}`)
        const request = this.requireActive(requestId)
        if (code === SFTPStatusCode.Ok && !expectsStatus(request.type)) {
            throw new Error(`SFTP request type ${request.type} requires a data response on success`)
        }
        return this.respond({
            type: SFTPPacketType.Status,
            requestId,
            code,
            message: message || STATUS_MESSAGES[code] || "",
            languageTag,
        })
    }

    handle(requestId: number, handle: Buffer): Promise<void> {
        const request = this.requireActive(requestId)
        if (
            request.type !== SFTPPacketType.Open &&
            request.type !== SFTPPacketType.OpenDir &&
            request.type !== SFTPPacketType.Extended
        ) {
            throw new Error("SFTP HANDLE is only valid for OPEN and OPENDIR")
        }
        return this.respond({ type: SFTPPacketType.Handle, requestId, handle })
    }

    data(requestId: number, data: Buffer): Promise<void> {
        const request = this.requireActive(requestId)
        if (request.type !== SFTPPacketType.Read && request.type !== SFTPPacketType.Extended) {
            throw new Error("SFTP DATA is only valid for READ")
        }
        if (request.type === SFTPPacketType.Read && data.length > request.length) {
            throw new Error("SFTP DATA exceeds the requested read length")
        }
        return this.respond({ type: SFTPPacketType.Data, requestId, data })
    }

    name(requestId: number, names: SFTPNameEntry | readonly SFTPNameEntry[]): Promise<void> {
        const request = this.requireActive(requestId)
        const entries = Array.isArray(names) ? names : [names]
        if (entries.length === 0) throw new Error("SFTP NAME must contain at least one entry")
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
        return this.respond({ type: SFTPPacketType.Attrs, requestId, attributes })
    }

    extendedReply(requestId: number, data: Buffer): Promise<void> {
        const request = this.requireActive(requestId)
        if (request.type !== SFTPPacketType.Extended) {
            throw new Error("SFTP EXTENDED_REPLY is only valid for EXTENDED requests")
        }
        return this.respond({ type: SFTPPacketType.ExtendedReply, requestId, data })
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
            const queuedIndex = this.queued.findIndex(
                (request) => !this.activeRequestIds.has(request.requestId),
            )
            if (queuedIndex === -1) return
            const [request] = this.queued.splice(queuedIndex, 1)
            const active: ActiveSFTPRequest = { request }
            this.active.add(active)
            this.activeRequestIds.add(request.requestId)
            this.awaitingResponse.set(request.requestId, active)
            void this.dispatch(active).then(
                () => {
                    this.active.delete(active)
                    this.activeRequestIds.delete(request.requestId)
                    this.scheduleDispatch()
                },
                (error: unknown) => {
                    const failure = error instanceof Error ? error : new Error(String(error))
                    this.destroy(failure)
                },
            )
        }
    }

    private async dispatch(active: ActiveSFTPRequest): Promise<void> {
        const { request } = active
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
        this.awaitingResponse.clear()
        this.queued.length = 0
        this.requestIds.clear()
        if (this.listenerCount("error") > 0) this.emit("error", error)
        this.emit("close")
    }
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

function snapshotAttributes(attributes: SFTPAttributes): Readonly<SFTPAttributes> {
    return Object.freeze({
        ...attributes,
        ...(attributes.extended === undefined
            ? {}
            : {
                  extended: Object.freeze(
                      attributes.extended.map((attribute) =>
                          Object.freeze({
                              type: Buffer.from(attribute.type),
                              data: Buffer.from(attribute.data),
                          }),
                      ),
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
