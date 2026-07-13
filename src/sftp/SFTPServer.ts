import EventEmitter from "node:events"
import type Shell from "../channels/Session/Shell.js"
import { encodeSFTPPacket, SFTPPacketParser, SFTPProtocolError } from "./codec.js"
import { SFTP_VERSION, SFTPPacketType, SFTPStatusCode } from "./constants.js"
import type {
    SFTPAttributes,
    SFTPExtension,
    SFTPNameEntry,
    SFTPPacket,
    SFTPRequestPacket,
} from "./types.js"

const MAX_QUEUED_REQUESTS = 1024

const STATUS_MESSAGES: Readonly<Record<number, string>> = {
    [SFTPStatusCode.Ok]: "No error",
    [SFTPStatusCode.EOF]: "End of file",
    [SFTPStatusCode.NoSuchFile]: "No such file or directory",
    [SFTPStatusCode.PermissionDenied]: "Permission denied",
    [SFTPStatusCode.Failure]: "Failure",
    [SFTPStatusCode.BadMessage]: "Bad message",
    [SFTPStatusCode.OperationUnsupported]: "Operation unsupported",
}

type RequestOf<T extends SFTPPacketType> = Readonly<SFTPRequestPacket & { type: T }>

// eslint-disable-next-line @typescript-eslint/consistent-type-definitions
export type SFTPServerEvents = {
    ready: [clientVersion: number]
    close: []
    error: [error: Error]
    requestReceived: [request: Readonly<SFTPRequestPacket>]
    request: [request: Readonly<SFTPRequestPacket>]
    OPEN: [request: RequestOf<SFTPPacketType.Open>]
    CLOSE: [request: RequestOf<SFTPPacketType.Close>]
    READ: [request: RequestOf<SFTPPacketType.Read>]
    WRITE: [request: RequestOf<SFTPPacketType.Write>]
    LSTAT: [request: RequestOf<SFTPPacketType.LStat>]
    FSTAT: [request: RequestOf<SFTPPacketType.FStat>]
    SETSTAT: [request: RequestOf<SFTPPacketType.SetStat>]
    FSETSTAT: [request: RequestOf<SFTPPacketType.FSetStat>]
    OPENDIR: [request: RequestOf<SFTPPacketType.OpenDir>]
    READDIR: [request: RequestOf<SFTPPacketType.ReadDir>]
    REMOVE: [request: RequestOf<SFTPPacketType.Remove>]
    MKDIR: [request: RequestOf<SFTPPacketType.MkDir>]
    RMDIR: [request: RequestOf<SFTPPacketType.RmDir>]
    REALPATH: [request: RequestOf<SFTPPacketType.RealPath>]
    STAT: [request: RequestOf<SFTPPacketType.Stat>]
    RENAME: [request: RequestOf<SFTPPacketType.Rename>]
    READLINK: [request: RequestOf<SFTPPacketType.ReadLink>]
    SYMLINK: [request: RequestOf<SFTPPacketType.SymLink>]
    EXTENDED: [request: RequestOf<SFTPPacketType.Extended>]
}

export interface SFTPServerOptions {
    extensions?: readonly SFTPExtension[]
    openSSHSymlinkArguments?: boolean
}

export interface SFTPSymlinkPaths {
    targetPath: Buffer
    linkPath: Buffer
}

const REQUEST_EVENT_NAMES = new Map<SFTPPacketType, keyof SFTPServerEvents>([
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
    readonly protocolVersion = SFTP_VERSION
    readonly stream: Shell
    readonly extensions: readonly SFTPExtension[]
    readonly openSSHSymlinkArguments: boolean

    private readonly parser = new SFTPPacketParser()
    private readonly queued: SFTPRequestPacket[] = []
    private readonly requestIds = new Set<number>()
    private active: SFTPRequestPacket | undefined
    private initialized = false
    private closed = false
    private dispatchScheduled = false

    constructor(stream: Shell, options: SFTPServerOptions = {}) {
        super()
        this.stream = stream
        this.extensions = options.extensions ?? []
        this.openSSHSymlinkArguments = options.openSSHSymlinkArguments ?? false
        stream.on("data", (data: Buffer) => this.receive(data))
        stream.once("end", () => this.handleEnd())
        stream.once("close", () => this.handleEnd())
        stream.once("error", (error) => this.fail(error))
    }

    status(requestId: number, code: SFTPStatusCode, message = "", languageTag = ""): void {
        if (code === SFTPStatusCode.NoConnection || code === SFTPStatusCode.ConnectionLost) {
            throw new Error("SFTP servers must not send client-only connection status codes")
        }
        if (!(code in STATUS_MESSAGES)) throw new Error(`Unknown SFTP v3 status code ${code}`)
        const request = this.requireActive(requestId)
        if (code === SFTPStatusCode.Ok && !expectsStatus(request.type)) {
            throw new Error(`SFTP request type ${request.type} requires a data response on success`)
        }
        this.respond({
            type: SFTPPacketType.Status,
            requestId,
            code,
            message: message || STATUS_MESSAGES[code] || "",
            languageTag,
        })
    }

    handle(requestId: number, handle: Buffer): void {
        const request = this.requireActive(requestId)
        if (
            request.type !== SFTPPacketType.Open &&
            request.type !== SFTPPacketType.OpenDir &&
            request.type !== SFTPPacketType.Extended
        ) {
            throw new Error("SFTP HANDLE is only valid for OPEN and OPENDIR")
        }
        this.respond({ type: SFTPPacketType.Handle, requestId, handle })
    }

    data(requestId: number, data: Buffer): void {
        const request = this.requireActive(requestId)
        if (request.type !== SFTPPacketType.Read && request.type !== SFTPPacketType.Extended) {
            throw new Error("SFTP DATA is only valid for READ")
        }
        if (request.type === SFTPPacketType.Read && data.length > request.length) {
            throw new Error("SFTP DATA exceeds the requested read length")
        }
        this.respond({ type: SFTPPacketType.Data, requestId, data })
    }

    name(requestId: number, names: SFTPNameEntry | readonly SFTPNameEntry[]): void {
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
        this.respond({ type: SFTPPacketType.Name, requestId, names: entries })
    }

    attributes(requestId: number, attributes: SFTPAttributes): void {
        const request = this.requireActive(requestId)
        if (
            request.type !== SFTPPacketType.Stat &&
            request.type !== SFTPPacketType.LStat &&
            request.type !== SFTPPacketType.FStat &&
            request.type !== SFTPPacketType.Extended
        ) {
            throw new Error("SFTP ATTRS is not valid for this request")
        }
        this.respond({ type: SFTPPacketType.Attrs, requestId, attributes })
    }

    extendedReply(requestId: number, data: Buffer): void {
        const request = this.requireActive(requestId)
        if (request.type !== SFTPPacketType.Extended) {
            throw new Error("SFTP EXTENDED_REPLY is only valid for EXTENDED requests")
        }
        this.respond({ type: SFTPPacketType.ExtendedReply, requestId, data })
    }

    symlinkPaths(request: RequestOf<SFTPPacketType.SymLink>): Readonly<SFTPSymlinkPaths> {
        return Object.freeze(
            this.openSSHSymlinkArguments
                ? { targetPath: request.firstPath, linkPath: request.secondPath }
                : { linkPath: request.firstPath, targetPath: request.secondPath },
        )
    }

    destroy(error?: Error): void {
        if (!this.closed) this.stream.destroy(error)
        this.fail(error ?? new Error("SFTP server session closed"))
    }

    private receive(data: Buffer): void {
        try {
            for (const packet of this.parser.push(data)) this.receivePacket(packet)
        } catch (error) {
            const protocolError = error instanceof Error ? error : new Error(String(error))
            this.fail(protocolError)
            this.stream.destroy(protocolError)
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
            this.writePacket({
                type: SFTPPacketType.Version,
                version: SFTP_VERSION,
                extensions: this.extensions,
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
        if (this.queued.length >= MAX_QUEUED_REQUESTS) {
            throw new SFTPProtocolError(`SFTP request queue exceeds ${MAX_QUEUED_REQUESTS}`)
        }
        this.requestIds.add(packet.requestId)
        this.queued.push(packet)
        this.emit("requestReceived", packet)
        this.scheduleDispatch()
    }

    private scheduleDispatch(): void {
        if (this.dispatchScheduled || this.active || this.closed) return
        this.dispatchScheduled = true
        queueMicrotask(() => {
            this.dispatchScheduled = false
            try {
                this.dispatch()
            } catch (error) {
                const failure = error instanceof Error ? error : new Error(String(error))
                this.fail(failure)
                this.stream.destroy(failure)
            }
        })
    }

    private dispatch(): void {
        if (this.active || this.closed) return
        const request = this.queued.shift()
        if (!request) return
        this.active = request
        const eventName = REQUEST_EVENT_NAMES.get(request.type)
        if (!eventName) throw new SFTPProtocolError(`Unsupported SFTP request type ${request.type}`)
        if (this.listenerCount(eventName) > 0) {
            this.emit(eventName, request as never)
        } else if (this.listenerCount("request") > 0) {
            this.emit("request", request)
        } else {
            this.status(request.requestId, SFTPStatusCode.OperationUnsupported)
        }
    }

    private requireActive(requestId: number): SFTPRequestPacket {
        if (this.closed) throw new Error("SFTP server session is closed")
        if (!this.active || this.active.requestId !== requestId) {
            throw new Error(`SFTP request ${requestId} is not awaiting a response`)
        }
        return this.active
    }

    private respond(packet: SFTPPacket): void {
        if (!("requestId" in packet)) throw new Error("SFTP response has no request id")
        const request = this.requireActive(packet.requestId)
        this.writePacket(packet)
        this.active = undefined
        this.requestIds.delete(request.requestId)
        this.scheduleDispatch()
    }

    private writePacket(packet: SFTPPacket): void {
        const frame = encodeSFTPPacket(packet)
        this.stream.write(frame, (error) => {
            if (!error) return
            this.fail(error)
            this.stream.destroy(error)
        })
    }

    private handleEnd(): void {
        if (this.closed) return
        try {
            this.parser.end()
        } catch (error) {
            this.fail(error instanceof Error ? error : new Error(String(error)))
            return
        }
        this.closed = true
        this.active = undefined
        this.queued.length = 0
        this.requestIds.clear()
        this.emit("close")
        if (!this.stream.destroyed && !this.stream.writableEnded) this.stream.end()
    }

    private fail(error: Error): void {
        if (this.closed) return
        this.closed = true
        this.active = undefined
        this.queued.length = 0
        this.requestIds.clear()
        if (this.listenerCount("error") > 0) this.emit("error", error)
        this.emit("close")
    }
}

function isRequest(packet: SFTPPacket): packet is SFTPRequestPacket {
    return REQUEST_EVENT_NAMES.has(packet.type)
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
