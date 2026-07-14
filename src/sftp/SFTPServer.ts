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
}

export interface SFTPSymlinkPaths {
    targetPath: Buffer
    linkPath: Buffer
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
    readonly extensions: readonly SFTPExtension[]
    readonly openSSHSymlinkArguments: boolean

    private readonly parser = new SFTPPacketParser()
    private readonly queued: SFTPRequestPacket[] = []
    private readonly requestIds = new Set<number>()
    private active: SFTPRequestPacket | undefined
    private initialized = false
    private closed = false
    private dispatchScheduled = false
    private hookError: Error | undefined

    constructor(stream: Shell, options: SFTPServerOptions = {}) {
        super()
        this.stream = stream
        this.extensions = Object.freeze(
            (options.extensions ?? []).map((extension) => {
                validateSSHName(extension.name, "SFTP extension name")
                return Object.freeze({ name: extension.name, data: Buffer.from(extension.data) })
            }),
        )
        this.openSSHSymlinkArguments = options.openSSHSymlinkArguments ?? false
        this.hooker.on("uncaughtException", (_event, error) => {
            this.hookError = error
        })
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

    symlinkPaths(request: SFTPRequestOf<SFTPPacketType.SymLink>): Readonly<SFTPSymlinkPaths> {
        return Object.freeze(
            this.openSSHSymlinkArguments
                ? { targetPath: request.firstPath, linkPath: request.secondPath }
                : { linkPath: request.firstPath, targetPath: request.secondPath },
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
            void this.dispatch().catch((error: unknown) => {
                const failure = error instanceof Error ? error : new Error(String(error))
                this.destroy(failure)
            })
        })
    }

    private async dispatch(): Promise<void> {
        if (this.active || this.closed) return
        const request = this.queued.shift()
        if (!request) return
        this.active = request
        const hookName = REQUEST_HOOK_NAMES.get(request.type)
        if (!hookName) throw new SFTPProtocolError(`Unsupported SFTP request type ${request.type}`)
        this.hookError = undefined
        if (this.hooker.hasHooks(hookName)) {
            await this.triggerRequestHook(hookName, request)
        } else if (this.hooker.hasHooks("request")) {
            await this.hooker.triggerHook("request", request)
        } else {
            this.status(request.requestId, SFTPStatusCode.OperationUnsupported)
            return
        }
        if (this.hookError && this.active === request) {
            this.status(request.requestId, SFTPStatusCode.Failure, "SFTP request handler failed")
            return
        }
        if (this.active === request) {
            this.status(
                request.requestId,
                SFTPStatusCode.Failure,
                "SFTP request handler returned without a response",
            )
        }
    }

    private triggerRequestHook(
        hookName: keyof SFTPServerHooker,
        request: Readonly<SFTPRequestPacket>,
    ): Promise<void> {
        // REQUEST_HOOK_NAMES is the single mapping between each discriminated packet and hook.
        return this.hooker.triggerHook(hookName, request as SFTPServerHooker[typeof hookName][0])
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
    return REQUEST_HOOK_NAMES.has(packet.type)
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
