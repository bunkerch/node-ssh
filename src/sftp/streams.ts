import { Readable, Writable } from "node:stream"
import type { ReadableOptions, WritableOptions } from "node:stream"
import type SFTPClient from "./SFTPClient.js"
import type { SFTPPath, SFTPPosition } from "./SFTPClient.js"
import { MAX_SFTP_HANDLE_LENGTH, SFTPOpenFlags, SFTPStatusCode } from "./constants.js"

const UINT32_MAX = 0xffff_ffff
const UINT64_MAX = 0xffff_ffff_ffff_ffffn

export interface SFTPReadStreamOptions extends ReadableOptions {
    autoClose?: boolean
    end?: SFTPPosition
    flags?: string | number
    handle?: Buffer
    mode?: number | string
    start?: SFTPPosition
}

export interface SFTPWriteStreamOptions extends WritableOptions {
    autoClose?: boolean
    flags?: string | number
    handle?: Buffer
    mode?: number | string
    start?: SFTPPosition
}

export class SFTPReadStream extends Readable {
    readonly flags: string | number
    readonly mode: number
    readonly autoClose: boolean
    readonly start: bigint
    readonly end: bigint

    bytesRead = 0n
    isClosed = false

    private readonly remotePath: SFTPPath
    private remoteHandle: Buffer | undefined
    private position: bigint
    private opening: Promise<void> | undefined
    private closing: Promise<void> | undefined
    private forceClose = false

    constructor(
        readonly sftp: SFTPClient,
        path: SFTPPath,
        options: SFTPReadStreamOptions = {},
    ) {
        const {
            autoClose = true,
            end,
            flags = "r",
            handle,
            mode = 0o666,
            start,
            ...stream
        } = options
        const ownedPath = streamPath(path)
        const ownedHandle = handle === undefined ? undefined : streamHandle(handle)
        super({ ...stream, autoDestroy: stream.autoDestroy ?? autoClose })
        this.remotePath = ownedPath
        this.flags = flags
        this.mode = streamMode(mode)
        this.autoClose = autoClose
        this.start = streamPosition(start ?? 0, "start")
        this.end = streamPosition(end ?? UINT64_MAX, "end")
        if (this.start > this.end) throw new RangeError("SFTP stream start must not exceed end")
        this.position = this.start
        this.remoteHandle = ownedHandle
        void this.ensureOpen().catch((error: unknown) => {
            this.destroy(error instanceof Error ? error : new Error(String(error)))
        })
    }

    get path(): SFTPPath {
        return Buffer.isBuffer(this.remotePath) ? Buffer.from(this.remotePath) : this.remotePath
    }

    get handle(): Buffer | undefined {
        return this.remoteHandle === undefined ? undefined : Buffer.from(this.remoteHandle)
    }

    get pending(): boolean {
        return this.remoteHandle === undefined && !this.isClosed
    }

    close(): Promise<void> {
        if (this.isClosed) return Promise.resolve()
        this.forceClose = true
        if (this.destroyed) return this.destroyStream()
        const closed = closePromise(this)
        this.destroy()
        return closed
    }

    override _read(size: number): void {
        void this.readNext(size).catch((error: unknown) => {
            this.destroy(error instanceof Error ? error : new Error(String(error)))
        })
    }

    override _destroy(error: Error | null, callback: (error?: Error | null) => void): void {
        void this.destroyStream().then(
            () => callback(error),
            (closeError: unknown) =>
                callback(
                    error ??
                        (closeError instanceof Error ? closeError : new Error(String(closeError))),
                ),
        )
    }

    private async ensureOpen(): Promise<void> {
        if (this.remoteHandle !== undefined) return
        if (this.opening !== undefined) return this.opening
        this.opening = this.sftp
            .open(this.remotePath, this.flags, { permissions: this.mode })
            .then((handle) => {
                const ownedHandle = streamHandle(handle)
                this.remoteHandle = ownedHandle
                this.emit("open", Buffer.from(ownedHandle))
                this.emit("ready")
            })
        return this.opening
    }

    private async readNext(size: number): Promise<void> {
        await this.ensureOpen()
        if (this.destroyed) return
        const remaining = this.end - this.position + 1n
        if (remaining <= 0n) {
            this.push(null)
            return
        }
        const requested = Math.min(Math.max(size, 1), this.sftp.maxReadLength)
        const length = Number(remaining < BigInt(requested) ? remaining : BigInt(requested))
        let data: Buffer
        try {
            data = await this.sftp.read(this.remoteHandle!, length, this.position)
        } catch (error) {
            if (isSFTPEOF(error)) {
                this.push(null)
                return
            }
            throw error
        }
        if (data.length === 0) {
            this.push(null)
            return
        }
        this.position += BigInt(data.length)
        this.bytesRead += BigInt(data.length)
        this.push(data)
        if (this.position > this.end) this.push(null)
    }

    private async destroyStream(): Promise<void> {
        if (!this.autoClose && !this.forceClose) return
        try {
            await this.opening
        } catch {
            return
        }
        await this.closeHandle()
    }

    private async closeHandle(): Promise<void> {
        if (this.closing !== undefined) return this.closing
        const handle = this.remoteHandle
        if (handle === undefined) {
            this.isClosed = true
            return
        }
        this.remoteHandle = undefined
        this.closing = this.sftp.close(handle).then(() => {
            this.isClosed = true
        })
        return this.closing
    }
}

export class SFTPWriteStream extends Writable {
    readonly flags: string | number
    readonly mode: number
    readonly autoClose: boolean
    readonly start: bigint

    bytesWritten = 0n
    isClosed = false

    private readonly remotePath: SFTPPath
    private remoteHandle: Buffer | undefined
    private position: bigint
    private opening: Promise<void> | undefined
    private closing: Promise<void> | undefined
    private forceClose = false

    constructor(
        readonly sftp: SFTPClient,
        path: SFTPPath,
        options: SFTPWriteStreamOptions = {},
    ) {
        const { autoClose = true, flags = "w", handle, mode = 0o666, start, ...stream } = options
        const ownedPath = streamPath(path)
        const ownedHandle = handle === undefined ? undefined : streamHandle(handle)
        super({ ...stream, autoDestroy: stream.autoDestroy ?? autoClose })
        this.remotePath = ownedPath
        this.flags = flags
        this.mode = streamMode(mode)
        this.autoClose = autoClose
        this.start = streamPosition(start ?? 0, "start")
        this.position = this.start
        this.remoteHandle = ownedHandle
        void this.ensureOpen().catch((error: unknown) => {
            this.destroy(error instanceof Error ? error : new Error(String(error)))
        })
    }

    get path(): SFTPPath {
        return Buffer.isBuffer(this.remotePath) ? Buffer.from(this.remotePath) : this.remotePath
    }

    get handle(): Buffer | undefined {
        return this.remoteHandle === undefined ? undefined : Buffer.from(this.remoteHandle)
    }

    get pending(): boolean {
        return this.remoteHandle === undefined && !this.isClosed
    }

    close(): Promise<void> {
        if (this.isClosed) return Promise.resolve()
        this.forceClose = true
        if (this.destroyed) return this.destroyStream()
        const closed = closePromise(this)
        this.end(() => this.destroy())
        return closed
    }

    destroySoon(): this {
        return this.end()
    }

    override _write(
        chunk: Buffer | string,
        encoding: BufferEncoding,
        callback: (error?: Error | null) => void,
    ): void {
        const data = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, encoding)
        void this.writeChunk(data).then(() => callback(), callback)
    }

    override _destroy(error: Error | null, callback: (error?: Error | null) => void): void {
        void this.destroyStream().then(
            () => callback(error),
            (closeError: unknown) =>
                callback(
                    error ??
                        (closeError instanceof Error ? closeError : new Error(String(closeError))),
                ),
        )
    }

    private async ensureOpen(): Promise<void> {
        if (this.remoteHandle !== undefined) return
        if (this.opening !== undefined) return this.opening
        this.opening = this.sftp
            .open(this.remotePath, this.flags, { permissions: this.mode })
            .then(async (handle) => {
                const ownedHandle = streamHandle(handle)
                this.remoteHandle = ownedHandle
                if (isAppendFlag(this.flags)) {
                    this.position = (await this.sftp.fstat(ownedHandle)).size ?? 0n
                }
                this.emit("open", Buffer.from(ownedHandle))
                this.emit("ready")
            })
        return this.opening
    }

    private async writeChunk(data: Buffer): Promise<void> {
        await this.ensureOpen()
        await this.sftp.write(this.remoteHandle!, data, this.position)
        this.position += BigInt(data.length)
        this.bytesWritten += BigInt(data.length)
    }

    private async destroyStream(): Promise<void> {
        if (!this.autoClose && !this.forceClose) return
        try {
            await this.opening
        } catch {
            return
        }
        await this.closeHandle()
    }

    private async closeHandle(): Promise<void> {
        if (this.closing !== undefined) return this.closing
        const handle = this.remoteHandle
        if (handle === undefined) {
            this.isClosed = true
            return
        }
        this.remoteHandle = undefined
        this.closing = this.sftp.close(handle).then(() => {
            this.isClosed = true
        })
        return this.closing
    }
}

function streamPath(path: SFTPPath): SFTPPath {
    if (typeof path === "string") return path
    if (!Buffer.isBuffer(path)) throw new TypeError("SFTP stream path must be a string or buffer")
    return Buffer.from(path)
}

function streamHandle(handle: Buffer): Buffer {
    if (!Buffer.isBuffer(handle)) throw new TypeError("SFTP stream handle must be a buffer")
    if (handle.length > MAX_SFTP_HANDLE_LENGTH) {
        throw new RangeError(`SFTP stream handle must not exceed ${MAX_SFTP_HANDLE_LENGTH} bytes`)
    }
    return Buffer.from(handle)
}

function streamPosition(position: SFTPPosition, name: string): bigint {
    const value = typeof position === "bigint" ? position : BigInt(position)
    if (
        (typeof position === "number" && !Number.isSafeInteger(position)) ||
        value < 0n ||
        value > UINT64_MAX
    ) {
        throw new RangeError(`SFTP stream ${name} must be a uint64 or safe integer`)
    }
    return value
}

function streamMode(mode: number | string): number {
    if (typeof mode === "string" && !/^[0-7]+$/u.test(mode)) {
        throw new RangeError("SFTP stream mode string must contain only octal digits")
    }
    const value = typeof mode === "string" ? Number.parseInt(mode, 8) : mode
    if (!Number.isSafeInteger(value) || value < 0 || value > UINT32_MAX) {
        throw new RangeError("SFTP stream mode must be a uint32 or octal string")
    }
    return value
}

function isAppendFlag(flags: string | number): boolean {
    return typeof flags === "string" ? flags.includes("a") : (flags & SFTPOpenFlags.Append) !== 0
}

function isSFTPEOF(error: unknown): boolean {
    return (
        typeof error === "object" &&
        error !== null &&
        "code" in error &&
        error.code === SFTPStatusCode.EOF
    )
}

function closePromise(stream: SFTPReadStream | SFTPWriteStream): Promise<void> {
    return new Promise((resolve, reject) => {
        const finish = (error?: Error): void => {
            stream.off("close", onClose)
            stream.off("error", onError)
            if (error) reject(error)
            else resolve()
        }
        const onClose = (): void => finish()
        const onError = (error: Error): void => finish(error)
        stream.once("close", onClose)
        stream.once("error", onError)
    })
}
