import type ClientSessionChannel from "../channels/ClientSessionChannel.js"
import { constants as bufferConstants } from "node:buffer"
import EventEmitter, { once } from "node:events"
import { open as openLocalFile } from "node:fs/promises"
import type { FileHandle } from "node:fs/promises"
import { validateSSHName } from "../utils/SSHName.js"
import { encodeSFTPPacket, SFTPPacketParser, SFTPProtocolError } from "./codec.js"
import {
    MAX_SFTP_HANDLE_LENGTH,
    MAX_SFTP_PACKET_LENGTH,
    SFTP_VERSION,
    SFTPOpenFlags,
    SFTPPacketType,
    SFTPStatusCode,
    validateSFTPOpenFlags,
} from "./constants.js"
import {
    decodeSFTPLimits,
    decodeSFTPStatVFS,
    decodeSFTPUsersGroups,
    encodeSFTPCopyDataExtension,
    encodeSFTPExtensionString,
    encodeSFTPLSetStatExtension,
    encodeSFTPTwoPathExtension,
    encodeSFTPUsersGroupsExtension,
} from "./openssh.js"
import type { SFTPLimits, SFTPStatVFS, SFTPUserGroupNames } from "./openssh.js"
import { SFTPStats, sftpNameEntry, sftpStats, type SFTPClientNameEntry } from "./SFTPStats.js"
import {
    SFTPReadStream,
    SFTPWriteStream,
    type SFTPReadStreamOptions,
    type SFTPWriteStreamOptions,
} from "./streams.js"
import type {
    SFTPAttributes,
    SFTPExtension,
    SFTPExtensionResponsePacket,
    SFTPExtensionResponseType,
    SFTPPacket,
    SFTPRequestPacketBase,
    SFTPStatusPacket,
} from "./types.js"
import { decodeSSHUTF8, encodeSSHUTF8 } from "../utils/SSHText.js"
import { isPlainConfigurationObject } from "../utils/Configuration.js"
import { normalizeTimeout } from "../utils/Timeout.js"
import { validateSFTPDirectoryEntryName, validateSFTPRealPath } from "./names.js"

export interface SFTPExtendedRequestOptions {
    /** Require this exact advertised extension version. */
    version?: string
    /** Successful packet types accepted for this extension. Defaults to EXTENDED_REPLY. */
    expectedTypes?: readonly SFTPExtensionResponseType[]
}

export interface SFTPClientOptions {
    /** Maximum integer milliseconds for initialization or a reply. Range: 1 through 2147483647. */
    requestTimeout?: number
}

export function normalizeSFTPClientOptions(
    options: SFTPClientOptions,
    defaultRequestTimeout = 30_000,
): Readonly<Required<SFTPClientOptions>> {
    if (!isPlainConfigurationObject(options)) {
        throw new TypeError("SFTP client options must be an object")
    }
    const requestTimeout = normalizeTimeout(
        options.requestTimeout,
        defaultRequestTimeout,
        "SFTP request timeout",
    )
    return Object.freeze({ requestTimeout })
}

const MAX_PENDING_REQUESTS = 1024
const DEFAULT_READ_WRITE_LENGTH = 32768
const MAX_EXTENSION_READ_WRITE_LENGTH = MAX_SFTP_PACKET_LENGTH - 2048
const DEFAULT_DIRECTORY_MAX_ENTRIES = 100_000
const DEFAULT_DIRECTORY_MAX_BYTES = 16 * 1024 * 1024
const UINT32_MAX = 0xffff_ffff

const STATUS_MESSAGES: Readonly<Record<number, string>> = {
    [SFTPStatusCode.Ok]: "No error",
    [SFTPStatusCode.EOF]: "End of file",
    [SFTPStatusCode.NoSuchFile]: "No such file or directory",
    [SFTPStatusCode.PermissionDenied]: "Permission denied",
    [SFTPStatusCode.Failure]: "Failure",
    [SFTPStatusCode.BadMessage]: "Bad message",
    [SFTPStatusCode.NoConnection]: "No connection",
    [SFTPStatusCode.ConnectionLost]: "Connection lost",
    [SFTPStatusCode.OperationUnsupported]: "Operation unsupported",
    [SFTPStatusCode.InvalidParameter]: "Invalid parameter",
}

const STRING_OPEN_FLAGS: Readonly<Record<string, number>> = {
    r: SFTPOpenFlags.Read,
    "r+": SFTPOpenFlags.Read | SFTPOpenFlags.Write,
    w: SFTPOpenFlags.Write | SFTPOpenFlags.Create | SFTPOpenFlags.Truncate,
    wx:
        SFTPOpenFlags.Write |
        SFTPOpenFlags.Create |
        SFTPOpenFlags.Truncate |
        SFTPOpenFlags.Exclusive,
    xw:
        SFTPOpenFlags.Write |
        SFTPOpenFlags.Create |
        SFTPOpenFlags.Truncate |
        SFTPOpenFlags.Exclusive,
    "w+": SFTPOpenFlags.Read | SFTPOpenFlags.Write | SFTPOpenFlags.Create | SFTPOpenFlags.Truncate,
    "wx+":
        SFTPOpenFlags.Read |
        SFTPOpenFlags.Write |
        SFTPOpenFlags.Create |
        SFTPOpenFlags.Truncate |
        SFTPOpenFlags.Exclusive,
    "xw+":
        SFTPOpenFlags.Read |
        SFTPOpenFlags.Write |
        SFTPOpenFlags.Create |
        SFTPOpenFlags.Truncate |
        SFTPOpenFlags.Exclusive,
    a: SFTPOpenFlags.Write | SFTPOpenFlags.Create | SFTPOpenFlags.Append,
    ax: SFTPOpenFlags.Write | SFTPOpenFlags.Create | SFTPOpenFlags.Append | SFTPOpenFlags.Exclusive,
    xa: SFTPOpenFlags.Write | SFTPOpenFlags.Create | SFTPOpenFlags.Append | SFTPOpenFlags.Exclusive,
    "a+": SFTPOpenFlags.Read | SFTPOpenFlags.Write | SFTPOpenFlags.Create | SFTPOpenFlags.Append,
    "ax+":
        SFTPOpenFlags.Read |
        SFTPOpenFlags.Write |
        SFTPOpenFlags.Create |
        SFTPOpenFlags.Append |
        SFTPOpenFlags.Exclusive,
    "xa+":
        SFTPOpenFlags.Read |
        SFTPOpenFlags.Write |
        SFTPOpenFlags.Create |
        SFTPOpenFlags.Append |
        SFTPOpenFlags.Exclusive,
}

export const OPEN_MODE = Object.freeze({
    READ: SFTPOpenFlags.Read,
    WRITE: SFTPOpenFlags.Write,
    APPEND: SFTPOpenFlags.Append,
    CREAT: SFTPOpenFlags.Create,
    TRUNC: SFTPOpenFlags.Truncate,
    EXCL: SFTPOpenFlags.Exclusive,
})

export const STATUS_CODE = Object.freeze({
    OK: SFTPStatusCode.Ok,
    EOF: SFTPStatusCode.EOF,
    NO_SUCH_FILE: SFTPStatusCode.NoSuchFile,
    PERMISSION_DENIED: SFTPStatusCode.PermissionDenied,
    FAILURE: SFTPStatusCode.Failure,
    BAD_MESSAGE: SFTPStatusCode.BadMessage,
    NO_CONNECTION: SFTPStatusCode.NoConnection,
    CONNECTION_LOST: SFTPStatusCode.ConnectionLost,
    OP_UNSUPPORTED: SFTPStatusCode.OperationUnsupported,
    INVALID_PARAMETER: SFTPStatusCode.InvalidParameter,
})

interface PendingRequest {
    requestType: SFTPPacketType
    expectedTypes: ReadonlySet<SFTPPacketType>
    resolve: (packet: SFTPPacket) => void
    reject: (error: Error) => void
}

type SFTPHandleType = "file" | "directory" | "extension"

export type SFTPPath = string | Buffer
export type SFTPPosition = number | bigint
export type SFTPNameEncoding = "utf8" | "buffer"

export interface SFTPReadFileOptions {
    encoding?: BufferEncoding | null
    flag?: string | number
    maxBytes?: number
}

export interface SFTPReadDirectoryOptions {
    /** Maximum non-dot entries retained by readDirectory. Defaults to 100,000. */
    maxEntries?: number
    /** Maximum bytes retained in entry names and extended attributes. Defaults to 16 MiB. */
    maxBytes?: number
}

export interface SFTPWriteFileOptions {
    encoding?: BufferEncoding
    flag?: string | number
    mode?: number | string
}

export interface SFTPFastGetOptions {
    chunkSize?: number
    concurrency?: number
}

export interface SFTPFastPutOptions extends SFTPFastGetOptions {
    mode?: number | string
}

export interface SFTPTransferProgress {
    readonly remotePath: Buffer
    readonly localPath: string
    readonly transferred: number
    readonly chunk: number
    readonly total: number
}

export interface SFTPClientEvents {
    downloadProgress: [progress: SFTPTransferProgress]
    uploadProgress: [progress: SFTPTransferProgress]
}

export interface SFTPReadResult {
    bytesRead: number
    buffer: Buffer
}

export interface SFTPWriteResult {
    bytesWritten: number
    buffer: Buffer
}

export class SFTPStatusError extends Error {
    readonly code: number
    readonly requestId: number
    readonly languageTag: string

    constructor(packet: SFTPStatusPacket) {
        super(packet.message || STATUS_MESSAGES[packet.code] || `SFTP status ${packet.code}`)
        this.name = "SFTPStatusError"
        this.code = packet.code
        this.requestId = packet.requestId
        this.languageTag = packet.languageTag
    }
}

export function sftpOpenFlags(flags: string | number): number {
    if (typeof flags === "number") {
        validateSFTPOpenFlags(flags)
        return flags
    }
    const value = STRING_OPEN_FLAGS[flags]
    if (value === undefined) throw new Error(`Unknown SFTP open flags: ${flags}`)
    return value
}

export function stringToFlags(flags: string): number | null {
    return STRING_OPEN_FLAGS[flags] ?? null
}

export function flagsToString(flags: number): string | null {
    for (const [name, value] of Object.entries(STRING_OPEN_FLAGS)) {
        if (value === flags) return name
    }
    return null
}

export default class SFTPClient extends EventEmitter<SFTPClientEvents> {
    readonly protocolVersion = SFTP_VERSION
    readonly channel: ClientSessionChannel
    readonly isOpenSSH: boolean
    readonly requestTimeout: number
    maxReadLength = DEFAULT_READ_WRITE_LENGTH
    maxWriteLength = DEFAULT_READ_WRITE_LENGTH
    maxOpenHandles: number | undefined
    limits: Readonly<SFTPLimits> | undefined

    private readonly parser = new SFTPPacketParser()
    private negotiatedExtensions: readonly SFTPExtension[] = Object.freeze([])
    private readonly pending = new Map<number, PendingRequest>()
    private readonly activeHandles = new Map<string, SFTPHandleType>()
    private pendingHandleRequests = 0
    private nextRequestId = 0
    private initialized = false
    private closed = false
    private closePromise: Promise<void> | undefined
    private readyResolve!: () => void
    private readyReject!: (error: Error) => void
    private readonly ready: Promise<void>

    private constructor(
        channel: ClientSessionChannel,
        isOpenSSH: boolean,
        options: SFTPClientOptions,
    ) {
        super()
        this.channel = channel
        this.isOpenSSH = isOpenSSH
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
        isOpenSSH = false,
        options: SFTPClientOptions = {},
    ): Promise<SFTPClient> {
        if (typeof isOpenSSH !== "boolean") {
            throw new TypeError("SFTP OpenSSH compatibility flag must be a boolean")
        }
        const client = new SFTPClient(channel, isOpenSSH, normalizeSFTPClientOptions(options))
        try {
            await client.waitForResponse(
                Promise.all([
                    client.writePacket({
                        type: SFTPPacketType.Init,
                        version: SFTP_VERSION,
                        extensions: [],
                    }),
                    client.ready,
                ]).then(() => undefined),
                "initialization",
            )
            await client.negotiateLimits()
            return client
        } catch (error) {
            client.destroy(error instanceof Error ? error : new Error(String(error)))
            throw error
        }
    }

    get extensions(): readonly SFTPExtension[] {
        return ownExtensions(this.negotiatedExtensions)
    }

    supportsExtension(name: string, version?: string): boolean {
        validateSSHName(name, "SFTP extension name")
        const versionBytes =
            version === undefined ? undefined : encodeSSHUTF8(version, "SFTP extension version")
        return this.negotiatedExtensions.some(
            (extension) =>
                extension.name === name &&
                (versionBytes === undefined || extension.data.equals(versionBytes)),
        )
    }

    extended(
        name: string,
        data: Buffer = Buffer.alloc(0),
        options: SFTPExtendedRequestOptions = {},
    ): Promise<SFTPExtensionResponsePacket> {
        try {
            validateSSHName(name, "SFTP extension name")
        } catch (error) {
            return Promise.reject(error)
        }
        if (!Buffer.isBuffer(data)) {
            return Promise.reject(new TypeError("SFTP extension data must be a buffer"))
        }
        if (!this.supportsExtension(name, options.version)) {
            const version = options.version === undefined ? "" : ` version ${options.version}`
            return Promise.reject(new Error(`SFTP server does not advertise ${name}${version}`))
        }
        const expectedTypes = options.expectedTypes ?? [SFTPPacketType.ExtendedReply]
        if (!Array.isArray(expectedTypes) || expectedTypes.length === 0) {
            return Promise.reject(
                new TypeError("SFTP extension must accept at least one response type"),
            )
        }
        const allowed = new Set<number>([
            SFTPPacketType.Status,
            SFTPPacketType.Handle,
            SFTPPacketType.Data,
            SFTPPacketType.Name,
            SFTPPacketType.Attrs,
            SFTPPacketType.ExtendedReply,
        ])
        if (expectedTypes.some((type) => !allowed.has(type))) {
            return Promise.reject(new TypeError("Invalid SFTP extension response type"))
        }
        const request = {
            type: SFTPPacketType.Extended,
            requestId: this.allocateRequestId(),
            request: name,
            data: Buffer.from(data),
        } as const
        const responseTypes = [...new Set(expectedTypes)]
        return (
            responseTypes.includes(SFTPPacketType.Handle)
                ? this.extensionHandle(request, responseTypes)
                : this.request(request, ...responseTypes)
        ) as Promise<SFTPExtensionResponsePacket>
    }

    createReadStream(path: SFTPPath, options?: SFTPReadStreamOptions): SFTPReadStream {
        return new SFTPReadStream(this, path, options)
    }

    createWriteStream(path: SFTPPath, options?: SFTPWriteStreamOptions): SFTPWriteStream {
        return new SFTPWriteStream(this, path, options)
    }

    async exists(path: SFTPPath): Promise<boolean> {
        try {
            await this.stat(path)
            return true
        } catch (error) {
            if (error instanceof SFTPStatusError && error.code === SFTPStatusCode.NoSuchFile) {
                return false
            }
            throw error
        }
    }

    async readFile(path: SFTPPath): Promise<Buffer>
    async readFile(path: SFTPPath, encoding: BufferEncoding): Promise<string>
    async readFile(
        path: SFTPPath,
        options: SFTPReadFileOptions & { encoding: BufferEncoding },
    ): Promise<string>
    async readFile(path: SFTPPath, options?: SFTPReadFileOptions): Promise<Buffer>
    async readFile(
        path: SFTPPath,
        options: BufferEncoding | SFTPReadFileOptions = {},
    ): Promise<Buffer | string> {
        const normalized = normalizeReadFileOptions(options)
        const maxBytes = normalized.maxBytes ?? bufferConstants.MAX_LENGTH
        validateMaximumFileBytes(maxBytes)

        const contents = await this.withFileHandle(
            path,
            normalized.flag ?? "r",
            {},
            async (handle) => {
                const attributes = await this.fstat(handle)
                if (attributes.size !== undefined && attributes.size > BigInt(maxBytes)) {
                    throw new RangeError(`SFTP file exceeds the ${maxBytes}-byte read limit`)
                }

                const chunks: Buffer[] = []
                let total = 0
                let position = 0n
                while (true) {
                    const knownRemaining =
                        attributes.size === undefined ? undefined : attributes.size - position
                    if (knownRemaining !== undefined && knownRemaining <= 0n) break
                    const length =
                        knownRemaining === undefined
                            ? this.maxReadLength
                            : Number(
                                  knownRemaining < BigInt(this.maxReadLength)
                                      ? knownRemaining
                                      : BigInt(this.maxReadLength),
                              )
                    let chunk: Buffer
                    try {
                        chunk = await this.read(handle, length, position)
                    } catch (error) {
                        if (error instanceof SFTPStatusError && error.code === SFTPStatusCode.EOF)
                            break
                        throw error
                    }
                    if (chunk.length === 0) break
                    total += chunk.length
                    if (total > maxBytes) {
                        throw new RangeError(`SFTP file exceeds the ${maxBytes}-byte read limit`)
                    }
                    chunks.push(chunk)
                    position += BigInt(chunk.length)
                }
                return Buffer.concat(chunks, total)
            },
        )

        return normalized.encoding ? contents.toString(normalized.encoding) : contents
    }

    async writeFile(
        path: SFTPPath,
        data: string | Buffer,
        options: BufferEncoding | SFTPWriteFileOptions = {},
    ): Promise<void> {
        const normalized = normalizeWriteFileOptions(options)
        const contents = Buffer.isBuffer(data)
            ? Buffer.from(data)
            : Buffer.from(data, normalized.encoding ?? "utf8")
        const flag = normalized.flag ?? "w"
        const mode = parseMode(normalized.mode ?? 0o666)
        await this.withFileHandle(path, flag, { permissions: mode }, async (handle) => {
            const append = (sftpOpenFlags(flag) & SFTPOpenFlags.Append) !== 0
            const position = append ? ((await this.fstat(handle)).size ?? 0n) : 0n
            await this.write(handle, contents, position)
        })
    }

    appendFile(
        path: SFTPPath,
        data: string | Buffer,
        options: BufferEncoding | SFTPWriteFileOptions = {},
    ): Promise<void> {
        const normalized = normalizeWriteFileOptions(options)
        return this.writeFile(path, data, { ...normalized, flag: normalized.flag ?? "a" })
    }

    async fastGet(
        remotePath: SFTPPath,
        localPath: string,
        options: SFTPFastGetOptions = {},
    ): Promise<void> {
        if (!isPlainConfigurationObject(options)) {
            throw new TypeError("SFTP fastGet options must be an object")
        }
        const ownedRemotePath = Buffer.from(pathBuffer(remotePath))
        const chunkSize = transferChunkSize(options.chunkSize, this.maxReadLength)
        const concurrency = transferConcurrency(options.concurrency)
        const total = transferFileSize((await this.stat(ownedRemotePath)).size)
        const remoteHandle = await this.open(ownedRemotePath, "r")
        let localHandle: FileHandle | undefined
        let operationError: unknown
        try {
            localHandle = await openLocalFile(localPath, "w")
            let transferred = 0
            await runConcurrentTransfer(total, chunkSize, concurrency, async (offset, length) => {
                const data = await readRemoteChunk(this, remoteHandle, length, offset, total)
                await writeLocalChunk(localHandle!, data, offset)
                transferred += data.length
                this.emit("downloadProgress", {
                    remotePath: Buffer.from(ownedRemotePath),
                    localPath,
                    transferred,
                    chunk: data.length,
                    total,
                })
            })
        } catch (error) {
            operationError = error
        }
        operationError = await closeLocalFile(localHandle, operationError)
        operationError = await closeRemoteFile(this, remoteHandle, operationError)
        if (operationError !== undefined) throw operationError
    }

    async fastPut(
        localPath: string,
        remotePath: SFTPPath,
        options: SFTPFastPutOptions = {},
    ): Promise<void> {
        if (!isPlainConfigurationObject(options)) {
            throw new TypeError("SFTP fastPut options must be an object")
        }
        const ownedRemotePath = Buffer.from(pathBuffer(remotePath))
        const chunkSize = transferChunkSize(options.chunkSize, this.maxWriteLength)
        const concurrency = transferConcurrency(options.concurrency)
        const mode = options.mode === undefined ? undefined : parseMode(options.mode)
        const localHandle = await openLocalFile(localPath, "r")
        let remoteHandle: Buffer | undefined
        let operationError: unknown
        try {
            const localAttributes = await localHandle.stat({ bigint: true })
            const total = transferFileSize(localAttributes.size)
            remoteHandle = await this.open(ownedRemotePath, "w", {
                permissions: mode ?? parseMode(Number(localAttributes.mode & 0o777n)),
            })
            let transferred = 0
            await runConcurrentTransfer(total, chunkSize, concurrency, async (offset, length) => {
                const data = await readLocalChunk(localHandle, length, offset)
                await this.write(remoteHandle!, data, BigInt(offset))
                transferred += data.length
                this.emit("uploadProgress", {
                    remotePath: Buffer.from(ownedRemotePath),
                    localPath,
                    transferred,
                    chunk: data.length,
                    total,
                })
            })
        } catch (error) {
            operationError = error
        }
        if (remoteHandle !== undefined) {
            operationError = await closeRemoteFile(this, remoteHandle, operationError)
        }
        operationError = await closeLocalFile(localHandle, operationError)
        if (operationError !== undefined) throw operationError
    }

    async open(
        path: SFTPPath,
        flags: string | number,
        attributes: SFTPAttributes = {},
    ): Promise<Buffer> {
        return this.createHandle({
            type: SFTPPacketType.Open,
            requestId: this.allocateRequestId(),
            filename: pathBuffer(path),
            flags: sftpOpenFlags(flags),
            attributes,
        })
    }

    /** Close the SFTP session and settle after its SSH channel closes. */
    close(): Promise<void>
    /** Close one active remote file, directory, or extension handle. */
    close(handle: Buffer): Promise<void>
    close(handle?: Buffer): Promise<void> {
        return handle === undefined ? this.closeSession() : this.closeHandle(handle)
    }

    private async closeHandle(handle: Buffer): Promise<void> {
        const ownedHandle = this.activeHandle(handle)
        await this.requestPacket(
            {
                type: SFTPPacketType.Close,
                requestId: this.allocateRequestId(),
                handle: ownedHandle,
            },
            [SFTPPacketType.Status],
            () => this.releaseHandle(ownedHandle),
        )
    }

    read(handle: Buffer, length: number, position: SFTPPosition): Promise<Buffer>
    read(
        handle: Buffer,
        buffer: Buffer,
        bufferOffset: number,
        length: number,
        position: SFTPPosition,
    ): Promise<SFTPReadResult>
    async read(
        handle: Buffer,
        lengthOrBuffer: number | Buffer,
        positionOrBufferOffset: SFTPPosition,
        bufferLength?: number,
        bufferPosition?: SFTPPosition,
    ): Promise<Buffer | SFTPReadResult> {
        const ownedHandle = ownHandle(handle)
        let target: Buffer | undefined
        let bufferOffset = 0
        let length: number
        let offset: bigint
        if (Buffer.isBuffer(lengthOrBuffer)) {
            target = lengthOrBuffer
            const range = validateBufferRange(
                target,
                positionOrBufferOffset,
                bufferLength,
                "SFTP read",
            )
            bufferOffset = range.offset
            length = range.length
            offset = positionBigInt(bufferPosition)
        } else {
            length = lengthOrBuffer
            offset = positionBigInt(positionOrBufferOffset)
        }
        const maximumReadLength = this.maxReadLength
        if (!Number.isSafeInteger(maximumReadLength) || maximumReadLength < 1) {
            throw new RangeError("SFTP maximum read length must be a positive safe integer")
        }
        if (!Number.isSafeInteger(length) || length < 0 || length > maximumReadLength) {
            throw new RangeError(`SFTP read length must be between 0 and ${maximumReadLength}`)
        }
        this.requireHandleType(ownedHandle, "file")
        if (length === 0) {
            return target === undefined ? Buffer.alloc(0) : { bytesRead: 0, buffer: target }
        }
        const response = await this.request(
            {
                type: SFTPPacketType.Read,
                requestId: this.allocateRequestId(),
                handle: ownedHandle,
                offset,
                length,
            },
            SFTPPacketType.Data,
        )
        return this.peerResponse(() => {
            if (response.type !== SFTPPacketType.Data) {
                throw new SFTPProtocolError("Expected DATA")
            }
            if (response.data.length === 0) {
                throw new SFTPProtocolError(
                    "SFTP server returned empty data for a positive-length read",
                )
            }
            if (response.data.length > length) {
                throw new SFTPProtocolError("SFTP server returned more data than requested")
            }
            if (target === undefined) return response.data
            response.data.copy(target, bufferOffset)
            return { bytesRead: response.data.length, buffer: target }
        })
    }

    write(handle: Buffer, data: Buffer, position: SFTPPosition): Promise<void>
    write(
        handle: Buffer,
        buffer: Buffer,
        bufferOffset: number,
        length: number,
        position: SFTPPosition,
    ): Promise<SFTPWriteResult>
    async write(
        handle: Buffer,
        data: Buffer,
        positionOrBufferOffset: SFTPPosition,
        bufferLength?: number,
        bufferPosition?: SFTPPosition,
    ): Promise<void | SFTPWriteResult> {
        const ownedHandle = ownHandle(handle)
        if (!Buffer.isBuffer(data)) throw new TypeError("SFTP write data must be a buffer")
        const writesBufferRange = bufferLength !== undefined || bufferPosition !== undefined
        const range = writesBufferRange
            ? validateBufferRange(data, positionOrBufferOffset, bufferLength, "SFTP write")
            : { offset: 0, length: data.length }
        const ownedData = Buffer.from(data.subarray(range.offset, range.offset + range.length))
        const maximumWriteLength = this.maxWriteLength
        if (!Number.isSafeInteger(maximumWriteLength) || maximumWriteLength < 1) {
            throw new RangeError("SFTP maximum write length must be a positive safe integer")
        }
        this.requireHandleType(ownedHandle, "file")
        let offset = positionBigInt(writesBufferRange ? bufferPosition : positionOrBufferOffset)
        for (let start = 0; start < ownedData.length; start += maximumWriteLength) {
            const chunk = ownedData.subarray(start, start + maximumWriteLength)
            await this.statusRequest({
                type: SFTPPacketType.Write,
                requestId: this.allocateRequestId(),
                handle: ownedHandle,
                offset,
                data: chunk,
            })
            offset += BigInt(chunk.length)
        }
        if (writesBufferRange) return { bytesWritten: ownedData.length, buffer: data }
    }

    stat(path: SFTPPath): Promise<SFTPStats> {
        return this.pathAttributes(SFTPPacketType.Stat, path)
    }

    lstat(path: SFTPPath): Promise<SFTPStats> {
        return this.pathAttributes(SFTPPacketType.LStat, path)
    }

    async fstat(handle: Buffer): Promise<SFTPStats> {
        const ownedHandle = this.activeHandle(handle)
        const response = await this.request(
            {
                type: SFTPPacketType.FStat,
                requestId: this.allocateRequestId(),
                handle: ownedHandle,
            },
            SFTPPacketType.Attrs,
        )
        return this.peerResponse(() => {
            if (response.type !== SFTPPacketType.Attrs) {
                throw new SFTPProtocolError("Expected ATTRS")
            }
            return sftpStats(response.attributes)
        })
    }

    async setstat(path: SFTPPath, attributes: SFTPAttributes): Promise<void> {
        await this.statusRequest({
            type: SFTPPacketType.SetStat,
            requestId: this.allocateRequestId(),
            path: pathBuffer(path),
            attributes,
        })
    }

    async fsetstat(handle: Buffer, attributes: SFTPAttributes): Promise<void> {
        const ownedHandle = this.activeHandle(handle)
        await this.statusRequest({
            type: SFTPPacketType.FSetStat,
            requestId: this.allocateRequestId(),
            handle: ownedHandle,
            attributes,
        })
    }

    truncate(path: SFTPPath, length: SFTPPosition): Promise<void> {
        return this.setstat(path, { size: uint64BigInt(length, "SFTP truncate length") })
    }

    ftruncate(handle: Buffer, length: SFTPPosition): Promise<void> {
        return this.fsetstat(handle, {
            size: uint64BigInt(length, "SFTP truncate length"),
        })
    }

    async opendir(path: SFTPPath): Promise<Buffer> {
        return this.createHandle({
            type: SFTPPacketType.OpenDir,
            requestId: this.allocateRequestId(),
            path: pathBuffer(path),
        })
    }

    async readdir(handle: Buffer): Promise<readonly SFTPClientNameEntry[] | null> {
        const ownedHandle = ownHandle(handle)
        this.requireHandleType(ownedHandle, "directory")
        try {
            const response = await this.request(
                {
                    type: SFTPPacketType.ReadDir,
                    requestId: this.allocateRequestId(),
                    handle: ownedHandle,
                },
                SFTPPacketType.Name,
            )
            return this.peerResponse(() => {
                if (response.type !== SFTPPacketType.Name) {
                    throw new SFTPProtocolError("Expected NAME")
                }
                if (response.names.length === 0) {
                    throw new SFTPProtocolError(
                        "SFTP directory response must contain at least one name",
                    )
                }
                for (const entry of response.names) {
                    validateSFTPDirectoryEntryName(entry.filename)
                }
                return response.names.map(sftpNameEntry)
            })
        } catch (error) {
            if (error instanceof SFTPStatusError && error.code === SFTPStatusCode.EOF) return null
            throw error
        }
    }

    iterateDirectory(path: SFTPPath): AsyncGenerator<SFTPClientNameEntry, void, void> {
        return this.iterateOwnedDirectory(Buffer.from(pathBuffer(path)))
    }

    async readDirectory(
        path: SFTPPath,
        options: SFTPReadDirectoryOptions = {},
    ): Promise<readonly SFTPClientNameEntry[]> {
        const limits = normalizeReadDirectoryOptions(options)
        const entries: SFTPClientNameEntry[] = []
        let retainedBytes = 0
        for await (const entry of this.iterateDirectory(path)) {
            if (entries.length >= limits.maxEntries) {
                const noun = limits.maxEntries === 1 ? "entry" : "entries"
                throw new RangeError(
                    `SFTP directory exceeds the ${limits.maxEntries}-${noun} collection limit`,
                )
            }
            const entryBytes = retainedDirectoryEntryBytes(entry)
            if (entryBytes > limits.maxBytes - retainedBytes) {
                throw new RangeError(
                    `SFTP directory exceeds the ${limits.maxBytes}-byte collection limit`,
                )
            }
            entries.push(entry)
            retainedBytes += entryBytes
        }
        return entries
    }

    private async *iterateOwnedDirectory(
        path: Buffer,
    ): AsyncGenerator<SFTPClientNameEntry, void, void> {
        const directory = await this.opendir(path)
        let operationError: unknown
        try {
            while (true) {
                const batch = await this.readdir(directory)
                if (batch === null) break
                for (const entry of batch) {
                    if (!isDotDirectoryEntry(entry.filename)) yield entry
                }
            }
        } catch (error) {
            operationError = error
            throw error
        } finally {
            await this.closeDirectoryIterator(directory, operationError)
        }
    }

    private async closeDirectoryIterator(handle: Buffer, operationError: unknown): Promise<void> {
        try {
            await this.close(handle)
        } catch (closeError) {
            if (operationError === undefined) throw closeError
        }
    }

    async unlink(path: SFTPPath): Promise<void> {
        await this.pathStatus(SFTPPacketType.Remove, path)
    }

    remove(path: SFTPPath): Promise<void> {
        return this.unlink(path)
    }

    async mkdir(path: SFTPPath, attributes: SFTPAttributes = {}): Promise<void> {
        await this.statusRequest({
            type: SFTPPacketType.MkDir,
            requestId: this.allocateRequestId(),
            path: pathBuffer(path),
            attributes,
        })
    }

    rmdir(path: SFTPPath): Promise<void> {
        return this.pathStatus(SFTPPacketType.RmDir, path)
    }

    async rename(oldPath: SFTPPath, newPath: SFTPPath): Promise<void> {
        await this.statusRequest({
            type: SFTPPacketType.Rename,
            requestId: this.allocateRequestId(),
            firstPath: pathBuffer(oldPath),
            secondPath: pathBuffer(newPath),
        })
    }

    realpath(path: SFTPPath, encoding: "buffer"): Promise<Buffer>
    realpath(path: SFTPPath, encoding?: "utf8"): Promise<string>
    realpath(path: SFTPPath, encoding: SFTPNameEncoding = "utf8"): Promise<string | Buffer> {
        return this.singleName(SFTPPacketType.RealPath, path, encoding)
    }

    readlink(path: SFTPPath, encoding: "buffer"): Promise<Buffer>
    readlink(path: SFTPPath, encoding?: "utf8"): Promise<string>
    readlink(path: SFTPPath, encoding: SFTPNameEncoding = "utf8"): Promise<string | Buffer> {
        return this.singleName(SFTPPacketType.ReadLink, path, encoding)
    }

    async symlink(targetPath: SFTPPath, linkPath: SFTPPath): Promise<void> {
        const target = pathBuffer(targetPath)
        const link = pathBuffer(linkPath)
        await this.statusRequest({
            type: SFTPPacketType.SymLink,
            requestId: this.allocateRequestId(),
            firstPath: this.isOpenSSH ? target : link,
            secondPath: this.isOpenSSH ? link : target,
        })
    }

    opensshPosixRename(oldPath: SFTPPath, newPath: SFTPPath): Promise<void> {
        return this.extensionStatus(
            "posix-rename@openssh.com",
            "1",
            encodeSFTPTwoPathExtension(pathBuffer(oldPath), pathBuffer(newPath)),
        )
    }

    ext_openssh_rename(oldPath: SFTPPath, newPath: SFTPPath): Promise<void> {
        return this.opensshPosixRename(oldPath, newPath)
    }

    async opensshStatVFS(path: SFTPPath): Promise<Readonly<SFTPStatVFS>> {
        const response = await this.extensionRequest(
            "statvfs@openssh.com",
            "2",
            encodeSFTPExtensionString(pathBuffer(path)),
            SFTPPacketType.ExtendedReply,
        )
        return this.peerResponse(() => {
            if (response.type !== SFTPPacketType.ExtendedReply) {
                throw new SFTPProtocolError("Expected EXTENDED_REPLY")
            }
            return decodeSFTPStatVFS(response.data)
        })
    }

    ext_openssh_statvfs(path: SFTPPath): Promise<Readonly<SFTPStatVFS>> {
        return this.opensshStatVFS(path)
    }

    async opensshFStatVFS(handle: Buffer): Promise<Readonly<SFTPStatVFS>> {
        this.requireExtension("fstatvfs@openssh.com", "2")
        const ownedHandle = this.activeHandle(handle)
        const response = await this.extensionRequest(
            "fstatvfs@openssh.com",
            "2",
            encodeSFTPExtensionString(ownedHandle),
            SFTPPacketType.ExtendedReply,
        )
        return this.peerResponse(() => {
            if (response.type !== SFTPPacketType.ExtendedReply) {
                throw new SFTPProtocolError("Expected EXTENDED_REPLY")
            }
            return decodeSFTPStatVFS(response.data)
        })
    }

    ext_openssh_fstatvfs(handle: Buffer): Promise<Readonly<SFTPStatVFS>> {
        return this.opensshFStatVFS(handle)
    }

    opensshHardlink(oldPath: SFTPPath, newPath: SFTPPath): Promise<void> {
        return this.extensionStatus(
            "hardlink@openssh.com",
            "1",
            encodeSFTPTwoPathExtension(pathBuffer(oldPath), pathBuffer(newPath)),
        )
    }

    ext_openssh_hardlink(oldPath: SFTPPath, newPath: SFTPPath): Promise<void> {
        return this.opensshHardlink(oldPath, newPath)
    }

    async opensshFSync(handle: Buffer): Promise<void> {
        this.requireExtension("fsync@openssh.com", "1")
        const ownedHandle = this.activeHandle(handle)
        this.requireHandleType(ownedHandle, "file")
        await this.extensionStatus("fsync@openssh.com", "1", encodeSFTPExtensionString(ownedHandle))
    }

    ext_openssh_fsync(handle: Buffer): Promise<void> {
        return this.opensshFSync(handle)
    }

    opensshLSetStat(path: SFTPPath, attributes: SFTPAttributes): Promise<void> {
        return this.extensionStatus(
            "lsetstat@openssh.com",
            "1",
            encodeSFTPLSetStatExtension(pathBuffer(path), attributes),
        )
    }

    ext_openssh_lsetstat(path: SFTPPath, attributes: SFTPAttributes): Promise<void> {
        return this.opensshLSetStat(path, attributes)
    }

    opensshExpandPath(path: SFTPPath, encoding: "buffer"): Promise<Buffer>
    opensshExpandPath(path: SFTPPath, encoding?: "utf8"): Promise<string>
    opensshExpandPath(
        path: SFTPPath,
        encoding: SFTPNameEncoding = "utf8",
    ): Promise<string | Buffer> {
        return this.extensionSingleName(
            "expand-path@openssh.com",
            "1",
            encodeSFTPExtensionString(pathBuffer(path)),
            encoding,
        )
    }

    ext_openssh_expandPath(path: SFTPPath, encoding: "buffer"): Promise<Buffer>
    ext_openssh_expandPath(path: SFTPPath, encoding?: "utf8"): Promise<string>
    ext_openssh_expandPath(
        path: SFTPPath,
        encoding: SFTPNameEncoding = "utf8",
    ): Promise<string | Buffer> {
        return encoding === "buffer"
            ? this.opensshExpandPath(path, "buffer")
            : this.opensshExpandPath(path, "utf8")
    }

    async copyData(
        sourceHandle: Buffer,
        sourceOffset: SFTPPosition,
        length: SFTPPosition,
        destinationHandle: Buffer,
        destinationOffset: SFTPPosition,
    ): Promise<void> {
        this.requireExtension("copy-data", "1")
        const ownedSourceHandle = this.activeHandle(sourceHandle)
        this.requireHandleType(ownedSourceHandle, "file")
        const ownedDestinationHandle = this.activeHandle(destinationHandle)
        this.requireHandleType(ownedDestinationHandle, "file")
        await this.extensionStatus(
            "copy-data",
            "1",
            encodeSFTPCopyDataExtension(
                ownedSourceHandle,
                positionBigInt(sourceOffset),
                positionBigInt(length),
                ownedDestinationHandle,
                positionBigInt(destinationOffset),
            ),
        )
    }

    ext_copy_data(
        sourceHandle: Buffer,
        sourceOffset: SFTPPosition,
        length: SFTPPosition,
        destinationHandle: Buffer,
        destinationOffset: SFTPPosition,
    ): Promise<void> {
        return this.copyData(
            sourceHandle,
            sourceOffset,
            length,
            destinationHandle,
            destinationOffset,
        )
    }

    homeDirectory(username: string | Buffer, encoding: "buffer"): Promise<Buffer>
    homeDirectory(username?: string | Buffer, encoding?: "utf8"): Promise<string>
    homeDirectory(
        username: string | Buffer = "",
        encoding: SFTPNameEncoding = "utf8",
    ): Promise<string | Buffer> {
        return this.extensionSingleName(
            "home-directory",
            "1",
            encodeSFTPExtensionString(username),
            encoding,
        )
    }

    ext_home_dir(username: string | Buffer, encoding: "buffer"): Promise<Buffer>
    ext_home_dir(username?: string | Buffer, encoding?: "utf8"): Promise<string>
    ext_home_dir(
        username: string | Buffer = "",
        encoding: SFTPNameEncoding = "utf8",
    ): Promise<string | Buffer> {
        return encoding === "buffer"
            ? this.homeDirectory(username, "buffer")
            : this.homeDirectory(username, "utf8")
    }

    async usersGroups(
        uids: readonly number[],
        gids: readonly number[],
    ): Promise<Readonly<SFTPUserGroupNames>> {
        const uidCount = uids.length
        const gidCount = gids.length
        const response = await this.extensionRequest(
            "users-groups-by-id@openssh.com",
            "1",
            encodeSFTPUsersGroupsExtension(uids, gids),
            SFTPPacketType.ExtendedReply,
        )
        return this.peerResponse(() => {
            if (response.type !== SFTPPacketType.ExtendedReply) {
                throw new SFTPProtocolError("Expected EXTENDED_REPLY")
            }
            const names = decodeSFTPUsersGroups(response.data)
            if (names.usernames.length !== uidCount) {
                throw new SFTPProtocolError(
                    `SFTP users-groups reply returned ${names.usernames.length} username for ${uidCount} user IDs`,
                )
            }
            if (names.groupNames.length !== gidCount) {
                throw new SFTPProtocolError(
                    `SFTP users-groups reply returned ${names.groupNames.length} group name for ${gidCount} group IDs`,
                )
            }
            return names
        })
    }

    ext_users_groups(
        uids: readonly number[],
        gids: readonly number[],
    ): Promise<Readonly<SFTPUserGroupNames>> {
        return this.usersGroups(uids, gids)
    }

    async opensshLimits(): Promise<Readonly<SFTPLimits>> {
        const response = await this.extensionRequest(
            "limits@openssh.com",
            "1",
            Buffer.alloc(0),
            SFTPPacketType.ExtendedReply,
        )
        return this.peerResponse(() => {
            if (response.type !== SFTPPacketType.ExtendedReply) {
                throw new SFTPProtocolError("Expected EXTENDED_REPLY")
            }
            return decodeSFTPLimits(response.data)
        })
    }

    chmod(path: SFTPPath, mode: number | string): Promise<void> {
        return this.setstat(path, { permissions: parseMode(mode) })
    }

    fchmod(handle: Buffer, mode: number | string): Promise<void> {
        return this.fsetstat(handle, { permissions: parseMode(mode) })
    }

    chown(path: SFTPPath, uid: number, gid: number): Promise<void> {
        return this.setstat(path, { uid, gid })
    }

    fchown(handle: Buffer, uid: number, gid: number): Promise<void> {
        return this.fsetstat(handle, { uid, gid })
    }

    utimes(
        path: SFTPPath,
        accessTime: Date | number,
        modificationTime: Date | number,
    ): Promise<void> {
        return this.setstat(path, {
            accessTime: unixTime(accessTime),
            modificationTime: unixTime(modificationTime),
        })
    }

    futimes(
        handle: Buffer,
        accessTime: Date | number,
        modificationTime: Date | number,
    ): Promise<void> {
        return this.fsetstat(handle, {
            accessTime: unixTime(accessTime),
            modificationTime: unixTime(modificationTime),
        })
    }

    end(): void {
        if (!this.closed) this.channel.end()
    }

    [Symbol.asyncDispose](): Promise<void> {
        return this.closeSession()
    }

    destroy(error?: Error): void {
        if (!this.channel.destroyed) this.channel.destroy(error)
        this.fail(error ?? new Error("SFTP session closed"))
    }

    private closeSession(): Promise<void> {
        if (this.closePromise !== undefined) return this.closePromise
        if (this.channel.destroyed) return Promise.resolve()

        this.closePromise = this.waitForResponse(
            once(this.channel, "close").then(() => undefined),
            "channel close",
        )
        this.fail(new Error("SFTP session closed"))
        try {
            this.channel.close()
        } catch (error) {
            this.channel.destroy(error instanceof Error ? error : new Error(String(error)))
        }
        return this.closePromise
    }

    private async withFileHandle<T>(
        path: SFTPPath,
        flags: string | number,
        attributes: SFTPAttributes,
        operation: (handle: Buffer) => Promise<T>,
    ): Promise<T> {
        const handle = await this.open(path, flags, attributes)
        let value: T | undefined
        let operationError: unknown
        try {
            value = await operation(handle)
        } catch (error) {
            operationError = error
        }
        operationError = await closeRemoteFile(this, handle, operationError)
        if (operationError !== undefined) throw operationError
        return value as T
    }

    private async pathAttributes(
        type: SFTPPacketType.Stat | SFTPPacketType.LStat,
        path: SFTPPath,
    ): Promise<SFTPStats> {
        const response = await this.request(
            { type, requestId: this.allocateRequestId(), path: pathBuffer(path) },
            SFTPPacketType.Attrs,
        )
        return this.peerResponse(() => {
            if (response.type !== SFTPPacketType.Attrs) {
                throw new SFTPProtocolError("Expected ATTRS")
            }
            return sftpStats(response.attributes)
        })
    }

    private async pathStatus(
        type: SFTPPacketType.Remove | SFTPPacketType.RmDir,
        path: SFTPPath,
    ): Promise<void> {
        await this.statusRequest({
            type,
            requestId: this.allocateRequestId(),
            path: pathBuffer(path),
        })
    }

    private async singleName(
        type: SFTPPacketType.RealPath | SFTPPacketType.ReadLink,
        path: SFTPPath,
        encoding: SFTPNameEncoding,
    ): Promise<string | Buffer> {
        const response = await this.request(
            { type, requestId: this.allocateRequestId(), path: pathBuffer(path) },
            SFTPPacketType.Name,
        )
        return this.peerResponse(() => {
            if (response.type !== SFTPPacketType.Name || response.names.length !== 1) {
                throw new SFTPProtocolError("SFTP response must contain exactly one name")
            }
            if (type === SFTPPacketType.RealPath) {
                validateSFTPRealPath(response.names[0]!.filename)
            }
            return decodeSFTPName(response.names[0]!.filename, encoding)
        })
    }

    private async extensionSingleName(
        name: string,
        version: string,
        data: Buffer,
        encoding: SFTPNameEncoding,
    ): Promise<string | Buffer> {
        const response = await this.extensionRequest(name, version, data, SFTPPacketType.Name)
        return this.peerResponse(() => {
            if (response.type !== SFTPPacketType.Name || response.names.length !== 1) {
                throw new SFTPProtocolError("SFTP extension response must contain exactly one name")
            }
            return decodeSFTPName(response.names[0]!.filename, encoding)
        })
    }

    private async extensionStatus(name: string, version: string, data: Buffer): Promise<void> {
        await this.extensionRequest(name, version, data, SFTPPacketType.Status)
    }

    private extensionRequest(
        name: string,
        version: string,
        data: Buffer,
        ...expectedTypes: SFTPPacketType[]
    ): Promise<SFTPPacket> {
        this.requireExtension(name, version)
        return this.request(
            {
                type: SFTPPacketType.Extended,
                requestId: this.allocateRequestId(),
                request: name,
                data,
            },
            ...expectedTypes,
        )
    }

    private requireExtension(name: string, version: string): void {
        if (!this.supportsExtension(name, version)) {
            throw new Error(`SFTP server does not advertise ${name} version ${version}`)
        }
    }

    private async negotiateLimits(): Promise<void> {
        if (!this.supportsExtension("limits@openssh.com", "1")) return
        try {
            const limits = await this.opensshLimits()
            this.limits = limits
            this.maxReadLength = negotiatedLength(
                limits.maximumReadLength,
                limits.maximumPacketLength,
            )
            this.maxWriteLength = negotiatedLength(
                limits.maximumWriteLength,
                limits.maximumPacketLength,
            )
            this.maxOpenHandles =
                limits.maximumOpenHandles === 0n
                    ? Number.POSITIVE_INFINITY
                    : safeLimitNumber(limits.maximumOpenHandles)
        } catch (error) {
            if (!(error instanceof SFTPStatusError)) throw error
        }
    }

    private async statusRequest(packet: SFTPPacket & SFTPRequestPacketBase): Promise<void> {
        await this.request(packet, SFTPPacketType.Status)
    }

    private async createHandle(packet: SFTPPacket & SFTPRequestPacketBase): Promise<Buffer> {
        this.reserveHandle()
        try {
            const response = await this.request(packet, SFTPPacketType.Handle)
            return this.peerResponse(() => {
                if (response.type !== SFTPPacketType.Handle) {
                    throw new SFTPProtocolError("Expected HANDLE")
                }
                this.trackHandle(
                    response.handle,
                    packet.type === SFTPPacketType.Open ? "file" : "directory",
                )
                return response.handle
            })
        } finally {
            this.pendingHandleRequests--
        }
    }

    private async extensionHandle(
        packet: SFTPPacket & SFTPRequestPacketBase,
        expectedTypes: readonly SFTPPacketType[],
    ): Promise<SFTPPacket> {
        this.reserveHandle()
        try {
            const response = await this.request(packet, ...expectedTypes)
            if (response.type === SFTPPacketType.Handle) {
                this.peerResponse(() => this.trackHandle(response.handle, "extension"))
            }
            return response
        } finally {
            this.pendingHandleRequests--
        }
    }

    private reserveHandle(): void {
        const maximum = this.maxOpenHandles
        if (maximum !== undefined && maximum !== Number.POSITIVE_INFINITY) {
            if (!Number.isSafeInteger(maximum) || maximum < 1) {
                throw new RangeError(
                    "SFTP maximum open handles must be a positive safe integer or Infinity",
                )
            }
            if (this.activeHandles.size + this.pendingHandleRequests >= maximum) {
                const noun = maximum === 1 ? "handle" : "handles"
                throw new Error(`SFTP server permits at most ${maximum} active ${noun}`)
            }
        }
        this.pendingHandleRequests++
    }

    private trackHandle(handle: Buffer, type: SFTPHandleType): void {
        const key = handle.toString("base64")
        if (this.activeHandles.has(key)) {
            throw new SFTPProtocolError("SFTP server reused an active handle")
        }
        this.activeHandles.set(key, type)
    }

    private peerResponse<T>(decode: () => T): T {
        try {
            return decode()
        } catch (error) {
            const protocolError =
                error instanceof Error ? error : new SFTPProtocolError(String(error))
            this.destroy(protocolError)
            throw protocolError
        }
    }

    private releaseHandle(handle: Buffer): void {
        this.activeHandles.delete(handle.toString("base64"))
    }

    private activeHandle(handle: Buffer): Buffer {
        const ownedHandle = ownHandle(handle)
        if (!this.activeHandles.has(ownedHandle.toString("base64"))) {
            throw new Error("SFTP handle is not active")
        }
        return ownedHandle
    }

    private requireHandleType(handle: Buffer, expected: "file" | "directory"): void {
        const type = this.activeHandles.get(handle.toString("base64"))
        if (type === undefined) throw new Error("SFTP handle is not active")
        if (type === "extension") return
        if (type !== expected) {
            throw new Error(
                expected === "file"
                    ? "SFTP handle is not a file"
                    : "SFTP handle is not a directory",
            )
        }
    }

    private request(
        packet: SFTPPacket & SFTPRequestPacketBase,
        ...expectedTypes: SFTPPacketType[]
    ): Promise<SFTPPacket> {
        return this.requestPacket(packet, expectedTypes)
    }

    private requestPacket(
        packet: SFTPPacket & SFTPRequestPacketBase,
        expectedTypes: readonly SFTPPacketType[],
        onWrite?: () => void,
    ): Promise<SFTPPacket> {
        if (!this.initialized) return Promise.reject(new Error("SFTP client is not initialized"))
        if (this.closed) return Promise.reject(new Error("SFTP session is closed"))
        if (this.pending.size >= MAX_PENDING_REQUESTS) {
            return Promise.reject(
                new Error(`SFTP has ${MAX_PENDING_REQUESTS} outstanding requests`),
            )
        }
        let frame: Buffer
        try {
            frame = encodeSFTPPacket(packet)
        } catch (error) {
            return Promise.reject(error)
        }

        const request = new Promise<SFTPPacket>((resolve, reject) => {
            this.pending.set(packet.requestId, {
                requestType: packet.type,
                expectedTypes: new Set(expectedTypes),
                resolve,
                reject,
            })
        })
        const writing = this.writeFrame(frame)
        onWrite?.()
        void writing.catch((error: unknown) => {
            const pending = this.pending.get(packet.requestId)
            if (!pending) return
            this.pending.delete(packet.requestId)
            pending.reject(error instanceof Error ? error : new Error(String(error)))
        })
        return this.waitForResponse(request, `request ${packet.requestId} reply`)
    }

    private async waitForResponse<T>(operation: Promise<T>, description: string): Promise<T> {
        let timer: NodeJS.Timeout | undefined
        const timeout = new Promise<never>((_resolve, reject) => {
            timer = setTimeout(() => {
                const error = new Error(`Timed out waiting for SFTP ${description}`)
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

    private allocateRequestId(): number {
        for (let attempts = 0; attempts <= MAX_PENDING_REQUESTS; attempts++) {
            const requestId = this.nextRequestId
            this.nextRequestId = (this.nextRequestId + 1) >>> 0
            if (!this.pending.has(requestId)) return requestId
        }
        throw new Error("No SFTP request identifiers are available")
    }

    private writePacket(packet: SFTPPacket): Promise<void> {
        return this.writeFrame(encodeSFTPPacket(packet))
    }

    private writeFrame(frame: Buffer): Promise<void> {
        return new Promise<void>((resolve, reject) => {
            this.channel.write(frame, (error) => (error ? reject(error) : resolve()))
        })
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

    private receivePacket(packet: SFTPPacket): void {
        if (!this.initialized) {
            if (packet.type !== SFTPPacketType.Version) {
                throw new SFTPProtocolError("Expected SFTP VERSION packet")
            }
            if (packet.version !== SFTP_VERSION) {
                throw new SFTPProtocolError(`Unsupported SFTP protocol version ${packet.version}`)
            }
            this.initialized = true
            this.negotiatedExtensions = ownExtensions(packet.extensions)
            this.readyResolve()
            return
        }
        if (packet.type === SFTPPacketType.Version) {
            throw new SFTPProtocolError("Received duplicate SFTP VERSION packet")
        }
        if (!("requestId" in packet)) {
            throw new SFTPProtocolError(`Unexpected SFTP packet type ${packet.type}`)
        }
        const pending = this.pending.get(packet.requestId)
        if (!pending) {
            throw new SFTPProtocolError(`Unexpected SFTP response id ${packet.requestId}`)
        }
        if (packet.type === SFTPPacketType.Status) {
            validateServerStatus(packet.code, pending.requestType)
            if (packet.code !== SFTPStatusCode.Ok) {
                this.pending.delete(packet.requestId)
                pending.reject(new SFTPStatusError(packet))
                return
            }
            if (!pending.expectedTypes.has(SFTPPacketType.Status)) {
                throw new SFTPProtocolError("Received successful STATUS instead of response data")
            }
            this.pending.delete(packet.requestId)
            pending.resolve(packet)
            return
        }
        if (!pending.expectedTypes.has(packet.type)) {
            throw new SFTPProtocolError(`Unexpected SFTP response type ${packet.type}`)
        }
        this.pending.delete(packet.requestId)
        pending.resolve(packet)
    }

    private handleEnd(): void {
        if (this.closed) return
        try {
            this.parser.end()
        } catch (error) {
            this.destroy(error instanceof Error ? error : new Error(String(error)))
            return
        }
        this.fail(
            new SFTPStatusError({
                type: SFTPPacketType.Status,
                requestId: 0,
                code: SFTPStatusCode.ConnectionLost,
                message: "SFTP channel closed",
                languageTag: "",
            }),
        )
    }

    private fail(error: Error): void {
        if (this.closed) return
        this.closed = true
        if (!this.initialized) this.readyReject(error)
        for (const request of this.pending.values()) request.reject(error)
        this.pending.clear()
        this.activeHandles.clear()
    }
}

function validateServerStatus(code: number, requestType: SFTPPacketType): void {
    if (code === SFTPStatusCode.NoConnection || code === SFTPStatusCode.ConnectionLost) {
        throw new SFTPProtocolError("SFTP server returned a client-only connection status")
    }
    if (
        code === SFTPStatusCode.EOF &&
        requestType !== SFTPPacketType.Read &&
        requestType !== SFTPPacketType.ReadDir &&
        requestType !== SFTPPacketType.Extended
    ) {
        throw new SFTPProtocolError(
            "SFTP EOF status is only valid for READ, READDIR, and EXTENDED requests",
        )
    }
    if (code === SFTPStatusCode.InvalidParameter && requestType !== SFTPPacketType.Extended) {
        throw new SFTPProtocolError(
            "SFTP invalid-parameter status is only valid for extension requests",
        )
    }
}

function pathBuffer(path: SFTPPath): Buffer {
    return Buffer.isBuffer(path) ? path : encodeSSHUTF8(path, "SFTP path")
}

function ownExtensions(extensions: readonly SFTPExtension[]): readonly SFTPExtension[] {
    return Object.freeze(
        extensions.map((extension) =>
            Object.freeze({ name: extension.name, data: Buffer.from(extension.data) }),
        ),
    )
}

function decodeSFTPName(value: Buffer, encoding: SFTPNameEncoding): string | Buffer {
    return encoding === "buffer"
        ? Buffer.from(value)
        : decodeSSHUTF8(value, "SFTP returned filename")
}

function positionBigInt(position: unknown): bigint {
    return uint64BigInt(position, "SFTP position")
}

function validateBufferRange(
    buffer: Buffer,
    offset: unknown,
    length: unknown,
    operation: string,
): { offset: number; length: number } {
    if (!Number.isSafeInteger(offset) || (offset as number) < 0) {
        throw new RangeError(`${operation} buffer offset must be a non-negative safe integer`)
    }
    if (!Number.isSafeInteger(length) || (length as number) < 0) {
        throw new RangeError(`${operation} length must be a non-negative safe integer`)
    }
    const numericOffset = offset as number
    const numericLength = length as number
    if (numericOffset > buffer.length || numericLength > buffer.length - numericOffset) {
        throw new RangeError(`${operation} buffer range exceeds the buffer length`)
    }
    return { offset: numericOffset, length: numericLength }
}

function uint64BigInt(value: unknown, name: string): bigint {
    if (typeof value === "bigint") {
        if (value < 0n || value > 0xffff_ffff_ffff_ffffn) {
            throw new RangeError(`${name} must be a uint64`)
        }
        return value
    }
    if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
        throw new RangeError(`Numeric ${name} must be a non-negative safe integer`)
    }
    return BigInt(value)
}

function validateHandle(handle: Buffer): void {
    if (!Buffer.isBuffer(handle)) throw new TypeError("SFTP handle must be a buffer")
    if (handle.length > MAX_SFTP_HANDLE_LENGTH) {
        throw new RangeError(`SFTP handle exceeds ${MAX_SFTP_HANDLE_LENGTH} bytes`)
    }
}

function ownHandle(handle: Buffer): Buffer {
    validateHandle(handle)
    return Buffer.from(handle)
}

function safeLimitNumber(limit: bigint): number {
    return Number(limit > BigInt(Number.MAX_SAFE_INTEGER) ? Number.MAX_SAFE_INTEGER : limit)
}

function negotiatedLength(length: bigint, packetLength: bigint): number {
    let negotiated = length === 0n ? BigInt(DEFAULT_READ_WRITE_LENGTH) : length
    const packetMaximum =
        packetLength === 0n
            ? BigInt(MAX_EXTENSION_READ_WRITE_LENGTH)
            : packetLength > 2048n
              ? packetLength - 2048n
              : 1n
    if (packetMaximum < negotiated) negotiated = packetMaximum
    const implementationMaximum = BigInt(MAX_EXTENSION_READ_WRITE_LENGTH)
    if (implementationMaximum < negotiated) negotiated = implementationMaximum
    return safeLimitNumber(negotiated)
}

function normalizeReadFileOptions(
    options: BufferEncoding | SFTPReadFileOptions,
): SFTPReadFileOptions {
    const normalized = typeof options === "string" ? { encoding: options } : options
    if (normalized === null || typeof normalized !== "object") {
        throw new TypeError("SFTP readFile options must be an encoding or object")
    }
    if (normalized.encoding !== undefined && normalized.encoding !== null) {
        validateEncoding(normalized.encoding)
    }
    return normalized
}

function normalizeReadDirectoryOptions(
    options: SFTPReadDirectoryOptions,
): Readonly<Required<SFTPReadDirectoryOptions>> {
    if (!isPlainConfigurationObject(options)) {
        throw new TypeError("SFTP readDirectory options must be an object")
    }
    const maxEntries = options.maxEntries ?? DEFAULT_DIRECTORY_MAX_ENTRIES
    const maxBytes = options.maxBytes ?? DEFAULT_DIRECTORY_MAX_BYTES
    if (!Number.isSafeInteger(maxEntries) || maxEntries < 0) {
        throw new RangeError("SFTP readDirectory maxEntries must be a non-negative safe integer")
    }
    if (!Number.isSafeInteger(maxBytes) || maxBytes < 0) {
        throw new RangeError("SFTP readDirectory maxBytes must be a non-negative safe integer")
    }
    return Object.freeze({ maxEntries, maxBytes })
}

function isDotDirectoryEntry(filename: Buffer): boolean {
    return (
        (filename.length === 1 && filename[0] === 0x2e) ||
        (filename.length === 2 && filename[0] === 0x2e && filename[1] === 0x2e)
    )
}

function retainedDirectoryEntryBytes(entry: SFTPClientNameEntry): number {
    let bytes = entry.filename.length + entry.longname.length
    for (const attribute of entry.attributes.extended ?? []) {
        bytes += attribute.type.length + attribute.data.length
    }
    return bytes
}

function normalizeWriteFileOptions(
    options: BufferEncoding | SFTPWriteFileOptions,
): SFTPWriteFileOptions {
    const normalized = typeof options === "string" ? { encoding: options } : options
    if (normalized === null || typeof normalized !== "object") {
        throw new TypeError("SFTP writeFile options must be an encoding or object")
    }
    if (normalized.encoding !== undefined) validateEncoding(normalized.encoding)
    return normalized
}

function validateEncoding(encoding: string): asserts encoding is BufferEncoding {
    if (!Buffer.isEncoding(encoding)) throw new TypeError(`Unknown encoding: ${encoding}`)
}

function validateMaximumFileBytes(maxBytes: number): void {
    if (!Number.isSafeInteger(maxBytes) || maxBytes < 0 || maxBytes > bufferConstants.MAX_LENGTH) {
        throw new RangeError(
            `SFTP readFile maxBytes must be between 0 and ${bufferConstants.MAX_LENGTH}`,
        )
    }
}

function transferFileSize(size: bigint | undefined): number {
    if (size === undefined) throw new SFTPProtocolError("SFTP server omitted the file size")
    if (size > BigInt(Number.MAX_SAFE_INTEGER)) {
        throw new RangeError("SFTP transfer size exceeds JavaScript's safe integer range")
    }
    return Number(size)
}

function transferChunkSize(requested: number | undefined, maximum: number): number {
    const chunkSize = requested ?? DEFAULT_READ_WRITE_LENGTH
    if (!Number.isSafeInteger(chunkSize) || chunkSize <= 0) {
        throw new RangeError("SFTP transfer chunkSize must be a positive safe integer")
    }
    if (!Number.isSafeInteger(maximum) || maximum <= 0) {
        throw new RangeError("SFTP maximum transfer length must be a positive safe integer")
    }
    return Math.min(chunkSize, maximum)
}

function transferConcurrency(requested: number | undefined): number {
    const concurrency = requested ?? 64
    if (
        !Number.isSafeInteger(concurrency) ||
        concurrency <= 0 ||
        concurrency > MAX_PENDING_REQUESTS
    ) {
        throw new RangeError(
            `SFTP transfer concurrency must be between 1 and ${MAX_PENDING_REQUESTS}`,
        )
    }
    return concurrency
}

async function runConcurrentTransfer(
    total: number,
    chunkSize: number,
    concurrency: number,
    transfer: (offset: number, length: number) => Promise<void>,
): Promise<void> {
    let nextOffset = 0
    let firstError: unknown
    const worker = async (): Promise<void> => {
        while (firstError === undefined && nextOffset < total) {
            const offset = nextOffset
            const length = Math.min(chunkSize, total - offset)
            nextOffset += length
            try {
                await transfer(offset, length)
            } catch (error) {
                firstError ??= error
            }
        }
    }
    await Promise.all(
        Array.from({ length: Math.min(concurrency, Math.ceil(total / chunkSize)) }, worker),
    )
    if (firstError !== undefined) throw firstError
}

async function readLocalChunk(
    handle: FileHandle,
    length: number,
    position: number,
): Promise<Buffer> {
    const data = Buffer.allocUnsafe(length)
    let offset = 0
    while (offset < length) {
        const { bytesRead } = await handle.read(data, offset, length - offset, position + offset)
        if (bytesRead === 0) {
            throw new Error(`Local file ended after ${position + offset} bytes`)
        }
        offset += bytesRead
    }
    return data
}

async function readRemoteChunk(
    client: SFTPClient,
    handle: Buffer,
    length: number,
    position: number,
    total: number,
): Promise<Buffer> {
    const chunks: Buffer[] = []
    let offset = 0
    while (offset < length) {
        let chunk: Buffer
        try {
            chunk = await client.read(handle, length - offset, BigInt(position + offset))
        } catch (error) {
            if (error instanceof SFTPStatusError && error.code === SFTPStatusCode.EOF) {
                throw new SFTPProtocolError(
                    `SFTP file ended after ${position + offset} of ${total} bytes`,
                )
            }
            throw error
        }
        if (chunk.length === 0) {
            throw new SFTPProtocolError(
                `SFTP read made no progress after ${position + offset} of ${total} bytes`,
            )
        }
        chunks.push(chunk)
        offset += chunk.length
    }
    return chunks.length === 1 ? chunks[0]! : Buffer.concat(chunks, length)
}

async function writeLocalChunk(handle: FileHandle, data: Buffer, position: number): Promise<void> {
    let offset = 0
    while (offset < data.length) {
        const { bytesWritten } = await handle.write(
            data,
            offset,
            data.length - offset,
            position + offset,
        )
        if (bytesWritten === 0) throw new Error("Local file write made no progress")
        offset += bytesWritten
    }
}

async function closeLocalFile(
    handle: FileHandle | undefined,
    operationError: unknown,
): Promise<unknown> {
    if (handle === undefined) return operationError
    try {
        await handle.close()
    } catch (error) {
        return operationError ?? error
    }
    return operationError
}

async function closeRemoteFile(
    client: SFTPClient,
    handle: Buffer,
    operationError: unknown,
): Promise<unknown> {
    try {
        await client.close(handle)
    } catch (error) {
        return operationError ?? error
    }
    return operationError
}

function parseMode(mode: number | string): number {
    if (typeof mode === "string" && !/^[0-7]+$/u.test(mode)) {
        throw new RangeError("SFTP mode string must contain only octal digits")
    }
    const value = typeof mode === "string" ? Number.parseInt(mode, 8) : mode
    if (!Number.isSafeInteger(value) || value < 0 || value > UINT32_MAX) {
        throw new RangeError("SFTP mode must be a uint32 or an octal string")
    }
    return value
}

function unixTime(value: Date | number): number {
    const seconds = value instanceof Date ? Math.floor(value.getTime() / 1000) : Math.floor(value)
    if (!Number.isSafeInteger(seconds) || seconds < 0 || seconds > UINT32_MAX) {
        throw new RangeError("SFTP timestamp must fit in uint32 seconds since the Unix epoch")
    }
    return seconds
}
