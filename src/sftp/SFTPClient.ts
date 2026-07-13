import type ClientSessionChannel from "../channels/ClientSessionChannel.js"
import { constants as bufferConstants } from "node:buffer"
import { open as openLocalFile } from "node:fs/promises"
import type { FileHandle } from "node:fs/promises"
import { encodeSFTPPacket, SFTPPacketParser, SFTPProtocolError } from "./codec.js"
import {
    MAX_SFTP_HANDLE_LENGTH,
    MAX_SFTP_PACKET_LENGTH,
    SFTP_VERSION,
    SFTPOpenFlags,
    SFTPPacketType,
    SFTPStatusCode,
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
import {
    SFTPReadStream,
    SFTPWriteStream,
    type SFTPReadStreamOptions,
    type SFTPWriteStreamOptions,
} from "./streams.js"
import type {
    SFTPAttributes,
    SFTPExtension,
    SFTPNameEntry,
    SFTPPacket,
    SFTPRequestPacketBase,
    SFTPStatusPacket,
} from "./types.js"

const MAX_PENDING_REQUESTS = 1024
const DEFAULT_READ_WRITE_LENGTH = 32768
const MAX_EXTENSION_READ_WRITE_LENGTH = MAX_SFTP_PACKET_LENGTH - 2048
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

interface PendingRequest {
    expectedTypes: ReadonlySet<SFTPPacketType>
    resolve: (packet: SFTPPacket) => void
    reject: (error: Error) => void
}

export type SFTPPath = string | Buffer
export type SFTPPosition = number | bigint

export interface SFTPReadFileOptions {
    encoding?: BufferEncoding | null
    flag?: string | number
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
    step?: (totalTransferred: number, chunk: number, total: number) => void
}

export interface SFTPFastPutOptions extends SFTPFastGetOptions {
    mode?: number | string
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
        if (!Number.isSafeInteger(flags) || flags < 0 || flags > UINT32_MAX) {
            throw new RangeError("SFTP open flags must be a uint32")
        }
        const knownFlags =
            SFTPOpenFlags.Read |
            SFTPOpenFlags.Write |
            SFTPOpenFlags.Append |
            SFTPOpenFlags.Create |
            SFTPOpenFlags.Truncate |
            SFTPOpenFlags.Exclusive
        if ((flags & ~knownFlags) !== 0) throw new Error("SFTP open flags contain unknown bits")
        if (
            (flags & (SFTPOpenFlags.Truncate | SFTPOpenFlags.Exclusive)) !== 0 &&
            (flags & SFTPOpenFlags.Create) === 0
        ) {
            throw new Error("SFTP truncate and exclusive flags require create")
        }
        return flags
    }
    const value = STRING_OPEN_FLAGS[flags]
    if (value === undefined) throw new Error(`Unknown SFTP open flags: ${flags}`)
    return value
}

export default class SFTPClient {
    readonly protocolVersion = SFTP_VERSION
    readonly channel: ClientSessionChannel
    readonly isOpenSSH: boolean
    extensions: readonly SFTPExtension[] = []

    maxReadLength = DEFAULT_READ_WRITE_LENGTH
    maxWriteLength = DEFAULT_READ_WRITE_LENGTH
    maxOpenHandles: number | undefined
    limits: Readonly<SFTPLimits> | undefined

    private readonly parser = new SFTPPacketParser()
    private readonly pending = new Map<number, PendingRequest>()
    private nextRequestId = 0
    private initialized = false
    private closed = false
    private readyResolve!: () => void
    private readyReject!: (error: Error) => void
    private readonly ready: Promise<void>

    private constructor(channel: ClientSessionChannel, isOpenSSH: boolean) {
        this.channel = channel
        this.isOpenSSH = isOpenSSH
        this.ready = new Promise<void>((resolve, reject) => {
            this.readyResolve = resolve
            this.readyReject = reject
        })
        channel.on("data", (data: Buffer) => this.receive(data))
        channel.once("end", () => this.handleEnd())
        channel.once("close", () => this.handleEnd())
        channel.once("error", (error) => this.fail(error))
    }

    static async connect(channel: ClientSessionChannel, isOpenSSH = false): Promise<SFTPClient> {
        const client = new SFTPClient(channel, isOpenSSH)
        try {
            await client.writePacket({
                type: SFTPPacketType.Init,
                version: SFTP_VERSION,
                extensions: [],
            })
            await client.ready
            await client.negotiateLimits()
            return client
        } catch (error) {
            client.destroy(error instanceof Error ? error : new Error(String(error)))
            throw error
        }
    }

    supportsExtension(name: string, version?: string): boolean {
        return this.extensions.some(
            (extension) =>
                extension.name === name &&
                (version === undefined || extension.data.toString("ascii") === version),
        )
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
            ? data
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
        const total = transferFileSize((await this.stat(remotePath)).size)
        const chunkSize = transferChunkSize(options.chunkSize, this.maxReadLength)
        const concurrency = transferConcurrency(options.concurrency)
        const remoteHandle = await this.open(remotePath, "r")
        let localHandle: FileHandle | undefined
        let operationError: unknown
        try {
            localHandle = await openLocalFile(localPath, "w")
            let transferred = 0
            await runConcurrentTransfer(total, chunkSize, concurrency, async (offset, length) => {
                const data = await readRemoteChunk(this, remoteHandle, length, offset, total)
                await writeLocalChunk(localHandle!, data, offset)
                transferred += data.length
                options.step?.(transferred, data.length, total)
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
        const localHandle = await openLocalFile(localPath, "r")
        let remoteHandle: Buffer | undefined
        let operationError: unknown
        try {
            const localAttributes = await localHandle.stat({ bigint: true })
            const total = transferFileSize(localAttributes.size)
            const chunkSize = transferChunkSize(options.chunkSize, this.maxWriteLength)
            const concurrency = transferConcurrency(options.concurrency)
            remoteHandle = await this.open(remotePath, "w", {
                permissions: parseMode(options.mode ?? Number(localAttributes.mode & 0o777n)),
            })
            let transferred = 0
            await runConcurrentTransfer(total, chunkSize, concurrency, async (offset, length) => {
                const data = await readLocalChunk(localHandle, length, offset)
                await this.write(remoteHandle!, data, BigInt(offset))
                transferred += data.length
                options.step?.(transferred, data.length, total)
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
        const response = await this.request(
            {
                type: SFTPPacketType.Open,
                requestId: this.allocateRequestId(),
                filename: pathBuffer(path),
                flags: sftpOpenFlags(flags),
                attributes,
            },
            SFTPPacketType.Handle,
        )
        if (response.type !== SFTPPacketType.Handle) throw new SFTPProtocolError("Expected HANDLE")
        return response.handle
    }

    async close(handle: Buffer): Promise<void> {
        await this.statusRequest({
            type: SFTPPacketType.Close,
            requestId: this.allocateRequestId(),
            handle,
        })
    }

    async read(handle: Buffer, length: number, position: SFTPPosition): Promise<Buffer> {
        if (!Number.isSafeInteger(length) || length < 0 || length > this.maxReadLength) {
            throw new RangeError(`SFTP read length must be between 0 and ${this.maxReadLength}`)
        }
        if (length === 0) return Buffer.alloc(0)
        const response = await this.request(
            {
                type: SFTPPacketType.Read,
                requestId: this.allocateRequestId(),
                handle,
                offset: positionBigInt(position),
                length,
            },
            SFTPPacketType.Data,
        )
        if (response.type !== SFTPPacketType.Data) throw new SFTPProtocolError("Expected DATA")
        if (response.data.length > length) {
            throw new SFTPProtocolError("SFTP server returned more data than requested")
        }
        return response.data
    }

    async write(handle: Buffer, data: Buffer, position: SFTPPosition): Promise<void> {
        let offset = positionBigInt(position)
        for (let start = 0; start < data.length; start += this.maxWriteLength) {
            const chunk = data.subarray(start, start + this.maxWriteLength)
            await this.statusRequest({
                type: SFTPPacketType.Write,
                requestId: this.allocateRequestId(),
                handle,
                offset,
                data: chunk,
            })
            offset += BigInt(chunk.length)
        }
    }

    stat(path: SFTPPath): Promise<SFTPAttributes> {
        return this.pathAttributes(SFTPPacketType.Stat, path)
    }

    lstat(path: SFTPPath): Promise<SFTPAttributes> {
        return this.pathAttributes(SFTPPacketType.LStat, path)
    }

    async fstat(handle: Buffer): Promise<SFTPAttributes> {
        const response = await this.request(
            {
                type: SFTPPacketType.FStat,
                requestId: this.allocateRequestId(),
                handle,
            },
            SFTPPacketType.Attrs,
        )
        if (response.type !== SFTPPacketType.Attrs) throw new SFTPProtocolError("Expected ATTRS")
        return response.attributes
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
        await this.statusRequest({
            type: SFTPPacketType.FSetStat,
            requestId: this.allocateRequestId(),
            handle,
            attributes,
        })
    }

    async opendir(path: SFTPPath): Promise<Buffer> {
        const response = await this.request(
            {
                type: SFTPPacketType.OpenDir,
                requestId: this.allocateRequestId(),
                path: pathBuffer(path),
            },
            SFTPPacketType.Handle,
        )
        if (response.type !== SFTPPacketType.Handle) throw new SFTPProtocolError("Expected HANDLE")
        return response.handle
    }

    async readdir(handle: Buffer): Promise<readonly SFTPNameEntry[] | null> {
        try {
            const response = await this.request(
                {
                    type: SFTPPacketType.ReadDir,
                    requestId: this.allocateRequestId(),
                    handle,
                },
                SFTPPacketType.Name,
            )
            if (response.type !== SFTPPacketType.Name) throw new SFTPProtocolError("Expected NAME")
            return response.names
        } catch (error) {
            if (error instanceof SFTPStatusError && error.code === SFTPStatusCode.EOF) return null
            throw error
        }
    }

    async readDirectory(path: SFTPPath): Promise<readonly SFTPNameEntry[]> {
        const directory = await this.opendir(path)
        const entries: SFTPNameEntry[] = []
        let operationError: unknown
        try {
            while (true) {
                const batch = await this.readdir(directory)
                if (batch === null) break
                entries.push(
                    ...batch.filter(
                        (entry) =>
                            !entry.filename.equals(Buffer.from(".")) &&
                            !entry.filename.equals(Buffer.from("..")),
                    ),
                )
            }
        } catch (error) {
            operationError = error
        }
        try {
            await this.close(directory)
        } catch (closeError) {
            if (operationError === undefined) throw closeError
        }
        if (operationError !== undefined) throw operationError
        return entries
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

    realpath(path: SFTPPath): Promise<string> {
        return this.singleName(SFTPPacketType.RealPath, path)
    }

    readlink(path: SFTPPath): Promise<string> {
        return this.singleName(SFTPPacketType.ReadLink, path)
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
        if (response.type !== SFTPPacketType.ExtendedReply) {
            throw new SFTPProtocolError("Expected EXTENDED_REPLY")
        }
        return decodeSFTPStatVFS(response.data)
    }

    ext_openssh_statvfs(path: SFTPPath): Promise<Readonly<SFTPStatVFS>> {
        return this.opensshStatVFS(path)
    }

    async opensshFStatVFS(handle: Buffer): Promise<Readonly<SFTPStatVFS>> {
        validateHandle(handle)
        const response = await this.extensionRequest(
            "fstatvfs@openssh.com",
            "2",
            encodeSFTPExtensionString(handle),
            SFTPPacketType.ExtendedReply,
        )
        if (response.type !== SFTPPacketType.ExtendedReply) {
            throw new SFTPProtocolError("Expected EXTENDED_REPLY")
        }
        return decodeSFTPStatVFS(response.data)
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

    opensshFSync(handle: Buffer): Promise<void> {
        validateHandle(handle)
        return this.extensionStatus("fsync@openssh.com", "1", encodeSFTPExtensionString(handle))
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

    opensshExpandPath(path: SFTPPath): Promise<string> {
        return this.extensionSingleName(
            "expand-path@openssh.com",
            "1",
            encodeSFTPExtensionString(pathBuffer(path)),
        )
    }

    ext_openssh_expandPath(path: SFTPPath): Promise<string> {
        return this.opensshExpandPath(path)
    }

    copyData(
        sourceHandle: Buffer,
        sourceOffset: SFTPPosition,
        length: SFTPPosition,
        destinationHandle: Buffer,
        destinationOffset: SFTPPosition,
    ): Promise<void> {
        validateHandle(sourceHandle)
        validateHandle(destinationHandle)
        return this.extensionStatus(
            "copy-data",
            "1",
            encodeSFTPCopyDataExtension(
                sourceHandle,
                positionBigInt(sourceOffset),
                positionBigInt(length),
                destinationHandle,
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

    homeDirectory(username: string | Buffer = ""): Promise<string> {
        return this.extensionSingleName("home-directory", "1", encodeSFTPExtensionString(username))
    }

    ext_home_dir(username: string | Buffer = ""): Promise<string> {
        return this.homeDirectory(username)
    }

    async usersGroups(
        uids: readonly number[],
        gids: readonly number[],
    ): Promise<Readonly<SFTPUserGroupNames>> {
        const response = await this.extensionRequest(
            "users-groups-by-id@openssh.com",
            "1",
            encodeSFTPUsersGroupsExtension(uids, gids),
            SFTPPacketType.ExtendedReply,
        )
        if (response.type !== SFTPPacketType.ExtendedReply) {
            throw new SFTPProtocolError("Expected EXTENDED_REPLY")
        }
        return decodeSFTPUsersGroups(response.data)
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
        if (response.type !== SFTPPacketType.ExtendedReply) {
            throw new SFTPProtocolError("Expected EXTENDED_REPLY")
        }
        return decodeSFTPLimits(response.data)
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

    destroy(error?: Error): void {
        if (!this.closed) this.channel.destroy(error)
        this.fail(error ?? new Error("SFTP session closed"))
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
    ): Promise<SFTPAttributes> {
        const response = await this.request(
            { type, requestId: this.allocateRequestId(), path: pathBuffer(path) },
            SFTPPacketType.Attrs,
        )
        if (response.type !== SFTPPacketType.Attrs) throw new SFTPProtocolError("Expected ATTRS")
        return response.attributes
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
    ): Promise<string> {
        const response = await this.request(
            { type, requestId: this.allocateRequestId(), path: pathBuffer(path) },
            SFTPPacketType.Name,
        )
        if (response.type !== SFTPPacketType.Name || response.names.length !== 1) {
            throw new SFTPProtocolError("SFTP response must contain exactly one name")
        }
        return response.names[0]!.filename.toString("utf8")
    }

    private async extensionSingleName(
        name: string,
        version: string,
        data: Buffer,
    ): Promise<string> {
        const response = await this.extensionRequest(name, version, data, SFTPPacketType.Name)
        if (response.type !== SFTPPacketType.Name || response.names.length !== 1) {
            throw new SFTPProtocolError("SFTP extension response must contain exactly one name")
        }
        return response.names[0]!.filename.toString("utf8")
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

    private request(
        packet: SFTPPacket & SFTPRequestPacketBase,
        ...expectedTypes: SFTPPacketType[]
    ): Promise<SFTPPacket> {
        if (!this.initialized) return Promise.reject(new Error("SFTP client is not initialized"))
        if (this.closed) return Promise.reject(new Error("SFTP session is closed"))
        if (this.pending.size >= MAX_PENDING_REQUESTS) {
            return Promise.reject(
                new Error(`SFTP has ${MAX_PENDING_REQUESTS} outstanding requests`),
            )
        }

        const request = new Promise<SFTPPacket>((resolve, reject) => {
            this.pending.set(packet.requestId, {
                expectedTypes: new Set(expectedTypes),
                resolve,
                reject,
            })
        })
        void this.writePacket(packet).catch((error: unknown) => {
            const pending = this.pending.get(packet.requestId)
            if (!pending) return
            this.pending.delete(packet.requestId)
            pending.reject(error instanceof Error ? error : new Error(String(error)))
        })
        return request
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
        const frame = encodeSFTPPacket(packet)
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
            this.extensions = packet.extensions
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
            this.fail(error instanceof Error ? error : new Error(String(error)))
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
    }
}

function pathBuffer(path: SFTPPath): Buffer {
    return Buffer.isBuffer(path) ? path : Buffer.from(path, "utf8")
}

function positionBigInt(position: SFTPPosition): bigint {
    if (typeof position === "bigint") {
        if (position < 0n || position > 0xffff_ffff_ffff_ffffn) {
            throw new RangeError("SFTP position must be a uint64")
        }
        return position
    }
    if (!Number.isSafeInteger(position) || position < 0) {
        throw new RangeError("Numeric SFTP position must be a non-negative safe integer")
    }
    return BigInt(position)
}

function validateHandle(handle: Buffer): void {
    if (handle.length > MAX_SFTP_HANDLE_LENGTH) {
        throw new RangeError(`SFTP handle exceeds ${MAX_SFTP_HANDLE_LENGTH} bytes`)
    }
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
