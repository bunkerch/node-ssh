import { decodeSFTPAttributes, encodeSFTPAttributes, SFTPProtocolError } from "./codec.js"
import { MAX_SFTP_HANDLE_LENGTH } from "./constants.js"
import type { SFTPAttributes } from "./types.js"
import { decodeSSHUTF8, encodeSSHUTF8 } from "../utils/SSHText.js"

const UINT32_MAX = 0xffff_ffff
const UINT64_MAX = 0xffff_ffff_ffff_ffffn

export interface SFTPStatVFS {
    blockSize: bigint
    fragmentSize: bigint
    blocks: bigint
    blocksFree: bigint
    blocksAvailable: bigint
    files: bigint
    filesFree: bigint
    filesAvailable: bigint
    filesystemId: bigint
    flags: bigint
    maximumFilenameLength: bigint
}

export interface SFTPLimits {
    maximumPacketLength: bigint
    maximumReadLength: bigint
    maximumWriteLength: bigint
    maximumOpenHandles: bigint
}

export interface SFTPUserGroupNames {
    usernames: readonly string[]
    groupNames: readonly string[]
}

export interface SFTPTwoPathExtension {
    firstPath: Buffer
    secondPath: Buffer
}

export interface SFTPLSetStatExtension {
    path: Buffer
    attributes: Readonly<SFTPAttributes>
}

export interface SFTPCopyDataExtension {
    sourceHandle: Buffer
    sourceOffset: bigint
    length: bigint
    destinationHandle: Buffer
    destinationOffset: bigint
}

export interface SFTPUsersGroupsExtension {
    uids: readonly number[]
    gids: readonly number[]
}

class Reader {
    private offset = 0

    constructor(private readonly data: Buffer) {
        if (!Buffer.isBuffer(data)) throw new TypeError("SFTP extension data must be a buffer")
    }

    get remaining(): number {
        return this.data.length - this.offset
    }

    uint32(name: string): number {
        if (this.remaining < 4) throw new SFTPProtocolError(`Truncated ${name}`)
        const value = this.data.readUInt32BE(this.offset)
        this.offset += 4
        return value
    }

    uint64(name: string): bigint {
        if (this.remaining < 8) throw new SFTPProtocolError(`Truncated ${name}`)
        const value = this.data.readBigUInt64BE(this.offset)
        this.offset += 8
        return value
    }

    string(name: string): Buffer {
        const length = this.uint32(`${name} length`)
        if (length > this.remaining) throw new SFTPProtocolError(`Truncated ${name}`)
        const value = Buffer.from(this.data.subarray(this.offset, this.offset + length))
        this.offset += length
        return value
    }

    rest(): Buffer {
        const value = Buffer.from(this.data.subarray(this.offset))
        this.offset = this.data.length
        return value
    }

    done(name: string): void {
        if (this.remaining !== 0) {
            throw new SFTPProtocolError(`${name} has ${this.remaining} trailing bytes`)
        }
    }
}

function uint32(value: number, name: string): Buffer {
    if (!Number.isSafeInteger(value) || value < 0 || value > UINT32_MAX) {
        throw new RangeError(`${name} must be a uint32`)
    }
    const data = Buffer.allocUnsafe(4)
    data.writeUInt32BE(value)
    return data
}

function uint64(value: bigint, name: string): Buffer {
    if (value < 0n || value > UINT64_MAX) throw new RangeError(`${name} must be a uint64`)
    const data = Buffer.allocUnsafe(8)
    data.writeBigUInt64BE(value)
    return data
}

export function encodeSFTPExtensionString(value: Buffer | string): Buffer {
    const data = Buffer.isBuffer(value) ? value : encodeSSHUTF8(value, "SFTP extension string")
    return Buffer.concat([uint32(data.length, "SFTP string length"), data])
}

export function decodeSFTPExtensionString(data: Buffer): Buffer {
    const reader = new Reader(data)
    const value = reader.string("SFTP extension string")
    reader.done("SFTP extension request")
    return value
}

export function decodeSFTPHandleExtension(data: Buffer): Buffer {
    const reader = new Reader(data)
    const value = extensionHandle(reader, "extension handle")
    reader.done("SFTP handle extension request")
    return value
}

export function encodeSFTPTwoPathExtension(firstPath: Buffer, secondPath: Buffer): Buffer {
    return Buffer.concat([
        encodeSFTPExtensionString(firstPath),
        encodeSFTPExtensionString(secondPath),
    ])
}

export function decodeSFTPTwoPathExtension(data: Buffer): Readonly<SFTPTwoPathExtension> {
    const reader = new Reader(data)
    const value = Object.freeze({
        firstPath: reader.string("first path"),
        secondPath: reader.string("second path"),
    })
    reader.done("SFTP two-path extension request")
    return value
}

export function encodeSFTPLSetStatExtension(path: Buffer, attributes: SFTPAttributes): Buffer {
    return Buffer.concat([encodeSFTPExtensionString(path), encodeSFTPAttributes(attributes)])
}

export function decodeSFTPLSetStatExtension(data: Buffer): Readonly<SFTPLSetStatExtension> {
    const reader = new Reader(data)
    const path = reader.string("lsetstat path")
    const attributes = decodeSFTPAttributes(reader.rest())
    return Object.freeze({ path, attributes: Object.freeze(attributes) })
}

export function encodeSFTPCopyDataExtension(
    sourceHandle: Buffer,
    sourceOffset: bigint,
    length: bigint,
    destinationHandle: Buffer,
    destinationOffset: bigint,
): Buffer {
    return Buffer.concat([
        encodeSFTPExtensionString(sourceHandle),
        uint64(sourceOffset, "source offset"),
        uint64(length, "copy length"),
        encodeSFTPExtensionString(destinationHandle),
        uint64(destinationOffset, "destination offset"),
    ])
}

export function decodeSFTPCopyDataExtension(data: Buffer): Readonly<SFTPCopyDataExtension> {
    const reader = new Reader(data)
    const value = Object.freeze({
        sourceHandle: extensionHandle(reader, "source handle"),
        sourceOffset: reader.uint64("source offset"),
        length: reader.uint64("copy length"),
        destinationHandle: extensionHandle(reader, "destination handle"),
        destinationOffset: reader.uint64("destination offset"),
    })
    reader.done("SFTP copy-data extension request")
    return value
}

export function encodeSFTPUsersGroupsExtension(
    uids: readonly number[],
    gids: readonly number[],
): Buffer {
    const encodedUids = Buffer.concat(uids.map((uid) => uint32(uid, "uid")))
    const encodedGids = Buffer.concat(gids.map((gid) => uint32(gid, "gid")))
    return Buffer.concat([
        encodeSFTPExtensionString(encodedUids),
        encodeSFTPExtensionString(encodedGids),
    ])
}

export function decodeSFTPUsersGroupsExtension(data: Buffer): Readonly<SFTPUsersGroupsExtension> {
    const reader = new Reader(data)
    const uids = decodeUint32List(reader.string("uids"), "uids")
    const gids = decodeUint32List(reader.string("gids"), "gids")
    reader.done("SFTP users-groups extension request")
    return Object.freeze({ uids, gids })
}

export function decodeSFTPStatVFS(data: Buffer): Readonly<SFTPStatVFS> {
    const reader = new Reader(data)
    const value: SFTPStatVFS = {
        blockSize: reader.uint64("statvfs block size"),
        fragmentSize: reader.uint64("statvfs fragment size"),
        blocks: reader.uint64("statvfs blocks"),
        blocksFree: reader.uint64("statvfs free blocks"),
        blocksAvailable: reader.uint64("statvfs available blocks"),
        files: reader.uint64("statvfs files"),
        filesFree: reader.uint64("statvfs free files"),
        filesAvailable: reader.uint64("statvfs available files"),
        filesystemId: reader.uint64("statvfs filesystem id"),
        flags: reader.uint64("statvfs flags"),
        maximumFilenameLength: reader.uint64("statvfs maximum filename length"),
    }
    reader.done("SFTP statvfs reply")
    return Object.freeze(value)
}

export function encodeSFTPStatVFS(statistics: Readonly<SFTPStatVFS>): Buffer {
    return Buffer.concat([
        uint64(statistics.blockSize, "statvfs block size"),
        uint64(statistics.fragmentSize, "statvfs fragment size"),
        uint64(statistics.blocks, "statvfs blocks"),
        uint64(statistics.blocksFree, "statvfs free blocks"),
        uint64(statistics.blocksAvailable, "statvfs available blocks"),
        uint64(statistics.files, "statvfs files"),
        uint64(statistics.filesFree, "statvfs free files"),
        uint64(statistics.filesAvailable, "statvfs available files"),
        uint64(statistics.filesystemId, "statvfs filesystem id"),
        uint64(statistics.flags, "statvfs flags"),
        uint64(statistics.maximumFilenameLength, "statvfs maximum filename length"),
    ])
}

export function decodeSFTPLimits(data: Buffer): Readonly<SFTPLimits> {
    const reader = new Reader(data)
    const value: SFTPLimits = {
        maximumPacketLength: reader.uint64("maximum packet length"),
        maximumReadLength: reader.uint64("maximum read length"),
        maximumWriteLength: reader.uint64("maximum write length"),
        maximumOpenHandles: reader.uint64("maximum open handles"),
    }
    reader.done("SFTP limits reply")
    return Object.freeze(value)
}

export function encodeSFTPLimits(limits: Readonly<SFTPLimits>): Buffer {
    return Buffer.concat([
        uint64(limits.maximumPacketLength, "maximum packet length"),
        uint64(limits.maximumReadLength, "maximum read length"),
        uint64(limits.maximumWriteLength, "maximum write length"),
        uint64(limits.maximumOpenHandles, "maximum open handles"),
    ])
}

export function decodeSFTPUsersGroups(data: Buffer): Readonly<SFTPUserGroupNames> {
    const reader = new Reader(data)
    const usernames = decodeNames(reader.string("usernames"), "usernames")
    const groupNames = decodeNames(reader.string("group names"), "group names")
    reader.done("SFTP users-groups reply")
    return Object.freeze({ usernames, groupNames })
}

export function encodeSFTPUsersGroups(names: Readonly<SFTPUserGroupNames>): Buffer {
    return Buffer.concat([
        encodeSFTPExtensionString(encodeNames(names.usernames)),
        encodeSFTPExtensionString(encodeNames(names.groupNames)),
    ])
}

function decodeNames(data: Buffer, name: string): readonly string[] {
    const reader = new Reader(data)
    const names: string[] = []
    while (reader.remaining > 0) {
        names.push(decodeSSHUTF8(reader.string(name), `SFTP ${name} entry`))
    }
    return names
}

function encodeNames(names: readonly string[]): Buffer {
    if (!Array.isArray(names)) throw new TypeError("SFTP user and group names must be arrays")
    return Buffer.concat(names.map((name) => encodeSFTPExtensionString(name)))
}

function extensionHandle(reader: Reader, name: string): Buffer {
    const handle = reader.string(name)
    if (handle.length > MAX_SFTP_HANDLE_LENGTH) {
        throw new SFTPProtocolError(`SFTP ${name} exceeds ${MAX_SFTP_HANDLE_LENGTH} bytes`)
    }
    return handle
}

function decodeUint32List(data: Buffer, name: string): readonly number[] {
    if (data.length % 4 !== 0) {
        throw new SFTPProtocolError(`SFTP ${name} list is not a sequence of uint32 values`)
    }
    const reader = new Reader(data)
    const values: number[] = []
    while (reader.remaining > 0) values.push(reader.uint32(name))
    return Object.freeze(values)
}
