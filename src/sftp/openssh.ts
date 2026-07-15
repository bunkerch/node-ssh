import { encodeSFTPAttributes, SFTPProtocolError } from "./codec.js"
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

class Reader {
    private offset = 0

    constructor(private readonly data: Buffer) {}

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
        const value = this.data.subarray(this.offset, this.offset + length)
        this.offset += length
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

export function encodeSFTPTwoPathExtension(firstPath: Buffer, secondPath: Buffer): Buffer {
    return Buffer.concat([
        encodeSFTPExtensionString(firstPath),
        encodeSFTPExtensionString(secondPath),
    ])
}

export function encodeSFTPLSetStatExtension(path: Buffer, attributes: SFTPAttributes): Buffer {
    return Buffer.concat([encodeSFTPExtensionString(path), encodeSFTPAttributes(attributes)])
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

function decodeNames(data: Buffer, name: string): readonly string[] {
    const reader = new Reader(data)
    const names: string[] = []
    while (reader.remaining > 0) {
        names.push(decodeSSHUTF8(reader.string(name), `SFTP ${name} entry`))
    }
    return names
}
