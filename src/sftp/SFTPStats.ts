import type { SFTPAttributes, SFTPExtendedAttribute, SFTPNameEntry } from "./types.js"

const FILE_TYPE_MASK = 0o170000
const FIFO = 0o010000
const CHARACTER_DEVICE = 0o020000
const DIRECTORY = 0o040000
const BLOCK_DEVICE = 0o060000
const REGULAR_FILE = 0o100000
const SYMBOLIC_LINK = 0o120000
const SOCKET = 0o140000

export class SFTPStats implements SFTPAttributes {
    readonly size: bigint | undefined
    readonly uid: number | undefined
    readonly gid: number | undefined
    readonly permissions: number | undefined
    readonly accessTime: number | undefined
    readonly modificationTime: number | undefined
    readonly extended: readonly SFTPExtendedAttribute[] | undefined

    constructor(attributes: SFTPAttributes = {}) {
        this.size = attributes.size
        this.uid = attributes.uid
        this.gid = attributes.gid
        this.permissions = attributes.permissions
        this.accessTime = attributes.accessTime
        this.modificationTime = attributes.modificationTime
        this.extended =
            attributes.extended === undefined
                ? undefined
                : Object.freeze(
                      attributes.extended.map((attribute) =>
                          Object.freeze({
                              type: ownBuffer(attribute.type, "extended attribute type"),
                              data: ownBuffer(attribute.data, "extended attribute data"),
                          }),
                      ),
                  )
    }

    get mode(): number | undefined {
        return this.permissions
    }

    get atime(): number | undefined {
        return this.accessTime
    }

    get mtime(): number | undefined {
        return this.modificationTime
    }

    isDirectory(): boolean {
        return this.hasType(DIRECTORY)
    }

    isFile(): boolean {
        return this.hasType(REGULAR_FILE)
    }

    isBlockDevice(): boolean {
        return this.hasType(BLOCK_DEVICE)
    }

    isCharacterDevice(): boolean {
        return this.hasType(CHARACTER_DEVICE)
    }

    isSymbolicLink(): boolean {
        return this.hasType(SYMBOLIC_LINK)
    }

    isFIFO(): boolean {
        return this.hasType(FIFO)
    }

    isSocket(): boolean {
        return this.hasType(SOCKET)
    }

    private hasType(type: number): boolean {
        return this.permissions !== undefined && (this.permissions & FILE_TYPE_MASK) === type
    }
}

export interface SFTPClientNameEntry extends Omit<SFTPNameEntry, "attributes"> {
    attributes: SFTPStats
}

export function sftpStats(attributes: SFTPAttributes): SFTPStats {
    return attributes instanceof SFTPStats ? attributes : new SFTPStats(attributes)
}

export function sftpNameEntry(entry: SFTPNameEntry): SFTPClientNameEntry {
    return {
        filename: ownBuffer(entry.filename, "name-entry filename"),
        longname: ownBuffer(entry.longname, "name-entry longname"),
        attributes: sftpStats(entry.attributes),
    }
}

function ownBuffer(value: Buffer, name: string): Buffer {
    if (!Buffer.isBuffer(value)) throw new TypeError(`SFTP ${name} must be a buffer`)
    return Buffer.from(value)
}
