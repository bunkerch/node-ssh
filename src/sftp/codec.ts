import {
    MAX_SFTP_HANDLE_LENGTH,
    MAX_SFTP_PACKET_LENGTH,
    SFTP_ATTRIBUTE_FLAGS_MASK,
    SFTPAttributeFlags,
    SFTPPacketType,
} from "./constants.js"
import type {
    SFTPAttributes,
    SFTPExtension,
    SFTPExtendedAttribute,
    SFTPNameEntry,
    SFTPPacket,
} from "./types.js"
import { decodeSSHName, encodeSSHName } from "../utils/SSHName.js"
import {
    decodeRFC5646LanguageTag,
    decodeSSHUTF8,
    encodeRFC5646LanguageTag,
    encodeSSHUTF8,
} from "../utils/SSHText.js"

const UINT32_MAX = 0xffff_ffff
const UINT64_MAX = 0xffff_ffff_ffff_ffffn

export class SFTPProtocolError extends Error {
    constructor(message: string) {
        super(message)
        this.name = "SFTPProtocolError"
    }
}

class Reader {
    private offset = 0

    constructor(private readonly buffer: Buffer) {}

    get remaining(): number {
        return this.buffer.length - this.offset
    }

    uint8(name: string): number {
        this.require(1, name)
        return this.buffer[this.offset++]!
    }

    uint32(name: string): number {
        this.require(4, name)
        const value = this.buffer.readUInt32BE(this.offset)
        this.offset += 4
        return value
    }

    uint64(name: string): bigint {
        this.require(8, name)
        const value = this.buffer.readBigUInt64BE(this.offset)
        this.offset += 8
        return value
    }

    string(name: string): Buffer {
        const length = this.uint32(`${name} length`)
        this.require(length, name)
        const value = Buffer.from(this.buffer.subarray(this.offset, this.offset + length))
        this.offset += length
        return value
    }

    rest(): Buffer {
        const value = Buffer.from(this.buffer.subarray(this.offset))
        this.offset = this.buffer.length
        return value
    }

    done(): void {
        if (this.remaining !== 0) {
            throw new SFTPProtocolError(`SFTP packet has ${this.remaining} trailing bytes`)
        }
    }

    private require(length: number, name: string): void {
        if (length > this.remaining) {
            throw new SFTPProtocolError(`Truncated SFTP ${name}`)
        }
    }
}

function uint32(value: number, name: string): Buffer {
    if (!Number.isSafeInteger(value) || value < 0 || value > UINT32_MAX) {
        throw new RangeError(`${name} must be a uint32`)
    }
    const buffer = Buffer.allocUnsafe(4)
    buffer.writeUInt32BE(value)
    return buffer
}

function uint64(value: bigint, name: string): Buffer {
    if (value < 0n || value > UINT64_MAX) throw new RangeError(`${name} must be a uint64`)
    const buffer = Buffer.allocUnsafe(8)
    buffer.writeBigUInt64BE(value)
    return buffer
}

function string(value: Buffer, name: string): Buffer {
    if (value.length > UINT32_MAX) throw new RangeError(`${name} is too long`)
    return Buffer.concat([uint32(value.length, `${name} length`), value])
}

function utf8(value: string, name: string): Buffer {
    return string(encodeSSHUTF8(value, `SFTP ${name}`), name)
}

function handle(value: Buffer): Buffer {
    if (value.length > MAX_SFTP_HANDLE_LENGTH) {
        throw new SFTPProtocolError(`SFTP handle exceeds ${MAX_SFTP_HANDLE_LENGTH} bytes`)
    }
    return string(value, "handle")
}

function readHandle(reader: Reader): Buffer {
    const value = reader.string("handle")
    if (value.length > MAX_SFTP_HANDLE_LENGTH) {
        throw new SFTPProtocolError(`SFTP handle exceeds ${MAX_SFTP_HANDLE_LENGTH} bytes`)
    }
    return value
}

function readExtensions(reader: Reader): readonly SFTPExtension[] {
    const extensions: SFTPExtension[] = []
    while (reader.remaining > 0) {
        extensions.push({
            name: decodeSSHName(reader.string("extension name"), "SFTP extension name"),
            data: reader.string("extension data"),
        })
    }
    return extensions
}

function encodeExtensions(extensions: readonly SFTPExtension[]): Buffer {
    return Buffer.concat(
        extensions.flatMap((extension) => [
            string(encodeSSHName(extension.name, "SFTP extension name"), "extension name"),
            string(extension.data, "extension data"),
        ]),
    )
}

function readSFTPAttributes(reader: Reader): SFTPAttributes {
    const flags = reader.uint32("attribute flags")
    if ((flags & ~SFTP_ATTRIBUTE_FLAGS_MASK) !== 0) {
        throw new SFTPProtocolError(`Unsupported SFTP attribute flags 0x${flags.toString(16)}`)
    }

    const attributes: SFTPAttributes = {}
    if (flags & SFTPAttributeFlags.Size) attributes.size = reader.uint64("attribute size")
    if (flags & SFTPAttributeFlags.UIDGID) {
        attributes.uid = reader.uint32("attribute uid")
        attributes.gid = reader.uint32("attribute gid")
    }
    if (flags & SFTPAttributeFlags.Permissions) {
        attributes.permissions = reader.uint32("attribute permissions")
    }
    if (flags & SFTPAttributeFlags.AccessModificationTime) {
        attributes.accessTime = reader.uint32("attribute access time")
        attributes.modificationTime = reader.uint32("attribute modification time")
    }
    if (flags & SFTPAttributeFlags.Extended) {
        const count = reader.uint32("extended attribute count")
        if (count > Math.floor(reader.remaining / 8)) {
            throw new SFTPProtocolError("SFTP extended attribute count exceeds packet data")
        }
        const extended: SFTPExtendedAttribute[] = []
        for (let index = 0; index < count; index++) {
            extended.push({
                type: reader.string("extended attribute type"),
                data: reader.string("extended attribute data"),
            })
        }
        attributes.extended = extended
    }
    return attributes
}

export function decodeSFTPAttributes(data: Buffer): SFTPAttributes {
    if (!Buffer.isBuffer(data)) throw new TypeError("SFTP attributes data must be a buffer")
    const reader = new Reader(data)
    const attributes = readSFTPAttributes(reader)
    reader.done()
    return attributes
}

export function encodeSFTPAttributes(attributes: SFTPAttributes): Buffer {
    const parts: Buffer[] = []
    let flags = 0
    if (attributes.size !== undefined) {
        flags |= SFTPAttributeFlags.Size
        parts.push(uint64(attributes.size, "attribute size"))
    }
    if ((attributes.uid === undefined) !== (attributes.gid === undefined)) {
        throw new SFTPProtocolError("SFTP uid and gid attributes must be provided together")
    }
    if (attributes.uid !== undefined && attributes.gid !== undefined) {
        flags |= SFTPAttributeFlags.UIDGID
        parts.push(uint32(attributes.uid, "attribute uid"), uint32(attributes.gid, "attribute gid"))
    }
    if (attributes.permissions !== undefined) {
        flags |= SFTPAttributeFlags.Permissions
        parts.push(uint32(attributes.permissions, "attribute permissions"))
    }
    if ((attributes.accessTime === undefined) !== (attributes.modificationTime === undefined)) {
        throw new SFTPProtocolError(
            "SFTP access and modification time attributes must be provided together",
        )
    }
    if (attributes.accessTime !== undefined && attributes.modificationTime !== undefined) {
        flags |= SFTPAttributeFlags.AccessModificationTime
        parts.push(
            uint32(attributes.accessTime, "attribute access time"),
            uint32(attributes.modificationTime, "attribute modification time"),
        )
    }
    if (attributes.extended !== undefined) {
        flags |= SFTPAttributeFlags.Extended
        parts.push(
            uint32(attributes.extended.length, "extended attribute count"),
            ...attributes.extended.flatMap((attribute) => [
                string(attribute.type, "extended attribute type"),
                string(attribute.data, "extended attribute data"),
            ]),
        )
    }
    return Buffer.concat([uint32(flags >>> 0, "attribute flags"), ...parts])
}

function requestId(reader: Reader): number {
    return reader.uint32("request id")
}

export function decodeSFTPPacket(frame: Buffer): SFTPPacket {
    if (frame.length < 5) throw new SFTPProtocolError("Truncated SFTP packet")
    const packetLength = frame.readUInt32BE(0)
    if (packetLength < 1) throw new SFTPProtocolError("SFTP packet length must include a type")
    if (packetLength > MAX_SFTP_PACKET_LENGTH) {
        throw new SFTPProtocolError(`SFTP packet length exceeds ${MAX_SFTP_PACKET_LENGTH} bytes`)
    }
    if (frame.length !== packetLength + 4) {
        throw new SFTPProtocolError("SFTP frame length does not match its length field")
    }

    const reader = new Reader(frame.subarray(4))
    const type = reader.uint8("packet type") as SFTPPacketType
    let packet: SFTPPacket
    switch (type) {
        case SFTPPacketType.Init:
        case SFTPPacketType.Version:
            packet = {
                type,
                version: reader.uint32("version"),
                extensions: readExtensions(reader),
            }
            break
        case SFTPPacketType.Open:
            packet = {
                type,
                requestId: requestId(reader),
                filename: reader.string("filename"),
                flags: reader.uint32("open flags"),
                attributes: readSFTPAttributes(reader),
            }
            break
        case SFTPPacketType.Close:
        case SFTPPacketType.FStat:
        case SFTPPacketType.ReadDir:
            packet = { type, requestId: requestId(reader), handle: readHandle(reader) }
            break
        case SFTPPacketType.Read:
            packet = {
                type,
                requestId: requestId(reader),
                handle: readHandle(reader),
                offset: reader.uint64("read offset"),
                length: reader.uint32("read length"),
            }
            break
        case SFTPPacketType.Write:
            packet = {
                type,
                requestId: requestId(reader),
                handle: readHandle(reader),
                offset: reader.uint64("write offset"),
                data: reader.string("write data"),
            }
            break
        case SFTPPacketType.LStat:
        case SFTPPacketType.OpenDir:
        case SFTPPacketType.Remove:
        case SFTPPacketType.RmDir:
        case SFTPPacketType.RealPath:
        case SFTPPacketType.Stat:
        case SFTPPacketType.ReadLink:
            packet = { type, requestId: requestId(reader), path: reader.string("path") }
            break
        case SFTPPacketType.SetStat:
            packet = {
                type,
                requestId: requestId(reader),
                path: reader.string("path"),
                attributes: readSFTPAttributes(reader),
            }
            break
        case SFTPPacketType.FSetStat:
            packet = {
                type,
                requestId: requestId(reader),
                handle: readHandle(reader),
                attributes: readSFTPAttributes(reader),
            }
            break
        case SFTPPacketType.MkDir:
            packet = {
                type,
                requestId: requestId(reader),
                path: reader.string("path"),
                attributes: readSFTPAttributes(reader),
            }
            break
        case SFTPPacketType.Rename:
        case SFTPPacketType.SymLink:
            packet = {
                type,
                requestId: requestId(reader),
                firstPath: reader.string("first path"),
                secondPath: reader.string("second path"),
            }
            break
        case SFTPPacketType.Status:
            packet = {
                type,
                requestId: requestId(reader),
                code: reader.uint32("status code"),
                message: decodeSSHUTF8(reader.string("status message"), "SFTP status message"),
                languageTag: decodeRFC5646LanguageTag(
                    reader.string("status language tag"),
                    "SFTP status language tag",
                ),
            }
            break
        case SFTPPacketType.Handle:
            packet = { type, requestId: requestId(reader), handle: readHandle(reader) }
            break
        case SFTPPacketType.Data:
            packet = { type, requestId: requestId(reader), data: reader.string("data") }
            break
        case SFTPPacketType.Name: {
            const id = requestId(reader)
            const count = reader.uint32("name count")
            if (count > Math.floor(reader.remaining / 12)) {
                throw new SFTPProtocolError("SFTP name count exceeds packet data")
            }
            const names: SFTPNameEntry[] = []
            for (let index = 0; index < count; index++) {
                names.push({
                    filename: reader.string("filename"),
                    longname: reader.string("longname"),
                    attributes: readSFTPAttributes(reader),
                })
            }
            packet = { type, requestId: id, names }
            break
        }
        case SFTPPacketType.Attrs:
            packet = {
                type,
                requestId: requestId(reader),
                attributes: readSFTPAttributes(reader),
            }
            break
        case SFTPPacketType.Extended:
            packet = {
                type,
                requestId: requestId(reader),
                request: decodeSSHName(
                    reader.string("extended request name"),
                    "SFTP extended request name",
                ),
                data: reader.rest(),
            }
            break
        case SFTPPacketType.ExtendedReply:
            packet = { type, requestId: requestId(reader), data: reader.rest() }
            break
        default:
            throw new SFTPProtocolError(`Unknown SFTP packet type ${type}`)
    }
    reader.done()
    return packet
}

export function encodeSFTPPacket(packet: SFTPPacket): Buffer {
    const parts: Buffer[] = [Buffer.from([packet.type])]
    switch (packet.type) {
        case SFTPPacketType.Init:
        case SFTPPacketType.Version:
            parts.push(uint32(packet.version, "version"), encodeExtensions(packet.extensions))
            break
        case SFTPPacketType.Open:
            parts.push(
                uint32(packet.requestId, "request id"),
                string(packet.filename, "filename"),
                uint32(packet.flags, "open flags"),
                encodeSFTPAttributes(packet.attributes),
            )
            break
        case SFTPPacketType.Close:
        case SFTPPacketType.FStat:
        case SFTPPacketType.ReadDir:
            parts.push(uint32(packet.requestId, "request id"), handle(packet.handle))
            break
        case SFTPPacketType.Read:
            parts.push(
                uint32(packet.requestId, "request id"),
                handle(packet.handle),
                uint64(packet.offset, "read offset"),
                uint32(packet.length, "read length"),
            )
            break
        case SFTPPacketType.Write:
            parts.push(
                uint32(packet.requestId, "request id"),
                handle(packet.handle),
                uint64(packet.offset, "write offset"),
                string(packet.data, "write data"),
            )
            break
        case SFTPPacketType.LStat:
        case SFTPPacketType.OpenDir:
        case SFTPPacketType.Remove:
        case SFTPPacketType.RmDir:
        case SFTPPacketType.RealPath:
        case SFTPPacketType.Stat:
        case SFTPPacketType.ReadLink:
            parts.push(uint32(packet.requestId, "request id"), string(packet.path, "path"))
            break
        case SFTPPacketType.SetStat:
        case SFTPPacketType.MkDir:
            parts.push(
                uint32(packet.requestId, "request id"),
                string(packet.path, "path"),
                encodeSFTPAttributes(packet.attributes),
            )
            break
        case SFTPPacketType.FSetStat:
            parts.push(
                uint32(packet.requestId, "request id"),
                handle(packet.handle),
                encodeSFTPAttributes(packet.attributes),
            )
            break
        case SFTPPacketType.Rename:
        case SFTPPacketType.SymLink:
            parts.push(
                uint32(packet.requestId, "request id"),
                string(packet.firstPath, "first path"),
                string(packet.secondPath, "second path"),
            )
            break
        case SFTPPacketType.Status:
            parts.push(
                uint32(packet.requestId, "request id"),
                uint32(packet.code, "status code"),
                utf8(packet.message, "status message"),
                string(
                    encodeRFC5646LanguageTag(packet.languageTag, "SFTP status language tag"),
                    "status language tag",
                ),
            )
            break
        case SFTPPacketType.Handle:
            parts.push(uint32(packet.requestId, "request id"), handle(packet.handle))
            break
        case SFTPPacketType.Data:
            parts.push(uint32(packet.requestId, "request id"), string(packet.data, "data"))
            break
        case SFTPPacketType.Name:
            parts.push(
                uint32(packet.requestId, "request id"),
                uint32(packet.names.length, "name count"),
                ...packet.names.flatMap((entry) => [
                    string(entry.filename, "filename"),
                    string(entry.longname, "longname"),
                    encodeSFTPAttributes(entry.attributes),
                ]),
            )
            break
        case SFTPPacketType.Attrs:
            parts.push(
                uint32(packet.requestId, "request id"),
                encodeSFTPAttributes(packet.attributes),
            )
            break
        case SFTPPacketType.Extended:
            parts.push(
                uint32(packet.requestId, "request id"),
                string(
                    encodeSSHName(packet.request, "SFTP extended request name"),
                    "extended request name",
                ),
                packet.data,
            )
            break
        case SFTPPacketType.ExtendedReply:
            parts.push(uint32(packet.requestId, "request id"), packet.data)
            break
    }
    const payload = Buffer.concat(parts)
    if (payload.length > MAX_SFTP_PACKET_LENGTH) {
        throw new SFTPProtocolError(`SFTP packet length exceeds ${MAX_SFTP_PACKET_LENGTH} bytes`)
    }
    return Buffer.concat([uint32(payload.length, "packet length"), payload])
}

export class SFTPPacketParser {
    private buffered: Buffer = Buffer.alloc(0)
    private expectedLength: number | undefined

    push(chunk: Buffer): SFTPPacket[] {
        if (chunk.length === 0) return []
        const borrowedInput = this.buffered.length === 0
        this.buffered = this.buffered.length === 0 ? chunk : Buffer.concat([this.buffered, chunk])
        const packets: SFTPPacket[] = []
        while (true) {
            if (this.expectedLength === undefined) {
                if (this.buffered.length < 4) break
                const packetLength = this.buffered.readUInt32BE(0)
                if (packetLength < 1) {
                    throw new SFTPProtocolError("SFTP packet length must include a type")
                }
                if (packetLength > MAX_SFTP_PACKET_LENGTH) {
                    throw new SFTPProtocolError(
                        `SFTP packet length exceeds ${MAX_SFTP_PACKET_LENGTH} bytes`,
                    )
                }
                this.expectedLength = packetLength + 4
            }
            if (this.buffered.length < this.expectedLength) break
            const frame = this.buffered.subarray(0, this.expectedLength)
            this.buffered = this.buffered.subarray(this.expectedLength)
            this.expectedLength = undefined
            packets.push(decodeSFTPPacket(frame))
        }
        if (borrowedInput && this.buffered.length !== 0) {
            this.buffered = Buffer.from(this.buffered)
        }
        return packets
    }

    end(): void {
        if (this.buffered.length !== 0) throw new SFTPProtocolError("Truncated SFTP stream")
    }
}
