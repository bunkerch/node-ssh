import assert from "assert"
import { parseBinaryBoolean } from "./BinaryBoolean.js"

export function readNextBuffer(buffer: Buffer): [Buffer, Buffer] {
    assert(buffer.length >= 4)
    const length = buffer.readUInt32BE(0)
    const data = buffer.subarray(4, 4 + length)
    assert(data.length === length)
    return [data, buffer.subarray(4 + length)]
}

export function readNextUint8(buffer: Buffer): [number, Buffer] {
    assert(buffer.length >= 1)
    const data = buffer.readUInt8(0)
    return [data, buffer.subarray(1)]
}

export function readNextUint32(buffer: Buffer): [number, Buffer] {
    assert(buffer.length >= 1)
    const data = buffer.readUint32BE(0)
    return [data, buffer.subarray(4)]
}

export function readNextBinaryBoolean(buffer: Buffer): [boolean, Buffer] {
    assert(buffer.length >= 1)
    const data = parseBinaryBoolean(buffer.subarray(0, 1))
    return [data, buffer.subarray(1)]
}

export function serializeBuffer(buffer: Buffer): Buffer {
    const length = Buffer.alloc(4)
    length.writeUInt32BE(buffer.length)
    return Buffer.concat([length, buffer])
}

export function serializeUint8(data: number): Buffer {
    return Buffer.from([data])
}