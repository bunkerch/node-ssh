import assert from "assert"

export function parseBinaryBoolean(raw: Buffer): boolean {
    assert(raw.length === 1)
    assert(raw[0] <= 1)
    return raw[0] === 1
}

export function serializeBinaryBoolean(value: boolean): Buffer {
    return Buffer.from([value ? 1 : 0])
}
