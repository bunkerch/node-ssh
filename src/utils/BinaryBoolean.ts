import assert from "assert"

export function parseBinaryBoolean(raw: Buffer): boolean {
    assert(raw.length === 1)
    return raw[0] !== 0
}

export function serializeBinaryBoolean(value: boolean): Buffer {
    assert(typeof value == "boolean")

    return Buffer.from([value ? 1 : 0])
}
