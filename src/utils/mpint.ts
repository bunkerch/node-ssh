import assert from "assert"
import { decodeBigIntBE } from "./BigInt.js"

export function serializeMpintBufferToBuffer(mpint: Buffer): Buffer {
    let i = 0
    while (mpint[i] === 0) {
        i++
    }
    const new_mpint = mpint.subarray(i)
    if (new_mpint.length === 0) {
        // new_mpint[0] would return undefined, early return is best
        return Buffer.alloc(1)
    }

    if (new_mpint[0] & 0b1000_0000) {
        // need to add a byte before, because the two-complement will break it
        return Buffer.concat([Buffer.alloc(1), new_mpint])
    }

    return new_mpint
}
export function parseBufferToMpintBuffer(raw: Buffer): Buffer {
    if (raw.length === 0) {
        return Buffer.alloc(0)
    }

    assert((raw[0] & 0b1000_0000) === 0, "Undefined behavior, for negative mpint buffer")

    return raw
}
