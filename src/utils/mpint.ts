import assert from "assert"

export function serializeMpintBufferToBuffer(mpint: Buffer): Buffer {
    let i = 0
    while (mpint[i] === 0) {
        i++
    }
    const new_mpint = mpint.subarray(i)
    if (new_mpint.length === 0) {
        return Buffer.alloc(0)
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
    assert(
        raw[0] !== 0 || (raw.length > 1 && (raw[1] & 0b1000_0000) !== 0),
        "Non-canonical mpint buffer",
    )

    return raw
}
