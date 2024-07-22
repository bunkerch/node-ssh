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

export function serializeMpint(mpint: bigint): Buffer {
    // TODO: Clean code lol
    if (mpint === 0n) {
        return Buffer.alloc(4)
    }

    const negative = mpint < 0
    if (mpint < 0n) {
        mpint = -mpint
    }
    const mpint_log2 = mpint.toString(2).length
    // since it's two-complement, we have to keep the first bit for sign
    const data_length = Math.ceil((mpint_log2 + 1) / 8)
    const data = Buffer.alloc(data_length)

    if (negative) {
        const mod = 2n ** BigInt(data_length * 8)
        const flip = mod - 1n
        mpint ^= flip
        mpint = (mpint + 1n) % mod
    }

    for (let i = 0; i < data_length && mpint != 0n; i++) {
        data[data.length - i - 1] = Number(mpint % 256n)
        // bigint, no need for decimals handling
        mpint = mpint / 256n
    }
    const length = Buffer.alloc(4)
    length.writeUInt32BE(data.length)

    return Buffer.concat([length, data])
}

export function parseMpint(raw: Buffer): [bigint, Buffer] {
    // TODO: Clean code lol
    assert(raw.length >= 4)
    const length = raw.readUInt32BE(0)
    assert(length >= 1)
    const data = raw.subarray(4, 4 + length)
    assert(data.length === length)

    const bitlen = BigInt(data.length * 8)
    let mpint = decodeBigIntBE(data)

    const sign_bitmask = 2n ** (bitlen - 1n)
    if ((mpint & sign_bitmask) != 0n) {
        const mod = 2n ** bitlen
        const flip = mod - 1n
        mpint ^= flip
        mpint = (mpint + 1n) % mod
        mpint = -mpint
    }

    return [mpint, raw.subarray(4 + data.length)]
}
