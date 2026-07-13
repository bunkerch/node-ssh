import assert from "node:assert"

const UINT64_MAX = 0xffff_ffff_ffff_ffffn
const ZERO_NONCE = Buffer.alloc(8)

function littleEndianInteger(buffer: Buffer): bigint {
    let value = 0n
    for (let index = buffer.length - 1; index >= 0; index--) {
        value = (value << 8n) | BigInt(buffer[index])
    }
    return value
}

function encodeLittleEndian(value: bigint, length: number): Buffer {
    const result = Buffer.alloc(length)
    for (let index = 0; index < length; index++) {
        result[index] = Number(value & 0xffn)
        value >>= 8n
    }
    return result
}

export function poly1305(message: Buffer, key: Buffer): Buffer {
    assert(key.length === 32, "Invalid Poly1305 key length")
    const r = littleEndianInteger(key.subarray(0, 16)) & 0x0ffffffc0ffffffc0ffffffc0fffffffn
    const s = littleEndianInteger(key.subarray(16))
    const modulus = (1n << 130n) - 5n
    let accumulator = 0n

    for (let offset = 0; offset < message.length; offset += 16) {
        const block = message.subarray(offset, Math.min(offset + 16, message.length))
        const value = littleEndianInteger(block) + (1n << BigInt(block.length * 8))
        accumulator = ((accumulator + value) * r) % modulus
    }

    return encodeLittleEndian((accumulator + s) & ((1n << 128n) - 1n), 16)
}

function rotateLeft(value: number, bits: number): number {
    return ((value << bits) | (value >>> (32 - bits))) >>> 0
}

function quarterRound(state: Uint32Array, a: number, b: number, c: number, d: number): void {
    state[a] = (state[a] + state[b]) >>> 0
    state[d] = rotateLeft(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) >>> 0
    state[b] = rotateLeft(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b]) >>> 0
    state[d] = rotateLeft(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) >>> 0
    state[b] = rotateLeft(state[b] ^ state[c], 7)
}

export function chacha20(
    input: Buffer,
    key: Buffer,
    initialCounter: bigint,
    nonce: Buffer = ZERO_NONCE,
): Buffer {
    assert(key.length === 32, "Invalid ChaCha20 key length")
    assert(nonce.length === 8, "Invalid ChaCha20 nonce length")
    assert(initialCounter >= 0n && initialCounter <= UINT64_MAX, "Invalid ChaCha20 block counter")
    const finalCounter = initialCounter + BigInt(Math.max(0, Math.ceil(input.length / 64) - 1))
    assert(finalCounter <= UINT64_MAX, "ChaCha20 block counter overflow")
    const output = Buffer.alloc(input.length)

    for (let offset = 0; offset < input.length; offset += 64) {
        const state = new Uint32Array(16)
        state.set([0x61707865, 0x3320646e, 0x79622d32, 0x6b206574])
        for (let index = 0; index < 8; index++) state[index + 4] = key.readUInt32LE(index * 4)
        const counter = initialCounter + BigInt(offset / 64)
        state[12] = Number(counter & 0xffffffffn)
        state[13] = Number((counter >> 32n) & 0xffffffffn)
        state[14] = nonce.readUInt32LE(0)
        state[15] = nonce.readUInt32LE(4)

        const working = new Uint32Array(state)
        for (let round = 0; round < 10; round++) {
            quarterRound(working, 0, 4, 8, 12)
            quarterRound(working, 1, 5, 9, 13)
            quarterRound(working, 2, 6, 10, 14)
            quarterRound(working, 3, 7, 11, 15)
            quarterRound(working, 0, 5, 10, 15)
            quarterRound(working, 1, 6, 11, 12)
            quarterRound(working, 2, 7, 8, 13)
            quarterRound(working, 3, 4, 9, 14)
        }

        const keyStream = Buffer.allocUnsafe(64)
        try {
            for (let index = 0; index < 16; index++) {
                keyStream.writeUInt32LE((working[index] + state[index]) >>> 0, index * 4)
            }
            const blockLength = Math.min(64, input.length - offset)
            for (let index = 0; index < blockLength; index++) {
                output[offset + index] = input[offset + index] ^ keyStream[index]
            }
        } finally {
            keyStream.fill(0)
            working.fill(0)
            state.fill(0)
        }
    }

    return output
}
