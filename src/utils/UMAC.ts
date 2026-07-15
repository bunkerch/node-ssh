import assert from "node:assert"
import { createCipheriv } from "node:crypto"

const BLOCK_LENGTH = 16
const KEY_LENGTH = 16
const UINT32_MASK = 0xffff_ffffn
const UINT64_MASK = 0xffff_ffff_ffff_ffffn
const PRIME36 = (1n << 36n) - 5n
const PRIME64 = (1n << 64n) - 59n
const PRIME128 = (1n << 128n) - 159n
const MAX64_WORD = (1n << 64n) - (1n << 32n)
const MAX128_WORD = (1n << 128n) - (1n << 96n)

export type UMACTagLength = 4 | 8 | 12 | 16

function readBigEndian(value: Buffer): bigint {
    let result = 0n
    for (const byte of value) result = (result << 8n) | BigInt(byte)
    return result
}

function writeBigEndian(value: bigint, length: number): Buffer {
    assert(value >= 0n && value < 1n << BigInt(length * 8), "UMAC integer is out of range")
    const result = Buffer.alloc(length)
    for (let index = length - 1; index >= 0; index--) {
        result[index] = Number(value & 0xffn)
        value >>= 8n
    }
    return result
}

function aesBlock(key: Buffer, plaintext: Buffer): Buffer {
    assert(key.length === KEY_LENGTH, "UMAC requires a 16-byte key")
    assert(plaintext.length === BLOCK_LENGTH, "UMAC AES input must be 16 bytes")
    const cipher = createCipheriv("aes-128-ecb", key, null)
    cipher.setAutoPadding(false)
    return Buffer.concat([cipher.update(plaintext), cipher.final()])
}

function kdf(key: Buffer, index: number, length: number): Buffer {
    assert(Number.isSafeInteger(index) && index >= 0, "Invalid UMAC KDF index")
    assert(Number.isSafeInteger(length) && length >= 0, "Invalid UMAC KDF length")
    const blocks: Buffer[] = []
    for (let counter = 1n; blocks.length * BLOCK_LENGTH < length; counter++) {
        blocks.push(
            aesBlock(
                key,
                Buffer.concat([writeBigEndian(BigInt(index), 8), writeBigEndian(counter, 8)]),
            ),
        )
    }
    return Buffer.concat(blocks).subarray(0, length)
}

function endianSwapWords(value: Buffer): Buffer {
    assert(value.length % 4 === 0, "UMAC word input is not aligned")
    const result = Buffer.allocUnsafe(value.length)
    for (let offset = 0; offset < value.length; offset += 4) {
        result[offset] = value[offset + 3]
        result[offset + 1] = value[offset + 2]
        result[offset + 2] = value[offset + 1]
        result[offset + 3] = value[offset]
    }
    return result
}

function zeroPad(value: Buffer, multiple: number): Buffer {
    const length = Math.max(multiple, Math.ceil(value.length / multiple) * multiple)
    if (length === value.length) return value
    return Buffer.concat([value, Buffer.alloc(length - value.length)])
}

function nh(key: Buffer, message: Buffer): bigint {
    assert(key.length === 1024, "Invalid UMAC NH key length")
    assert(message.length > 0 && message.length % 32 === 0, "Invalid UMAC NH input length")
    let result = 0n
    for (let offset = 0; offset < message.length; offset += 32) {
        for (let word = 0; word < 4; word++) {
            const firstOffset = offset + word * 4
            const secondOffset = offset + (word + 4) * 4
            const first =
                (BigInt(message.readUInt32BE(firstOffset)) +
                    BigInt(key.readUInt32BE(firstOffset))) &
                UINT32_MASK
            const second =
                (BigInt(message.readUInt32BE(secondOffset)) +
                    BigInt(key.readUInt32BE(secondOffset))) &
                UINT32_MASK
            result = (result + first * second) & UINT64_MASK
        }
    }
    return result
}

function l1Hash(key: Buffer, message: Buffer): Buffer {
    const chunks = Math.max(Math.ceil(message.length / 1024), 1)
    const result: Buffer[] = []
    for (let index = 0; index < chunks; index++) {
        const chunk = message.subarray(index * 1024, Math.min((index + 1) * 1024, message.length))
        const bitLength = BigInt(chunk.length * 8)
        const padded = chunk.length === 1024 ? chunk : zeroPad(chunk, 32)
        const hash = (nh(key, endianSwapWords(padded)) + bitLength) & UINT64_MASK
        result.push(writeBigEndian(hash, 8))
    }
    return Buffer.concat(result)
}

function poly(wordBits: 64 | 128, maximumWord: bigint, key: bigint, message: Buffer): bigint {
    const wordBytes = wordBits / 8
    assert(message.length % wordBytes === 0, "Invalid UMAC polynomial input length")
    const prime = wordBits === 64 ? PRIME64 : PRIME128
    const offset = (1n << BigInt(wordBits)) - prime
    const marker = prime - 1n
    let result = 1n
    for (let position = 0; position < message.length; position += wordBytes) {
        const word = readBigEndian(message.subarray(position, position + wordBytes))
        if (word >= maximumWord) {
            result = (key * result + marker) % prime
            result = (key * result + word - offset) % prime
        } else {
            result = (key * result + word) % prime
        }
    }
    return result
}

function l2Hash(key: Buffer, message: Buffer): Buffer {
    assert(key.length === 24, "Invalid UMAC L2 key length")
    const key64 = readBigEndian(key.subarray(0, 8)) & 0x01ff_ffff_01ff_ffffn
    const key128 = readBigEndian(key.subarray(8, 24)) & 0x01ff_ffff_01ff_ffff_01ff_ffff_01ff_ffffn
    let result: bigint
    if (message.length <= 1 << 17) {
        result = poly(64, MAX64_WORD, key64, message)
    } else {
        const prefix = message.subarray(0, 1 << 17)
        const suffix = zeroPad(Buffer.concat([message.subarray(1 << 17), Buffer.from([0x80])]), 16)
        result = poly(64, MAX64_WORD, key64, prefix)
        result = poly(128, MAX128_WORD, key128, Buffer.concat([writeBigEndian(result, 16), suffix]))
    }
    return writeBigEndian(result, 16)
}

function l3Hash(key1: Buffer, key2: Buffer, message: Buffer): Buffer {
    assert(key1.length === 64 && key2.length === 4, "Invalid UMAC L3 key length")
    assert(message.length === 16, "Invalid UMAC L3 input length")
    let result = 0n
    for (let index = 0; index < 8; index++) {
        const word = readBigEndian(message.subarray(index * 2, index * 2 + 2))
        const key = readBigEndian(key1.subarray(index * 8, index * 8 + 8)) % PRIME36
        result = (result + word * key) % PRIME36
    }
    const translated = writeBigEndian(result & UINT32_MASK, 4)
    for (let index = 0; index < 4; index++) translated[index] ^= key2[index]
    return translated
}

/** RFC 4418 UMAC with AES-128 and cached universal-hash subkeys. */
export class UMAC {
    private readonly key: Buffer
    private readonly tagLength: UMACTagLength
    private readonly l1Key: Buffer
    private readonly l2Key: Buffer
    private readonly l3Key1: Buffer
    private readonly l3Key2: Buffer
    private readonly pdfKey: Buffer
    private disposed = false

    constructor(key: Buffer, tagLength: UMACTagLength) {
        assert(key.length === KEY_LENGTH, "UMAC requires a 16-byte key")
        assert([4, 8, 12, 16].includes(tagLength), "Invalid UMAC tag length")
        this.key = Buffer.from(key)
        this.tagLength = tagLength
        const iterations = tagLength / 4
        this.l1Key = kdf(this.key, 1, 1024 + (iterations - 1) * 16)
        this.l2Key = kdf(this.key, 2, iterations * 24)
        this.l3Key1 = kdf(this.key, 3, iterations * 64)
        this.l3Key2 = kdf(this.key, 4, iterations * 4)
        this.pdfKey = kdf(this.key, 0, KEY_LENGTH)
    }

    compute(message: Buffer, nonce: Buffer): Buffer {
        if (this.disposed) throw new Error("UMAC is disposed")
        assert(nonce.length >= 1 && nonce.length <= BLOCK_LENGTH, "Invalid UMAC nonce length")
        const iterations = this.tagLength / 4
        const hashParts: Buffer[] = []
        for (let index = 0; index < iterations; index++) {
            const l1Key = this.l1Key.subarray(index * 16, index * 16 + 1024)
            const firstLayer = l1Hash(l1Key, message)
            const secondLayer =
                message.length <= 1024
                    ? Buffer.concat([Buffer.alloc(8), firstLayer])
                    : l2Hash(this.l2Key.subarray(index * 24, index * 24 + 24), firstLayer)
            hashParts.push(
                l3Hash(
                    this.l3Key1.subarray(index * 64, index * 64 + 64),
                    this.l3Key2.subarray(index * 4, index * 4 + 4),
                    secondLayer,
                ),
            )
        }

        let padIndex = 0
        const paddedNonce = Buffer.alloc(BLOCK_LENGTH)
        nonce.copy(paddedNonce)
        if (this.tagLength === 4 || this.tagLength === 8) {
            padIndex = Number(readBigEndian(nonce) % BigInt(BLOCK_LENGTH / this.tagLength))
            paddedNonce[nonce.length - 1] ^= padIndex
        }
        const pad = aesBlock(this.pdfKey, paddedNonce).subarray(
            padIndex * this.tagLength,
            (padIndex + 1) * this.tagLength,
        )
        const hash = Buffer.concat(hashParts)
        const tag = Buffer.allocUnsafe(this.tagLength)
        for (let index = 0; index < tag.length; index++) tag[index] = pad[index] ^ hash[index]
        return tag
    }

    dispose(): void {
        if (this.disposed) return
        this.disposed = true
        this.key.fill(0)
        this.l1Key.fill(0)
        this.l2Key.fill(0)
        this.l3Key1.fill(0)
        this.l3Key2.fill(0)
        this.pdfKey.fill(0)
    }
}
