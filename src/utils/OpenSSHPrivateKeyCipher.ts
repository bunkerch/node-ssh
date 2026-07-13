import assert from "node:assert"
import { createDecipheriv, timingSafeEqual, type DecipherGCM } from "node:crypto"
import { pbkdf } from "bcrypt-pbkdf"
import { readNextBuffer, readNextUint32 } from "./Buffer.js"

interface CipherInfo {
    nodeName?: string
    blockLength: number
    keyLength: number
    ivLength: number
    authLength: number
    chacha?: true
}

const ciphers = new Map<string, CipherInfo>([
    [
        "3des-cbc",
        {
            nodeName: "des-ede3-cbc",
            blockLength: 8,
            keyLength: 24,
            ivLength: 8,
            authLength: 0,
        },
    ],
    ...([128, 192, 256] as const).flatMap((bits) =>
        (["cbc", "ctr"] as const).map(
            (mode) =>
                [
                    `aes${bits}-${mode}`,
                    {
                        nodeName: `aes-${bits}-${mode}`,
                        blockLength: 16,
                        keyLength: bits / 8,
                        ivLength: 16,
                        authLength: 0,
                    },
                ] as const,
        ),
    ),
    ...([128, 256] as const).map(
        (bits) =>
            [
                `aes${bits}-gcm@openssh.com`,
                {
                    nodeName: `aes-${bits}-gcm`,
                    blockLength: 16,
                    keyLength: bits / 8,
                    ivLength: 12,
                    authLength: 16,
                },
            ] as const,
    ),
    [
        "chacha20-poly1305@openssh.com",
        {
            blockLength: 8,
            keyLength: 64,
            ivLength: 0,
            authLength: 16,
            chacha: true,
        },
    ],
])

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

function poly1305(message: Buffer, key: Buffer): Buffer {
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

function chacha20(input: Buffer, key: Buffer, initialCounter: bigint): Buffer {
    assert(key.length === 32, "Invalid ChaCha20 key length")
    const output = Buffer.alloc(input.length)

    for (let offset = 0; offset < input.length; offset += 64) {
        const state = new Uint32Array(16)
        state.set([0x61707865, 0x3320646e, 0x79622d32, 0x6b206574])
        for (let index = 0; index < 8; index++) state[index + 4] = key.readUInt32LE(index * 4)
        const counter = initialCounter + BigInt(offset / 64)
        state[12] = Number(counter & 0xffffffffn)
        state[13] = Number((counter >> 32n) & 0xffffffffn)

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
        for (let index = 0; index < 16; index++) {
            keyStream.writeUInt32LE((working[index] + state[index]) >>> 0, index * 4)
        }
        const blockLength = Math.min(64, input.length - offset)
        for (let index = 0; index < blockLength; index++) {
            output[offset + index] = input[offset + index] ^ keyStream[index]
        }
        keyStream.fill(0)
    }

    return output
}

function decryptChacha20(ciphertext: Buffer, tag: Buffer, key: Buffer): Buffer {
    const mainKey = key.subarray(0, 32)
    const polyKey = chacha20(Buffer.alloc(32), mainKey, 0n)
    const expectedTag = poly1305(ciphertext, polyKey)
    try {
        assert(timingSafeEqual(tag, expectedTag), "OpenSSH key integrity check failed")
        return chacha20(ciphertext, mainKey, 1n)
    } finally {
        polyKey.fill(0)
        expectedTag.fill(0)
    }
}

export interface OpenSSHPrivateKeyDecryptionResult {
    plaintext: Buffer
    blockLength: number
}

export function decryptOpenSSHPrivateKey(
    cipherName: string,
    kdfName: string,
    kdfOptions: Buffer,
    ciphertext: Buffer,
    authenticationTag: Buffer,
    passphrase?: string | Buffer,
): OpenSSHPrivateKeyDecryptionResult {
    const cipher = ciphers.get(cipherName)
    assert(cipher, `Unsupported OpenSSH private key cipher: ${cipherName}`)
    assert(kdfName === "bcrypt", `Unsupported OpenSSH private key KDF: ${kdfName}`)
    assert(passphrase !== undefined, "Encrypted OpenSSH private key requires a passphrase")

    const passphraseBuffer = Buffer.isBuffer(passphrase)
        ? Buffer.from(passphrase)
        : Buffer.from(passphrase, "utf8")
    const keyAndIV = Buffer.alloc(cipher.keyLength + cipher.ivLength)
    try {
        assert(passphraseBuffer.length > 0, "Encrypted OpenSSH private key requires a passphrase")

        let salt: Buffer
        ;[salt, kdfOptions] = readNextBuffer(kdfOptions)
        let rounds: number
        ;[rounds, kdfOptions] = readNextUint32(kdfOptions)
        assert(kdfOptions.length === 0, "Invalid bcrypt KDF options")
        assert(salt.length > 0, "Invalid bcrypt KDF salt")
        assert(rounds > 0, "Invalid bcrypt KDF rounds")
        assert(ciphertext.length >= cipher.blockLength, "Invalid encrypted private key length")
        assert(
            ciphertext.length % cipher.blockLength === 0,
            "Invalid encrypted private key block length",
        )
        assert(
            authenticationTag.length === cipher.authLength,
            "Invalid private key authentication tag length",
        )

        assert(
            pbkdf(
                passphraseBuffer,
                passphraseBuffer.length,
                salt,
                salt.length,
                keyAndIV,
                keyAndIV.length,
                rounds,
            ) === 0,
            "Failed to derive OpenSSH private key encryption key",
        )

        const key = keyAndIV.subarray(0, cipher.keyLength)
        const iv = keyAndIV.subarray(cipher.keyLength)
        let plaintext: Buffer
        if (cipher.chacha) {
            plaintext = decryptChacha20(ciphertext, authenticationTag, key)
        } else {
            assert(cipher.nodeName)
            const decipher = createDecipheriv(cipher.nodeName, key, iv) as DecipherGCM
            decipher.setAutoPadding(false)
            if (cipher.authLength > 0) decipher.setAuthTag(authenticationTag)
            plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()])
        }

        return { plaintext, blockLength: cipher.blockLength }
    } finally {
        keyAndIV.fill(0)
        passphraseBuffer.fill(0)
    }
}
