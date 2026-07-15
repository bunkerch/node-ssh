import assert from "node:assert"
import { timingSafeEqual } from "node:crypto"
import { EncryptionAlgorithm } from "../../algorithms.js"
import { chacha20, poly1305 } from "../../utils/chacha20.js"

const UINT32_MAX = 0xffff_ffff

export default class ChaCha20Poly1305OpenSSH implements EncryptionAlgorithm {
    static alg_name = "chacha20-poly1305@openssh.com"
    static key_length = 64
    static iv_length = 0
    static block_size = 8
    static aead = true
    static auth_tag_length = 16

    private readonly payloadKey: Buffer
    private readonly lengthKey: Buffer
    private lastSequenceNumber?: number
    private disposed = false

    static instantiate(key: Buffer, iv: Buffer): EncryptionAlgorithm {
        return new ChaCha20Poly1305OpenSSH(key, iv)
    }

    constructor(key: Buffer, iv: Buffer) {
        assert(key.length === 64, "SSH ChaCha20-Poly1305 key must be 64 bytes")
        assert(iv.length === 0, "SSH ChaCha20-Poly1305 does not use a derived IV")
        // The protocol names the first half K_2 (payload/MAC) and the second K_1 (length).
        this.payloadKey = Buffer.from(key.subarray(0, 32))
        this.lengthKey = Buffer.from(key.subarray(32))
    }

    encrypt(): Buffer {
        throw new Error("SSH ChaCha20-Poly1305 operates on complete binary packets")
    }

    decrypt(): Buffer {
        throw new Error("SSH ChaCha20-Poly1305 operates on complete binary packets")
    }

    encryptPacket(
        sequenceNumber: number,
        plaintext: Buffer,
    ): { ciphertext: Buffer; authenticationTag: Buffer } {
        this.assertUsable()
        assert(plaintext.length >= 4, "SSH ChaCha20-Poly1305 packet is missing its length")
        this.consumeSequenceNumber(sequenceNumber)
        const nonce = sequenceNonce(sequenceNumber)
        const encryptedLength = chacha20(plaintext.subarray(0, 4), this.lengthKey, 0n, nonce)
        const encryptedBody = chacha20(plaintext.subarray(4), this.payloadKey, 1n, nonce)
        const ciphertext = Buffer.concat([encryptedLength, encryptedBody])
        const authenticationKey = chacha20(Buffer.alloc(32), this.payloadKey, 0n, nonce)
        try {
            return { ciphertext, authenticationTag: poly1305(ciphertext, authenticationKey) }
        } finally {
            authenticationKey.fill(0)
        }
    }

    decryptPacketLength(sequenceNumber: number, encryptedLength: Buffer): Buffer {
        this.assertUsable()
        assert(encryptedLength.length === 4, "SSH ChaCha20-Poly1305 length must be 4 bytes")
        this.validateNextSequenceNumber(sequenceNumber)
        return chacha20(encryptedLength, this.lengthKey, 0n, sequenceNonce(sequenceNumber))
    }

    decryptPacket(sequenceNumber: number, ciphertext: Buffer, authenticationTag: Buffer): Buffer {
        this.assertUsable()
        assert(ciphertext.length >= 4, "SSH ChaCha20-Poly1305 packet is missing its length")
        assert(
            authenticationTag.length === 16,
            "SSH ChaCha20-Poly1305 authentication tag must be 16 bytes",
        )
        this.consumeSequenceNumber(sequenceNumber)
        const nonce = sequenceNonce(sequenceNumber)
        const authenticationKey = chacha20(Buffer.alloc(32), this.payloadKey, 0n, nonce)
        const expectedTag = poly1305(ciphertext, authenticationKey)
        try {
            if (!timingSafeEqual(authenticationTag, expectedTag)) {
                throw new Error("SSH ChaCha20-Poly1305 authentication failed")
            }
        } finally {
            authenticationKey.fill(0)
            expectedTag.fill(0)
        }

        const length = chacha20(ciphertext.subarray(0, 4), this.lengthKey, 0n, nonce)
        const body = chacha20(ciphertext.subarray(4), this.payloadKey, 1n, nonce)
        return Buffer.concat([length, body])
    }

    private consumeSequenceNumber(sequenceNumber: number): void {
        this.validateNextSequenceNumber(sequenceNumber)
        this.lastSequenceNumber = sequenceNumber
    }

    private validateNextSequenceNumber(sequenceNumber: number): void {
        validateSequenceNumber(sequenceNumber)
        if (this.lastSequenceNumber !== undefined) {
            assert(
                this.lastSequenceNumber < UINT32_MAX &&
                    sequenceNumber === this.lastSequenceNumber + 1,
                "SSH ChaCha20-Poly1305 nonce reuse; rekey is required",
            )
        }
    }

    dispose(): void {
        if (this.disposed) return
        this.disposed = true
        this.payloadKey.fill(0)
        this.lengthKey.fill(0)
    }

    private assertUsable(): void {
        if (this.disposed) throw new Error("SSH ChaCha20-Poly1305 cipher is disposed")
    }
}

function validateSequenceNumber(sequenceNumber: number): void {
    assert(
        Number.isSafeInteger(sequenceNumber) && sequenceNumber >= 0 && sequenceNumber <= UINT32_MAX,
        "Invalid SSH packet sequence number",
    )
}

function sequenceNonce(sequenceNumber: number): Buffer {
    const nonce = Buffer.alloc(8)
    nonce.writeBigUInt64BE(BigInt(sequenceNumber))
    return nonce
}
