import crypto from "node:crypto"
import { EncryptionAlgorithm } from "../../algorithms.js"

const UINT64_MAX = 0xffff_ffff_ffff_ffffn

export default abstract class AESGCM implements EncryptionAlgorithm {
    static aead = true
    static auth_tag_length = 16
    static iv_length = 12
    static block_size = 16

    private readonly key: Buffer
    private readonly initialIV: Buffer
    private invocationCounter: bigint
    private exhausted = false

    protected constructor(
        private readonly algorithm: "aes-128-gcm" | "aes-256-gcm",
        key: Buffer,
        iv: Buffer,
        expectedKeyLength: number,
    ) {
        if (key.length !== expectedKeyLength) {
            throw new Error(`SSH AES-GCM key must be ${expectedKeyLength} bytes`)
        }
        if (iv.length !== 12) throw new Error("SSH AES-GCM IV must be 12 bytes")

        this.key = Buffer.from(key)
        this.initialIV = Buffer.from(iv)
        this.invocationCounter = iv.readBigUInt64BE(4)
    }

    encrypt(): Buffer {
        throw new Error("SSH AES-GCM operates on complete binary packets")
    }

    decrypt(): Buffer {
        throw new Error("SSH AES-GCM operates on complete binary packets")
    }

    encryptPacket(
        plaintext: Buffer,
        associatedData: Buffer,
    ): { ciphertext: Buffer; authenticationTag: Buffer } {
        const cipher = crypto.createCipheriv(this.algorithm, this.key, this.nextIV(), {
            authTagLength: 16,
        })
        cipher.setAutoPadding(false)
        cipher.setAAD(associatedData, { plaintextLength: plaintext.length })
        const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()])
        return { ciphertext, authenticationTag: cipher.getAuthTag() }
    }

    decryptPacket(ciphertext: Buffer, associatedData: Buffer, authenticationTag: Buffer): Buffer {
        if (authenticationTag.length !== 16) {
            throw new Error("SSH AES-GCM authentication tag must be 16 bytes")
        }

        const decipher = crypto.createDecipheriv(this.algorithm, this.key, this.nextIV(), {
            authTagLength: 16,
        })
        decipher.setAutoPadding(false)
        decipher.setAAD(associatedData, { plaintextLength: ciphertext.length })
        decipher.setAuthTag(authenticationTag)
        try {
            return Buffer.concat([decipher.update(ciphertext), decipher.final()])
        } catch {
            throw new Error("SSH AES-GCM authentication failed")
        }
    }

    private nextIV(): Buffer {
        if (this.exhausted) {
            throw new Error("SSH AES-GCM invocation counter exhausted; rekey is required")
        }

        const iv = Buffer.from(this.initialIV)
        iv.writeBigUInt64BE(this.invocationCounter, 4)
        if (this.invocationCounter === UINT64_MAX) this.exhausted = true
        else this.invocationCounter++
        return iv
    }
}
