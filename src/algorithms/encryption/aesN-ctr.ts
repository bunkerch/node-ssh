import crypto from "node:crypto"
import { EncryptionAlgorithm } from "../../algorithms.js"

export default class AESNCTR implements EncryptionAlgorithm {
    static key_length: number
    static iv_length: number
    static block_size: number

    private readonly encryptInstance: crypto.Cipher
    private readonly decryptInstance: crypto.Decipher

    constructor(algorithm: string, key: Buffer, iv: Buffer, expectedKeyLength: number) {
        if (!Buffer.isBuffer(key) || key.length !== expectedKeyLength) {
            throw new Error(`SSH AES-CTR key must be ${expectedKeyLength} bytes`)
        }
        if (!Buffer.isBuffer(iv) || iv.length !== 16) {
            throw new Error("SSH AES-CTR IV must be 16 bytes")
        }

        const ownedKey = Buffer.from(key)
        const ownedIV = Buffer.from(iv)
        try {
            this.encryptInstance = crypto.createCipheriv(algorithm, ownedKey, ownedIV)
            this.decryptInstance = crypto.createDecipheriv(algorithm, ownedKey, ownedIV)
        } finally {
            ownedKey.fill(0)
            ownedIV.fill(0)
        }
    }

    encrypt(plaintext: Buffer): Buffer {
        return this.encryptInstance.update(plaintext)
    }

    decrypt(ciphertext: Buffer): Buffer {
        return this.decryptInstance.update(ciphertext)
    }
}
