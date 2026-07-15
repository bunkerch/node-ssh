import crypto from "node:crypto"
import type { EncryptionAlgorithm } from "../../algorithms.js"

export default class CBC implements EncryptionAlgorithm {
    private readonly encryptor: crypto.Cipher
    private readonly decryptor: crypto.Decipher
    private disposed = false

    constructor(
        algorithm: string,
        key: Buffer,
        iv: Buffer,
        expectedKeyLength: number,
        private readonly blockSize: number,
    ) {
        if (key.length !== expectedKeyLength) {
            throw new Error(`SSH CBC key must be ${expectedKeyLength} bytes`)
        }
        if (iv.length !== blockSize) throw new Error(`SSH CBC IV must be ${blockSize} bytes`)
        this.encryptor = crypto.createCipheriv(algorithm, key, iv)
        this.decryptor = crypto.createDecipheriv(algorithm, key, iv)
        this.encryptor.setAutoPadding(false)
        this.decryptor.setAutoPadding(false)
    }

    encrypt(plaintext: Buffer): Buffer {
        this.assertUsable()
        this.validateBlockLength(plaintext)
        return this.encryptor.update(plaintext)
    }

    decrypt(ciphertext: Buffer): Buffer {
        this.assertUsable()
        this.validateBlockLength(ciphertext)
        return this.decryptor.update(ciphertext)
    }

    private validateBlockLength(input: Buffer): void {
        if (input.length % this.blockSize !== 0) {
            throw new Error(`SSH CBC input must be a multiple of ${this.blockSize} bytes`)
        }
    }

    dispose(): void {
        if (this.disposed) return
        this.disposed = true
        try {
            this.encryptor.final()
        } finally {
            this.decryptor.final()
        }
    }

    private assertUsable(): void {
        if (this.disposed) throw new Error("SSH CBC cipher is disposed")
    }
}
