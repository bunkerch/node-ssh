import crypto from "node:crypto"
import type { EncryptionAlgorithm } from "../../algorithms.js"

export default class CBC implements EncryptionAlgorithm {
    private readonly encryptor: crypto.Cipher
    private readonly decryptor: crypto.Decipher

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
        this.validateBlockLength(plaintext)
        return this.encryptor.update(plaintext)
    }

    decrypt(ciphertext: Buffer): Buffer {
        this.validateBlockLength(ciphertext)
        return this.decryptor.update(ciphertext)
    }

    private validateBlockLength(input: Buffer): void {
        if (input.length % this.blockSize !== 0) {
            throw new Error(`SSH CBC input must be a multiple of ${this.blockSize} bytes`)
        }
    }
}
