import crypto from "crypto"
import { EncryptionAlgorithm } from "../../algorithms.js"

export default class AESNCTR implements EncryptionAlgorithm {
    static key_length: number
    static iv_length: number
    static block_size: number

    key: Buffer
    iv: Buffer
    encrypt_instance: crypto.Cipher
    decrypt_instance: crypto.Cipher
    constructor(algorithm: string, key: Buffer, iv: Buffer) {
        this.key = key
        this.iv = iv
        this.encrypt_instance = crypto.createCipheriv(algorithm, this.key, this.iv)
        this.decrypt_instance = crypto.createDecipheriv(algorithm, this.key, this.iv)
    }

    encrypt(plaintext: Buffer): Buffer {
        return this.encrypt_instance.update(plaintext)
    }

    decrypt(ciphertext: Buffer): Buffer {
        return this.decrypt_instance.update(ciphertext)
    }
}
