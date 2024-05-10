import crypto from "crypto"
import { EncryptionAlgorithm } from "../../algorithms.js";

export default class AES128CTR implements EncryptionAlgorithm {
    static alg_name = "aes128-ctr";
    static key_length = 16;
    static iv_length = 16;
    static block_size = 16;

    static instantiate(key: Buffer, iv: Buffer): EncryptionAlgorithm {
        return new AES128CTR(key, iv)
    }

    key: Buffer
    iv: Buffer
    encrypt_instance: crypto.Cipher
    decrypt_instance: crypto.Cipher
    constructor(key: Buffer, iv: Buffer) {
        this.key = key
        this.iv = iv
        this.encrypt_instance = crypto.createCipheriv("aes-128-ctr", this.key, this.iv)
        this.decrypt_instance = crypto.createDecipheriv("aes-128-ctr", this.key, this.iv)
    }

    encrypt(plaintext: Buffer): Buffer {
        return this.encrypt_instance.update(plaintext)
    }

    decrypt(ciphertext: Buffer): Buffer {
        return this.decrypt_instance.update(ciphertext)
    }
}