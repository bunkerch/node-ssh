import type { EncryptionAlgorithm } from "../../algorithms.js"
import CBC from "./cbc.js"

export default class AES256CBC extends CBC {
    static alg_name = "aes256-cbc"
    static key_length = 32
    static iv_length = 16
    static block_size = 16

    static instantiate(key: Buffer, iv: Buffer): EncryptionAlgorithm {
        return new AES256CBC(key, iv)
    }

    constructor(key: Buffer, iv: Buffer) {
        super("aes-256-cbc", key, iv, AES256CBC.key_length, AES256CBC.block_size)
    }
}
