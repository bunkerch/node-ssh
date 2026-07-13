import type { EncryptionAlgorithm } from "../../algorithms.js"
import CBC from "./cbc.js"

export default class AES192CBC extends CBC {
    static alg_name = "aes192-cbc"
    static key_length = 24
    static iv_length = 16
    static block_size = 16

    static instantiate(key: Buffer, iv: Buffer): EncryptionAlgorithm {
        return new AES192CBC(key, iv)
    }

    constructor(key: Buffer, iv: Buffer) {
        super("aes-192-cbc", key, iv, AES192CBC.key_length, AES192CBC.block_size)
    }
}
