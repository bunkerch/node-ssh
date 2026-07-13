import type { EncryptionAlgorithm } from "../../algorithms.js"
import CBC from "./cbc.js"

export default class AES128CBC extends CBC {
    static alg_name = "aes128-cbc"
    static key_length = 16
    static iv_length = 16
    static block_size = 16

    static instantiate(key: Buffer, iv: Buffer): EncryptionAlgorithm {
        return new AES128CBC(key, iv)
    }

    constructor(key: Buffer, iv: Buffer) {
        super("aes-128-cbc", key, iv, AES128CBC.key_length, AES128CBC.block_size)
    }
}
