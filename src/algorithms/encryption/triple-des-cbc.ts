import type { EncryptionAlgorithm } from "../../algorithms.js"
import CBC from "./cbc.js"

export default class TripleDESCBC extends CBC {
    static alg_name = "3des-cbc"
    static key_length = 24
    static iv_length = 8
    static block_size = 8

    static instantiate(key: Buffer, iv: Buffer): EncryptionAlgorithm {
        return new TripleDESCBC(key, iv)
    }

    constructor(key: Buffer, iv: Buffer) {
        super("des-ede3-cbc", key, iv, TripleDESCBC.key_length, TripleDESCBC.block_size)
    }
}
