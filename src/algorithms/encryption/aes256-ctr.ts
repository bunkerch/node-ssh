import { EncryptionAlgorithm } from "../../algorithms.js"
import AESNCTR from "./aesN-ctr.js"

export default class AES256CTR extends AESNCTR {
    static alg_name = "aes256-ctr"
    static key_length = 32
    static iv_length = 16
    static block_size = 16

    static instantiate(key: Buffer, iv: Buffer): EncryptionAlgorithm {
        return new AES256CTR(key, iv)
    }

    constructor(key: Buffer, iv: Buffer) {
        super("aes-256-ctr", key, iv)
    }
}
