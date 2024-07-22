import { EncryptionAlgorithm } from "../../algorithms.js"
import AESNCTR from "./aesN-ctr.js"

export default class AES192CTR extends AESNCTR {
    static alg_name = "aes192-ctr"
    static key_length = 24
    static iv_length = 16
    static block_size = 16

    static instantiate(key: Buffer, iv: Buffer): EncryptionAlgorithm {
        return new AES192CTR(key, iv)
    }

    constructor(key: Buffer, iv: Buffer) {
        super("aes-192-ctr", key, iv)
    }
}
