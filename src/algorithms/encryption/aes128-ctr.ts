import { EncryptionAlgorithm } from "../../algorithms.js"
import AESNCTR from "./aesN-ctr.js"

export default class AES128CTR extends AESNCTR {
    static alg_name = "aes128-ctr"
    static key_length = 16
    static iv_length = 16
    static block_size = 16

    static instantiate(key: Buffer, iv: Buffer): EncryptionAlgorithm {
        return new AES128CTR(key, iv)
    }

    constructor(key: Buffer, iv: Buffer) {
        super("aes-128-ctr", key, iv, AES128CTR.key_length)
    }
}
