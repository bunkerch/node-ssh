import { EncryptionAlgorithm } from "../../algorithms.js"
import AESGCM from "./aes-gcm.js"

export default class AES256GCMOpenSSH extends AESGCM {
    static alg_name = "aes256-gcm@openssh.com"
    static key_length = 32

    static instantiate(key: Buffer, iv: Buffer): EncryptionAlgorithm {
        return new AES256GCMOpenSSH(key, iv)
    }

    constructor(key: Buffer, iv: Buffer) {
        super("aes-256-gcm", key, iv, AES256GCMOpenSSH.key_length)
    }
}
