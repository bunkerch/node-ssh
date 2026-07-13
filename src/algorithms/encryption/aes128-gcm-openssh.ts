import { EncryptionAlgorithm } from "../../algorithms.js"
import AESGCM from "./aes-gcm.js"

export default class AES128GCMOpenSSH extends AESGCM {
    static alg_name = "aes128-gcm@openssh.com"
    static key_length = 16

    static instantiate(key: Buffer, iv: Buffer): EncryptionAlgorithm {
        return new AES128GCMOpenSSH(key, iv)
    }

    constructor(key: Buffer, iv: Buffer) {
        super("aes-128-gcm", key, iv, AES128GCMOpenSSH.key_length)
    }
}
