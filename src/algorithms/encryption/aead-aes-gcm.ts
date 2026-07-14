import { EncryptionAlgorithm } from "../../algorithms.js"
import AESGCM from "./aes-gcm.js"

export class AEADAES128GCM extends AESGCM {
    static alg_name = "AEAD_AES_128_GCM"
    static key_length = 16
    static required_mac = AEADAES128GCM.alg_name

    static instantiate(key: Buffer, iv: Buffer): EncryptionAlgorithm {
        return new AEADAES128GCM(key, iv)
    }

    constructor(key: Buffer, iv: Buffer) {
        super("aes-128-gcm", key, iv, AEADAES128GCM.key_length)
    }
}

export class AEADAES256GCM extends AESGCM {
    static alg_name = "AEAD_AES_256_GCM"
    static key_length = 32
    static required_mac = AEADAES256GCM.alg_name

    static instantiate(key: Buffer, iv: Buffer): EncryptionAlgorithm {
        return new AEADAES256GCM(key, iv)
    }

    constructor(key: Buffer, iv: Buffer) {
        super("aes-256-gcm", key, iv, AEADAES256GCM.key_length)
    }
}
