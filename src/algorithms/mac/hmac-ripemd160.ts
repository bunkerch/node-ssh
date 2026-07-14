import { createHmac } from "node:crypto"

import { MACAlgorithm } from "../../algorithms.js"

export default class HMACRIPEMD160 implements MACAlgorithm {
    static alg_name = "hmac-ripemd160"
    static key_length = 20
    static digest_length = 20
    static encrypt_then_mac = false

    static instantiate(key: Buffer): MACAlgorithm {
        return new HMACRIPEMD160(key)
    }

    readonly #key: Buffer

    constructor(key: Buffer) {
        if (key.length !== HMACRIPEMD160.key_length) {
            throw new Error("SSH HMAC-RIPEMD160 key must be 20 bytes")
        }
        this.#key = Buffer.from(key)
    }

    computeMAC(sequenceNumber: number, packet: Buffer): Buffer {
        const sequence = Buffer.allocUnsafe(4)
        sequence.writeUInt32BE(sequenceNumber)
        return createHmac("ripemd160", this.#key).update(sequence).update(packet).digest()
    }
}
