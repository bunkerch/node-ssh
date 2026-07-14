import crypto from "node:crypto"
import { MACAlgorithm } from "../../algorithms.js"

export default class HMACMD5 implements MACAlgorithm {
    static alg_name = "hmac-md5"
    static key_length = 16
    static digest_length = 16
    static encrypt_then_mac = false

    static instantiate(key: Buffer): MACAlgorithm {
        return new HMACMD5(key)
    }

    readonly #key: Buffer

    constructor(key: Buffer) {
        this.#key = Buffer.from(key)
    }

    computeMAC(sequenceNumber: number, packet: Buffer): Buffer {
        const sequence = Buffer.allocUnsafe(4)
        sequence.writeUInt32BE(sequenceNumber)
        return crypto.createHmac("md5", this.#key).update(sequence).update(packet).digest()
    }
}
