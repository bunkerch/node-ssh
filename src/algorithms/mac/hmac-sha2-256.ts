import crypto from "node:crypto"
import { MACAlgorithm } from "../../algorithms.js"

export default class HMACSHA2256 implements MACAlgorithm {
    static alg_name = "hmac-sha2-256"
    static key_length = 32
    static digest_length = 32
    static encrypt_then_mac = false

    static instantiate(key: Buffer): MACAlgorithm {
        return new HMACSHA2256(key)
    }

    readonly #key: Buffer

    constructor(key: Buffer) {
        this.#key = Buffer.from(key)
    }

    computeMAC(sequenceNumber: number, packet: Buffer): Buffer {
        const sequence = Buffer.allocUnsafe(4)

        sequence.writeUInt32BE(sequenceNumber)

        const hmac = crypto.createHmac("sha256", this.#key)
        hmac.update(sequence)
        hmac.update(packet)
        return hmac.digest()
    }
}
