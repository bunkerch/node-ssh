import crypto from "crypto"
import { MACAlgorithm } from "../../algorithms.js"

export default class HMACSHA2256 implements MACAlgorithm {
    static alg_name = "hmac-sha2-256"
    static key_length = 32
    static digest_length = 32

    static instantiate(key: Buffer): MACAlgorithm {
        return new HMACSHA2256(key)
    }

    key: Buffer
    constructor(key: Buffer) {
        this.key = key
    }

    computeMAC(sequence_number: number, packet: Buffer): Buffer {
        const seq = Buffer.alloc(4)

        seq.writeUInt32BE(sequence_number)

        const hmac = crypto.createHmac("sha256", this.key)
        hmac.update(seq)
        hmac.update(packet)
        return hmac.digest()
    }
}
