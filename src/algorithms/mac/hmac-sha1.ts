import crypto from "crypto"
import { MACAlgorithm } from "../../algorithms.js"

export default class HMACSHA1 implements MACAlgorithm {
    static alg_name = "hmac-sha1"
    static key_length = 20
    static digest_length = 20

    static instantiate(key: Buffer): MACAlgorithm {
        return new HMACSHA1(key)
    }

    key: Buffer
    constructor(key: Buffer) {
        this.key = key
    }

    computeMAC(sequence_number: number, packet: Buffer): Buffer {
        const seq = Buffer.allocUnsafe(4)

        seq.writeUInt32BE(sequence_number)

        const hmac = crypto.createHmac("sha1", this.key)
        hmac.update(seq)
        hmac.update(packet)
        return hmac.digest()
    }
}
