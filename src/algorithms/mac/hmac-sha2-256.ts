import crypto from "crypto"
import { MACAlgorithm } from "../../algorithms.js";

export default class HMACSHA2256 implements MACAlgorithm {
    static alg_name = "hmac-sha2-256";
    static key_length = 32;
    static digest_length = 32;

    sequence_number: number = 0
    
    static instantiate(key: Buffer): MACAlgorithm {
        return new HMACSHA2256(key)
    }

    key: Buffer
    constructor(key: Buffer) {
        this.key = key
    }

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    computeMAC(packet: Buffer): Buffer {
        const seq = Buffer.alloc(4)
        
        seq.writeUInt32BE(this.sequence_number)
        this.sequence_number = (this.sequence_number + 1) % 2**32

        const hmac = crypto.createHmac("sha2", this.key)
        hmac.update(seq)
        hmac.update(packet)
        return hmac.digest().subarray(0, HMACSHA2256.digest_length)
    }
}