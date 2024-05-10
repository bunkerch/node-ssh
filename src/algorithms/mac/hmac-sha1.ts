import crypto from "crypto"
import { MACAlgorithm } from "../../algorithms.js";

export default class HMACSHA1 implements MACAlgorithm {
    static alg_name = "hmac-sha1";
    static key_length = 20;
    static digest_length = 20;

    sequence_number: number = 0
    
    static instantiate(key: Buffer): MACAlgorithm {
        return new HMACSHA1(key)
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

        const hmac = crypto.createHmac("sha1", this.key)
        hmac.update(seq)
        hmac.update(packet)
        return hmac.digest()
    }
}