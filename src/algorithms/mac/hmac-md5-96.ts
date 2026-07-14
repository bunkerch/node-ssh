import { MACAlgorithm } from "../../algorithms.js"
import HMACMD5 from "./hmac-md5.js"

export default class HMACMD596 extends HMACMD5 {
    static alg_name = "hmac-md5-96"
    static digest_length = 12

    static instantiate(key: Buffer): MACAlgorithm {
        return new HMACMD596(key)
    }

    override computeMAC(sequenceNumber: number, packet: Buffer): Buffer {
        return super.computeMAC(sequenceNumber, packet).subarray(0, HMACMD596.digest_length)
    }
}
