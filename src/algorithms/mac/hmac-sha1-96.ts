import { MACAlgorithm } from "../../algorithms.js"
import HMACSHA1 from "./hmac-sha1.js"

export default class HMACSHA196 extends HMACSHA1 {
    static alg_name = "hmac-sha1-96"
    static digest_length = 12

    static instantiate(key: Buffer): MACAlgorithm {
        return new HMACSHA196(key)
    }

    override computeMAC(sequenceNumber: number, packet: Buffer): Buffer {
        return super.computeMAC(sequenceNumber, packet).subarray(0, HMACSHA196.digest_length)
    }
}
