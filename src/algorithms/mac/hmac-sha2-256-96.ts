import { MACAlgorithm } from "../../algorithms.js"
import HMACSHA2256 from "./hmac-sha2-256.js"

/** Historical draft compatibility name; RFC 6668 retained only the full-length form. */
export default class HMACSHA225696 extends HMACSHA2256 {
    static alg_name = "hmac-sha2-256-96"
    static digest_length = 12

    static instantiate(key: Buffer): MACAlgorithm {
        return new HMACSHA225696(key)
    }

    override computeMAC(sequenceNumber: number, packet: Buffer): Buffer {
        return super.computeMAC(sequenceNumber, packet).subarray(0, HMACSHA225696.digest_length)
    }
}
