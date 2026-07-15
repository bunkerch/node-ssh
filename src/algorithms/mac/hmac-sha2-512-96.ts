import { MACAlgorithm } from "../../algorithms.js"
import HMACSHA2512 from "./hmac-sha2-512.js"

/** Historical draft compatibility name; RFC 6668 retained only the full-length form. */
export default class HMACSHA251296 extends HMACSHA2512 {
    static alg_name = "hmac-sha2-512-96"
    static digest_length = 12

    static instantiate(key: Buffer): MACAlgorithm {
        return new HMACSHA251296(key)
    }

    override computeMAC(sequenceNumber: number, packet: Buffer): Buffer {
        return super.computeMAC(sequenceNumber, packet).subarray(0, HMACSHA251296.digest_length)
    }
}
