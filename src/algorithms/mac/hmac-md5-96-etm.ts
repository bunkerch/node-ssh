import { MACAlgorithm } from "../../algorithms.js"
import HMACMD596 from "./hmac-md5-96.js"

export default class HMACMD596ETM extends HMACMD596 {
    static alg_name = "hmac-md5-96-etm@openssh.com"
    static encrypt_then_mac = true

    static instantiate(key: Buffer): MACAlgorithm {
        return new HMACMD596ETM(key)
    }
}
