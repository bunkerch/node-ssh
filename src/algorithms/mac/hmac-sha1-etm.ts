import { MACAlgorithm } from "../../algorithms.js"
import HMACSHA1 from "./hmac-sha1.js"

export default class HMACSHA1ETM extends HMACSHA1 {
    static alg_name = "hmac-sha1-etm@openssh.com"
    static encrypt_then_mac = true

    static instantiate(key: Buffer): MACAlgorithm {
        return new HMACSHA1ETM(key)
    }
}
