import { MACAlgorithm } from "../../algorithms.js"
import HMACSHA2256 from "./hmac-sha2-256.js"

export default class HMACSHA2256ETM extends HMACSHA2256 {
    static alg_name = "hmac-sha2-256-etm@openssh.com"
    static encrypt_then_mac = true

    static instantiate(key: Buffer): MACAlgorithm {
        return new HMACSHA2256ETM(key)
    }
}
