import { MACAlgorithm } from "../../algorithms.js"
import HMACSHA2512 from "./hmac-sha2-512.js"

export default class HMACSHA2512ETM extends HMACSHA2512 {
    static alg_name = "hmac-sha2-512-etm@openssh.com"
    static encrypt_then_mac = true

    static instantiate(key: Buffer): MACAlgorithm {
        return new HMACSHA2512ETM(key)
    }
}
