import { MACAlgorithm } from "../../algorithms.js"
import HMACSHA196 from "./hmac-sha1-96.js"

export default class HMACSHA196ETM extends HMACSHA196 {
    static alg_name = "hmac-sha1-96-etm@openssh.com"
    static encrypt_then_mac = true

    static instantiate(key: Buffer): MACAlgorithm {
        return new HMACSHA196ETM(key)
    }
}
