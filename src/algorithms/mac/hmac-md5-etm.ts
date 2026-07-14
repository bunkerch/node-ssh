import { MACAlgorithm } from "../../algorithms.js"
import HMACMD5 from "./hmac-md5.js"

export default class HMACMD5ETM extends HMACMD5 {
    static alg_name = "hmac-md5-etm@openssh.com"
    static encrypt_then_mac = true

    static instantiate(key: Buffer): MACAlgorithm {
        return new HMACMD5ETM(key)
    }
}
