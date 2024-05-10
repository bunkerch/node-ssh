import { HostKeyAlgorithm } from "../../algorithms.js"

export default class SSHRSA implements HostKeyAlgorithm {
    static alg_name = "ssh-rsa"
    static has_encryption = false
    static has_signature = true
}
