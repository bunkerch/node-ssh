import DiffieHellmanGroupN from "./diffie-hellman-groupN.js"

export default class DiffieHellmanGroup1SHA1 extends DiffieHellmanGroupN {
    static alg_name = "diffie-hellman-group1-sha1"
    static requires_encryption = DiffieHellmanGroupN.requires_encryption
    static requires_signature = DiffieHellmanGroupN.requires_signature

    static instantiate(): DiffieHellmanGroup1SHA1 {
        return new DiffieHellmanGroup1SHA1()
    }

    constructor() {
        super("modp2", "sha1")
    }
}
