import DiffieHellmanGroupN from "./diffie-hellman-groupN.js"

export default class DiffieHellmanGroup14SHA1 extends DiffieHellmanGroupN {
    static alg_name = "diffie-hellman-group14-sha1"
    static requires_encryption = DiffieHellmanGroupN.requires_encryption
    static requires_signature = DiffieHellmanGroupN.requires_signature

    static instantiate(): DiffieHellmanGroup14SHA1 {
        return new DiffieHellmanGroup14SHA1()
    }

    constructor() {
        super("modp14", "sha1")
    }
}
