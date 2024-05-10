import DiffieHellmanGroupN from "./diffie-hellman-groupN.js"

export default class DiffieHellmanGroup18SHA512 extends DiffieHellmanGroupN {
    static alg_name = "diffie-hellman-group18-sha512"
    static requires_encryption = DiffieHellmanGroupN.requires_encryption
    static requires_signature = DiffieHellmanGroupN.requires_signature

    static instantiate(): DiffieHellmanGroup18SHA512 {
        return new DiffieHellmanGroup18SHA512()
    }

    constructor() {
        super("modp18", "sha512")
    }
}
