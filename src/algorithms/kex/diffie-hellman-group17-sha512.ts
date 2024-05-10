
import DiffieHellmanGroupN from "./diffie-hellman-groupN.js";

export default class DiffieHellmanGroup17SHA512 extends DiffieHellmanGroupN {
    static alg_name = "diffie-hellman-group17-sha512";
    static requires_encryption = DiffieHellmanGroupN.requires_encryption;
    static requires_signature = DiffieHellmanGroupN.requires_signature;

    static instantiate(): DiffieHellmanGroup17SHA512 {
        return new DiffieHellmanGroup17SHA512();
    }

    constructor() {
        super("modp17", "sha512")
    }
}