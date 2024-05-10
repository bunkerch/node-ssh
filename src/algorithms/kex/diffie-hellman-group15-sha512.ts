
import DiffieHellmanGroupN from "./diffie-hellman-groupN.js";

export default class DiffieHellmanGroup15SHA512 extends DiffieHellmanGroupN {
    static alg_name = "diffie-hellman-group15-sha512";
    static requires_encryption = DiffieHellmanGroupN.requires_encryption;
    static requires_signature = DiffieHellmanGroupN.requires_signature;

    static instantiate(): DiffieHellmanGroup15SHA512 {
        return new DiffieHellmanGroup15SHA512();
    }

    constructor() {
        super("modp15", "sha512")
    }
}