
import DiffieHellmanGroupN from "./diffie-hellman-groupN.js";

export default class DiffieHellmanGroup16SHA512 extends DiffieHellmanGroupN {
    static alg_name = "diffie-hellman-group16-sha512";
    static requires_encryption = DiffieHellmanGroupN.requires_encryption;
    static requires_signature = DiffieHellmanGroupN.requires_signature;

    static instantiate(): DiffieHellmanGroup16SHA512 {
        return new DiffieHellmanGroup16SHA512();
    }

    constructor() {
        super("modp16", "sha512")
    }
}