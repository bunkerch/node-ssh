import DiffieHellmanGroupN from "./diffie-hellman-groupN.js"

// RFC 4253 section 8.1 uses Oakley Group 2 from RFC 2409 section 6.2.
const prime = Buffer.from(
    "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd1" +
        "29024e088a67cc74020bbea63b139b22514a08798e3404dd" +
        "ef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245" +
        "e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed" +
        "ee386bfb5a899fa5ae9f24117c4b1fe649286651ece65381" +
        "ffffffffffffffff",
    "hex",
)

export default class DiffieHellmanGroup1SHA1 extends DiffieHellmanGroupN {
    static alg_name = "diffie-hellman-group1-sha1"
    static requires_encryption = DiffieHellmanGroupN.requires_encryption
    static requires_signature = DiffieHellmanGroupN.requires_signature

    static instantiate(): DiffieHellmanGroup1SHA1 {
        return new DiffieHellmanGroup1SHA1()
    }

    constructor(privateKey?: Buffer) {
        super("modp2", "sha1", privateKey, { prime, generator: Buffer.from([2]) })
    }
}
