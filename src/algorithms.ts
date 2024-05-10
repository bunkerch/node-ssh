// BE CAUTIOUS
// if the different algorithms import anything else than abstract classes
// this will create a circular dependency
import DiffieHellmanGroup1SHA1 from "./algorithms/kex/diffie-hellman-group1-sha1.js";
import DiffieHellmanGroup14SHA1 from "./algorithms/kex/diffie-hellman-group14-sha1.js";
import DiffieHellmanGroup14SHA256 from "./algorithms/kex/diffie-hellman-group14-sha256.js";
import DiffieHellmanGroup18SHA512 from "./algorithms/kex/diffie-hellman-group18-sha512.js";
import DiffieHellmanGroup16SHA512 from "./algorithms/kex/diffie-hellman-group16-sha512.js";
import DiffieHellmanGroup15SHA512 from "./algorithms/kex/diffie-hellman-group15-sha512.js";
import DiffieHellmanGroup17SHA512 from "./algorithms/kex/diffie-hellman-group17-sha512.js";

import SSHRSA from "./algorithms/host_key/ssh-rsa.js";

import AES128CTR from "./algorithms/encryption/aes128-ctr.js";

//import HMACSHA2256 from "./algorithms/mac/hmac-sha2-256.js";
import HMACSHA1 from "./algorithms/mac/hmac-sha1.js";

import Client from "./Client.js";

export abstract class KexAlgorithm {
    static alg_name: string;
    static requires_encryption: boolean;
    static requires_signature: boolean;

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    constructor() {
        throw new Error("Not implemented");
    }

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    static instantiate(): KexAlgorithm{
        throw new Error("Not implemented");
    }

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    deriveKeysClient(client: Client): void {
        throw new Error("Not implemented");
    }
}
export const kex_algorithms = new Map<string, typeof KexAlgorithm>([
    ["diffie-hellman-group16-sha512", DiffieHellmanGroup16SHA512],
    ["diffie-hellman-group18-sha512", DiffieHellmanGroup18SHA512],
    ["diffie-hellman-group17-sha512", DiffieHellmanGroup17SHA512],
    ["diffie-hellman-group15-sha512", DiffieHellmanGroup15SHA512],
    ["diffie-hellman-group14-sha256", DiffieHellmanGroup14SHA256],
    ["diffie-hellman-group14-sha1", DiffieHellmanGroup14SHA1],

    // OpenSSH supports this method, but does not enable it by default because it
    // is weak and within theoretical range of the so-called Logjam attack.
    // TODO: Figure if we should disable it.
    ["diffie-hellman-group1-sha1", DiffieHellmanGroup1SHA1],
])

export abstract class HostKeyAlgorithm {
    static alg_name: string;
    static has_encryption: boolean;
    static has_signature: boolean;
}
export const host_key_algorithms = new Map<string, typeof HostKeyAlgorithm>([
    ["ssh-rsa", SSHRSA],
])

export abstract class EncryptionAlgorithm {
    static alg_name: string;
    static key_length: number;
    static iv_length: number;
    static block_size: number;

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    constructor(key: Buffer, iv: Buffer) {
        throw new Error("Not implemented");
    }

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    static instantiate(key: Buffer, iv: Buffer): EncryptionAlgorithm {
        throw new Error("Not implemented");
    }

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    encrypt(plaintext: Buffer): Buffer {
        throw new Error("Not implemented");
    }

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    decrypt(ciphertext: Buffer): Buffer {
        throw new Error("Not implemented");
    }
}
export const encryption_algorithms = new Map<string, typeof EncryptionAlgorithm>([
    ["aes128-ctr", AES128CTR],
])

export abstract class MACAlgorithm {
    static alg_name: string;
    static key_length: number;
    static digest_length: number;

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    constructor(key: Buffer) {
        throw new Error("Not implemented");
    }

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    static instantiate(key: Buffer): MACAlgorithm {
        throw new Error("Not implemented");
    }

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    computeMAC(sequence_number: number, packet: Buffer): Buffer {
        throw new Error("Not implemented");
    }
}
export const mac_algorithms = new Map<string, typeof MACAlgorithm>([
    //["hmac-sha2-256", HMACSHA2256],
    ["hmac-sha1", HMACSHA1],
])