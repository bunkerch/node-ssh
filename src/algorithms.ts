// BE CAUTIOUS
// if the different algorithms import anything else than abstract classes
// client will create a circular dependency
import DiffieHellmanGroup1SHA1 from "./algorithms/kex/diffie-hellman-group1-sha1.js"
import DiffieHellmanGroup14SHA1 from "./algorithms/kex/diffie-hellman-group14-sha1.js"
import DiffieHellmanGroup14SHA256 from "./algorithms/kex/diffie-hellman-group14-sha256.js"
import DiffieHellmanGroup18SHA512 from "./algorithms/kex/diffie-hellman-group18-sha512.js"
import DiffieHellmanGroup16SHA512 from "./algorithms/kex/diffie-hellman-group16-sha512.js"
import DiffieHellmanGroup15SHA512 from "./algorithms/kex/diffie-hellman-group15-sha512.js"
import DiffieHellmanGroup17SHA512 from "./algorithms/kex/diffie-hellman-group17-sha512.js"

import AES128CTR from "./algorithms/encryption/aes128-ctr.js"
import AES192CTR from "./algorithms/encryption/aes192-ctr.js"
import AES256CTR from "./algorithms/encryption/aes256-ctr.js"

import HMACSHA2256 from "./algorithms/mac/hmac-sha2-256.js"
import HMACSHA1 from "./algorithms/mac/hmac-sha1.js"

import Client from "./Client.js"
import ServerClient from "./ServerClient.js"
import assert from "assert"
import PublicKey, { PublicKeyAlgoritm } from "./utils/PublicKey.js"

export abstract class KexAlgorithm {
    static alg_name: string
    static requires_encryption: boolean
    static requires_signature: boolean

    constructor() {
        throw new Error("Not implemented")
    }

    static instantiate(): KexAlgorithm {
        throw new Error("Not implemented")
    }

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    deriveKeysClient(client: Client): void {
        throw new Error("Not implemented")
    }
}
export const kex_algorithms = new Map<string, typeof KexAlgorithm>([
    ["diffie-hellman-group16-sha512", DiffieHellmanGroup16SHA512],
    ["diffie-hellman-group18-sha512", DiffieHellmanGroup18SHA512],
    ["diffie-hellman-group17-sha512", DiffieHellmanGroup17SHA512],
    ["diffie-hellman-group15-sha512", DiffieHellmanGroup15SHA512],
    ["diffie-hellman-group14-sha256", DiffieHellmanGroup14SHA256],
    ["diffie-hellman-group14-sha1", DiffieHellmanGroup14SHA1],

    // OpenSSH supports client method, but does not enable it by default because it
    // is weak and within theoretical range of the so-called Logjam attack.
    // TODO: Figure if we should disable it.
    ["diffie-hellman-group1-sha1", DiffieHellmanGroup1SHA1],
])

export abstract class EncryptionAlgorithm {
    static alg_name: string
    static key_length: number
    static iv_length: number
    static block_size: number

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    constructor(key: Buffer, iv: Buffer) {
        throw new Error("Not implemented")
    }

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    static instantiate(key: Buffer, iv: Buffer): EncryptionAlgorithm {
        throw new Error("Not implemented")
    }

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    encrypt(plaintext: Buffer): Buffer {
        throw new Error("Not implemented")
    }

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    decrypt(ciphertext: Buffer): Buffer {
        throw new Error("Not implemented")
    }
}
export const encryption_algorithms = new Map<string, typeof EncryptionAlgorithm>([
    ["aes256-ctr", AES256CTR],
    ["aes192-ctr", AES192CTR],
    ["aes128-ctr", AES128CTR],
])

export abstract class MACAlgorithm {
    static alg_name: string
    static key_length: number
    static digest_length: number

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    constructor(key: Buffer) {
        throw new Error("Not implemented")
    }

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    static instantiate(key: Buffer): MACAlgorithm {
        throw new Error("Not implemented")
    }

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    computeMAC(sequence_number: number, packet: Buffer): Buffer {
        throw new Error("Not implemented")
    }
}
export const mac_algorithms = new Map<string, typeof MACAlgorithm>([
    ["hmac-sha2-256", HMACSHA2256],
    ["hmac-sha1", HMACSHA1],
])

export function chooseAlgorithms(client: Client | ServerClient) {
    assert(client.clientKexInit, "Client KexInit not set")
    assert(client.serverKexInit, "Server KexInit not set")
    client.debug("Choosing algorithms...")

    // TODO: I feel like client code could be cleaned a bit...
    // I tried to follow the spec word by word.
    // https://datatracker.ietf.org/doc/html/rfc4253#section-7.1

    const server_host_key_algorithms: (typeof PublicKeyAlgoritm)[] = []
    for (const alg of client.serverKexInit.data.server_host_key_algorithms) {
        const algorithm = PublicKey.algorithms.get(alg)
        if (!algorithm) continue

        server_host_key_algorithms.push(algorithm)
    }
    const host_key_algorithms: (typeof PublicKeyAlgoritm)[] = []
    for (const alg of client.clientKexInit.data.server_host_key_algorithms) {
        const algorithm = PublicKey.algorithms.get(alg)
        if (!algorithm) continue
        if (!server_host_key_algorithms.includes(algorithm)) continue

        host_key_algorithms.push(algorithm)
    }

    if (
        client.clientKexInit.data.kex_algorithms[0] == client.serverKexInit.data.kex_algorithms[0]
    ) {
        client.debug(
            "Key Exchange Algorithm guessed right:",
            client.clientKexInit.data.kex_algorithms[0],
        )

        const algorithm = kex_algorithms.get(client.clientKexInit.data.kex_algorithms[0])!
        assert(algorithm, "Invalid key exchange algorithm")
        client.kexAlgorithm = algorithm.instantiate()

        const host_key_algorithm = host_key_algorithms.find((alg) => {
            if (algorithm.requires_encryption && !alg.has_encryption) {
                return false
            }
            if (algorithm.requires_signature && !alg.has_signature) {
                return false
            }
            return true
        })
        assert(host_key_algorithm, "No compatible host key algorithm found")
        client.hostKeyAlgorithm = host_key_algorithm
    } else {
        for (const alg of client.clientKexInit.data.kex_algorithms) {
            if (!client.serverKexInit.data.kex_algorithms.includes(alg)) {
                continue
            }
            const algorithm = kex_algorithms.get(alg)!
            // client is the client algorithms
            // we shouldn't have put an algorithm we don't support
            // assert is fine, it means we have a bug if it throws
            assert(algorithm, "Invalid key exchange algorithm")

            // need a compatible host key to provide encryption and signature if needed
            const host_key_algorithm = host_key_algorithms.find((alg) => {
                if (algorithm.requires_encryption && !alg.has_encryption) {
                    return false
                }
                if (algorithm.requires_signature && !alg.has_signature) {
                    return false
                }
                return true
            })
            if (!host_key_algorithm) {
                continue
            }

            client.kexAlgorithm = algorithm.instantiate()
            client.hostKeyAlgorithm = host_key_algorithm
            break
        }
        assert(client.kexAlgorithm, "No key exchange algorithm found")
        assert(client.hostKeyAlgorithm, "No host key algorithm found")
    }

    // TODO: Figure out why this needs a reverse
    // I will rewrite this to be cleaner later.
    for (const alg of [
        ...client.clientKexInit.data.encryption_algorithms_client_to_server,
    ].reverse()) {
        if (!client.serverKexInit.data.encryption_algorithms_client_to_server.includes(alg)) {
            continue
        }

        const algorithm = encryption_algorithms.get(alg)!
        assert(algorithm, "Invalid encryption algorithm")

        client.clientEncryptionAlgorithm = algorithm
    }
    assert(client.clientEncryptionAlgorithm, "No client to server encryption algorithm found")
    for (const alg of [
        ...client.clientKexInit.data.encryption_algorithms_server_to_client,
    ].reverse()) {
        if (!client.serverKexInit.data.encryption_algorithms_server_to_client.includes(alg)) {
            continue
        }

        const algorithm = encryption_algorithms.get(alg)!
        assert(algorithm, "Invalid encryption algorithm")

        client.serverEncryptionAlgorithm = algorithm
    }
    assert(client.serverEncryptionAlgorithm, "No server to client encryption algorithm found")

    for (const alg of [...client.clientKexInit.data.mac_algorithms_client_to_server].reverse()) {
        if (!client.serverKexInit.data.mac_algorithms_client_to_server.includes(alg)) {
            continue
        }

        const algorithm = mac_algorithms.get(alg)!
        assert(algorithm, "Invalid mac algorithm")

        client.clientMacAlgorithm = algorithm
    }
    assert(client.clientMacAlgorithm, "No client to server mac algorithm found")
    for (const alg of [...client.clientKexInit.data.mac_algorithms_server_to_client].reverse()) {
        if (!client.serverKexInit.data.mac_algorithms_server_to_client.includes(alg)) {
            continue
        }

        const algorithm = mac_algorithms.get(alg)!
        assert(algorithm, "Invalid mac algorithm")

        client.serverMacAlgorithm = algorithm
    }
    assert(client.serverMacAlgorithm, "No server to client mac algorithm found")

    // TODO: Implement languages (?)
    // TODO: Implement compression

    client.debug("Key Exchange Algorithm chosen:", client.kexAlgorithm)
    client.debug("Host Key Algorithm chosen:", client.hostKeyAlgorithm)
    client.debug("Client to Server Encryption Algorithm chosen:", client.clientEncryptionAlgorithm)
    client.debug("Server to Client Encryption Algorithm chosen:", client.serverEncryptionAlgorithm)
    client.debug("Client to Server MAC Algorithm chosen:", client.clientMacAlgorithm)
    client.debug("Server to Client MAC Algorithm chosen:", client.serverMacAlgorithm)
}
