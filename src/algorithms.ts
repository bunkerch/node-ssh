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
import Curve25519SHA256, { Curve25519SHA256LibSSH } from "./algorithms/kex/curve25519-sha256.js"
import {
    ECDHSHA2NISTP256,
    ECDHSHA2NISTP384,
    ECDHSHA2NISTP521,
} from "./algorithms/kex/ecdh-sha2-nist.js"

import AES128CTR from "./algorithms/encryption/aes128-ctr.js"
import AES192CTR from "./algorithms/encryption/aes192-ctr.js"
import AES256CTR from "./algorithms/encryption/aes256-ctr.js"
import AES128GCMOpenSSH from "./algorithms/encryption/aes128-gcm-openssh.js"
import AES256GCMOpenSSH from "./algorithms/encryption/aes256-gcm-openssh.js"

import HMACSHA2256 from "./algorithms/mac/hmac-sha2-256.js"
import HMACSHA2512 from "./algorithms/mac/hmac-sha2-512.js"
import HMACSHA1 from "./algorithms/mac/hmac-sha1.js"
import HMACSHA2256ETM from "./algorithms/mac/hmac-sha2-256-etm.js"
import HMACSHA2512ETM from "./algorithms/mac/hmac-sha2-512-etm.js"
import HMACSHA1ETM from "./algorithms/mac/hmac-sha1-etm.js"

import Client from "./Client.js"
import ServerClient from "./ServerClient.js"
import assert from "assert"
import PublicKey from "./utils/PublicKey.js"
import type { NegotiatedAlgorithms } from "./AlgorithmOptions.js"
import type { InboundPacketProtection, OutboundPacketProtection } from "./BinaryPacket.js"

export interface HostKeyAlgorithm {
    readonly alg_name: string
    readonly key_format: string
    readonly signature_algorithm: string
    readonly has_encryption: boolean
    readonly has_signature: boolean
}

function hostKeyAlgorithm(
    alg_name: string,
    key_format = alg_name,
    signature_algorithm = alg_name,
): HostKeyAlgorithm {
    const key = PublicKey.algorithms.get(key_format)
    assert(key, `Unsupported host key format: ${key_format}`)
    return Object.freeze({
        alg_name,
        key_format,
        signature_algorithm,
        has_encryption: key.has_encryption,
        has_signature: key.has_signature,
    })
}

export const host_key_algorithms = new Map<string, HostKeyAlgorithm>([
    ["ssh-ed25519", hostKeyAlgorithm("ssh-ed25519")],
    ["ecdsa-sha2-nistp256", hostKeyAlgorithm("ecdsa-sha2-nistp256")],
    ["ecdsa-sha2-nistp384", hostKeyAlgorithm("ecdsa-sha2-nistp384")],
    ["ecdsa-sha2-nistp521", hostKeyAlgorithm("ecdsa-sha2-nistp521")],
    ["rsa-sha2-512", hostKeyAlgorithm("rsa-sha2-512", "ssh-rsa")],
    ["rsa-sha2-256", hostKeyAlgorithm("rsa-sha2-256", "ssh-rsa")],
    ["ssh-rsa", hostKeyAlgorithm("ssh-rsa")],
])

export abstract class KexAlgorithm {
    static alg_name: string
    static requires_encryption: boolean
    static requires_signature: boolean

    static instantiate(): KexAlgorithm {
        throw new Error("Not implemented")
    }

    abstract readonly exchangeValueEncoding: "mpint" | "string"

    abstract generateKeyPair(): void
    abstract getPublicKey(): Buffer
    abstract computeSharedSecret(peerPublicKey: Buffer): void
    abstract computeHClient(client: Client, serverKexInit: Buffer): Buffer
    abstract computeHServer(client: ServerClient, clientKexInit: Buffer, hostKey: Buffer): Buffer

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    deriveKeysClient(client: Client | ServerClient): void {
        throw new Error("Not implemented")
    }
}
export const kex_algorithms = new Map<string, typeof KexAlgorithm>([
    ["curve25519-sha256", Curve25519SHA256],
    ["curve25519-sha256@libssh.org", Curve25519SHA256LibSSH],
    ["ecdh-sha2-nistp256", ECDHSHA2NISTP256],
    ["ecdh-sha2-nistp384", ECDHSHA2NISTP384],
    ["ecdh-sha2-nistp521", ECDHSHA2NISTP521],
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
    static aead?: boolean
    static auth_tag_length?: number

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

    encryptPacket?: (
        plaintext: Buffer,
        associatedData: Buffer,
    ) => { ciphertext: Buffer; authenticationTag: Buffer }

    decryptPacket?: (
        ciphertext: Buffer,
        associatedData: Buffer,
        authenticationTag: Buffer,
    ) => Buffer
}
export const encryption_algorithms = new Map<string, typeof EncryptionAlgorithm>([
    ["aes256-gcm@openssh.com", AES256GCMOpenSSH],
    ["aes128-gcm@openssh.com", AES128GCMOpenSSH],
    ["aes256-ctr", AES256CTR],
    ["aes192-ctr", AES192CTR],
    ["aes128-ctr", AES128CTR],
])

export abstract class MACAlgorithm {
    static alg_name: string
    static key_length: number
    static digest_length: number
    static encrypt_then_mac = false

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
    ["hmac-sha2-256-etm@openssh.com", HMACSHA2256ETM],
    ["hmac-sha2-512-etm@openssh.com", HMACSHA2512ETM],
    ["hmac-sha1-etm@openssh.com", HMACSHA1ETM],
    ["hmac-sha2-256", HMACSHA2256],
    ["hmac-sha2-512", HMACSHA2512],
    ["hmac-sha1", HMACSHA1],
])

export function chooseAlgorithms(client: Client | ServerClient) {
    assert(client.clientKexInit, "Client KexInit not set")
    assert(client.serverKexInit, "Server KexInit not set")
    client.debug("Choosing algorithms...")

    client.kexAlgorithm = undefined
    client.hostKeyAlgorithm = undefined
    client.clientEncryptionAlgorithm = undefined
    client.serverEncryptionAlgorithm = undefined
    client.clientMacAlgorithm = undefined
    client.serverMacAlgorithm = undefined

    const server_host_key_algorithms: HostKeyAlgorithm[] = []
    for (const alg of client.serverKexInit.data.server_host_key_algorithms) {
        const algorithm = host_key_algorithms.get(alg)
        if (!algorithm) continue

        server_host_key_algorithms.push(algorithm)
    }
    const mutual_host_key_algorithms: HostKeyAlgorithm[] = []
    for (const alg of client.clientKexInit.data.server_host_key_algorithms) {
        const algorithm = host_key_algorithms.get(alg)
        if (!algorithm) continue
        if (!server_host_key_algorithms.includes(algorithm)) continue

        mutual_host_key_algorithms.push(algorithm)
    }

    for (const name of client.clientKexInit.data.kex_algorithms) {
        if (!client.serverKexInit.data.kex_algorithms.includes(name)) continue
        const algorithm = kex_algorithms.get(name)
        if (!algorithm) continue
        const hostKeyAlgorithm = mutual_host_key_algorithms.find((alg) => {
            if (algorithm.requires_encryption && !alg.has_encryption) {
                return false
            }
            if (algorithm.requires_signature && !alg.has_signature) {
                return false
            }
            return true
        })
        if (!hostKeyAlgorithm) continue
        client.kexAlgorithm = algorithm.instantiate()
        client.hostKeyAlgorithm = hostKeyAlgorithm
        break
    }
    assert(
        client.kexAlgorithm,
        `No key exchange algorithm found (client KEX: ${client.clientKexInit.data.kex_algorithms.join(",")}; server KEX: ${client.serverKexInit.data.kex_algorithms.join(",")}; client host keys: ${client.clientKexInit.data.server_host_key_algorithms.join(",")}; server host keys: ${client.serverKexInit.data.server_host_key_algorithms.join(",")})`,
    )
    assert(client.hostKeyAlgorithm, "No host key algorithm found")

    client.clientEncryptionAlgorithm = firstRegisteredMutual(
        client.clientKexInit.data.encryption_algorithms_client_to_server,
        client.serverKexInit.data.encryption_algorithms_client_to_server,
        encryption_algorithms,
    )
    assert(client.clientEncryptionAlgorithm, "No client to server encryption algorithm found")
    client.serverEncryptionAlgorithm = firstRegisteredMutual(
        client.clientKexInit.data.encryption_algorithms_server_to_client,
        client.serverKexInit.data.encryption_algorithms_server_to_client,
        encryption_algorithms,
    )
    assert(client.serverEncryptionAlgorithm, "No server to client encryption algorithm found")

    if (!client.clientEncryptionAlgorithm.aead) {
        client.clientMacAlgorithm = firstRegisteredMutual(
            client.clientKexInit.data.mac_algorithms_client_to_server,
            client.serverKexInit.data.mac_algorithms_client_to_server,
            mac_algorithms,
        )
        assert(client.clientMacAlgorithm, "No client to server mac algorithm found")
    }
    if (!client.serverEncryptionAlgorithm.aead) {
        client.serverMacAlgorithm = firstRegisteredMutual(
            client.clientKexInit.data.mac_algorithms_server_to_client,
            client.serverKexInit.data.mac_algorithms_server_to_client,
            mac_algorithms,
        )
        assert(client.serverMacAlgorithm, "No server to client mac algorithm found")
    }

    assert(
        client.clientKexInit.data.compression_algorithms_client_to_server.includes("none") &&
            client.serverKexInit.data.compression_algorithms_client_to_server.includes("none"),
        "No supported client to server compression algorithm found",
    )
    assert(
        client.clientKexInit.data.compression_algorithms_server_to_client.includes("none") &&
            client.serverKexInit.data.compression_algorithms_server_to_client.includes("none"),
        "No supported server to client compression algorithm found",
    )

    client.debug(
        "Key Exchange Algorithm chosen:",
        (client.kexAlgorithm.constructor as typeof KexAlgorithm).alg_name,
    )
    client.debug("Host Key Algorithm chosen:", client.hostKeyAlgorithm.alg_name)
    client.debug(
        "Client to Server Encryption Algorithm chosen:",
        client.clientEncryptionAlgorithm.alg_name,
    )
    client.debug(
        "Server to Client Encryption Algorithm chosen:",
        client.serverEncryptionAlgorithm.alg_name,
    )
    client.debug(
        "Client to Server MAC Algorithm chosen:",
        client.clientMacAlgorithm?.alg_name ?? "<implicit>",
    )
    client.debug(
        "Server to Client MAC Algorithm chosen:",
        client.serverMacAlgorithm?.alg_name ?? "<implicit>",
    )
}

export function describeNegotiatedAlgorithms(
    client: Client | ServerClient,
): Readonly<NegotiatedAlgorithms> {
    assert(client.kexAlgorithm, "Key exchange algorithm not selected")
    assert(client.hostKeyAlgorithm, "Host key algorithm not selected")
    assert(client.clientEncryptionAlgorithm, "Client cipher not selected")
    assert(client.serverEncryptionAlgorithm, "Server cipher not selected")
    return Object.freeze({
        kex: (client.kexAlgorithm.constructor as typeof KexAlgorithm).alg_name,
        srvHostKey: client.hostKeyAlgorithm.alg_name,
        cs: Object.freeze({
            cipher: client.clientEncryptionAlgorithm.alg_name,
            mac: client.clientMacAlgorithm?.alg_name ?? "",
            compress: "none",
            lang: "",
        }),
        sc: Object.freeze({
            cipher: client.serverEncryptionAlgorithm.alg_name,
            mac: client.serverMacAlgorithm?.alg_name ?? "",
            compress: "none",
            lang: "",
        }),
    })
}

export function createOutboundPacketProtection(
    algorithm: typeof EncryptionAlgorithm,
    cipher: EncryptionAlgorithm,
    macAlgorithm: typeof MACAlgorithm | undefined,
    mac: MACAlgorithm | undefined,
): OutboundPacketProtection {
    if (algorithm.aead) {
        assert(cipher.encryptPacket, "AEAD cipher does not implement packet encryption")
        const authTagLength = validateAEADAlgorithm(algorithm)
        return {
            aead: true,
            cipher: { encryptPacket: cipher.encryptPacket.bind(cipher) },
            blockSize: algorithm.block_size,
            authTagLength,
        }
    }
    assert(macAlgorithm, "MAC algorithm not selected for non-AEAD cipher")
    assert(mac, "MAC not initialized for non-AEAD cipher")
    return {
        cipher,
        mac,
        blockSize: algorithm.block_size,
        macLength: macAlgorithm.digest_length,
        encryptThenMac: macAlgorithm.encrypt_then_mac,
    }
}

export function createInboundPacketProtection(
    algorithm: typeof EncryptionAlgorithm,
    cipher: EncryptionAlgorithm,
    macAlgorithm: typeof MACAlgorithm | undefined,
    mac: MACAlgorithm | undefined,
): InboundPacketProtection {
    if (algorithm.aead) {
        assert(cipher.decryptPacket, "AEAD cipher does not implement packet decryption")
        const authTagLength = validateAEADAlgorithm(algorithm)
        return {
            aead: true,
            cipher: { decryptPacket: cipher.decryptPacket.bind(cipher) },
            blockSize: algorithm.block_size,
            authTagLength,
        }
    }
    assert(macAlgorithm, "MAC algorithm not selected for non-AEAD cipher")
    assert(mac, "MAC not initialized for non-AEAD cipher")
    return {
        cipher,
        mac,
        blockSize: algorithm.block_size,
        macLength: macAlgorithm.digest_length,
        encryptThenMac: macAlgorithm.encrypt_then_mac,
    }
}

function validateAEADAlgorithm(algorithm: typeof EncryptionAlgorithm): number {
    const authTagLength = algorithm.auth_tag_length
    assert(
        Number.isSafeInteger(authTagLength) &&
            typeof authTagLength === "number" &&
            authTagLength > 0,
        "AEAD cipher has an invalid authentication tag length",
    )
    return authTagLength
}

function firstRegisteredMutual<T>(
    preferred: readonly string[],
    offered: readonly string[],
    registry: ReadonlyMap<string, T>,
): T | undefined {
    for (const name of preferred) {
        if (!offered.includes(name)) continue
        const algorithm = registry.get(name)
        if (algorithm) return algorithm
    }
    return undefined
}
