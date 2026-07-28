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
import Curve448SHA512 from "./algorithms/kex/curve448-sha512.js"
import DiffieHellmanGroupExchangeSHA256, {
    DiffieHellmanGroupExchangeSHA1,
} from "./algorithms/kex/diffie-hellman-group-exchange.js"
import {
    ECDHSHA2NISTP256,
    ECDHSHA2NISTP384,
    ECDHSHA2NISTP521,
} from "./algorithms/kex/ecdh-sha2-nist.js"
import RSA2048SHA256 from "./algorithms/kex/rsa2048-sha256.js"
import SNTRUP761X25519SHA512, {
    SNTRUP761X25519SHA512OpenSSH,
} from "./algorithms/kex/sntrup761x25519-sha512.js"
import {
    MLKEM1024NISTP384SHA384,
    MLKEM768NISTP256SHA256,
    MLKEM768X25519SHA256,
} from "./algorithms/kex/mlkem-hybrid.js"
import { MLKEM1024SHA384, MLKEM512SHA256, MLKEM768SHA256 } from "./algorithms/kex/mlkem.js"

import AES128CTR from "./algorithms/encryption/aes128-ctr.js"
import AES192CTR from "./algorithms/encryption/aes192-ctr.js"
import AES256CTR from "./algorithms/encryption/aes256-ctr.js"
import AES128GCMOpenSSH from "./algorithms/encryption/aes128-gcm-openssh.js"
import AES256GCMOpenSSH from "./algorithms/encryption/aes256-gcm-openssh.js"
import { AEADAES128GCM, AEADAES256GCM } from "./algorithms/encryption/aead-aes-gcm.js"
import ChaCha20Poly1305OpenSSH, {
    ChaCha20Poly1305,
} from "./algorithms/encryption/chacha20-poly1305-openssh.js"
import { SSHZlibCompressor, SSHZlibDecompressor } from "./algorithms/compression/zlib.js"
import AES128CBC from "./algorithms/encryption/aes128-cbc.js"
import AES192CBC from "./algorithms/encryption/aes192-cbc.js"
import AES256CBC from "./algorithms/encryption/aes256-cbc.js"
import BlowfishCBC from "./algorithms/encryption/blowfish-cbc.js"
import Cast128CBC from "./algorithms/encryption/cast128-cbc.js"
import TripleDESCBC from "./algorithms/encryption/triple-des-cbc.js"

import HMACSHA2256 from "./algorithms/mac/hmac-sha2-256.js"
import HMACSHA2512 from "./algorithms/mac/hmac-sha2-512.js"
import HMACSHA225696 from "./algorithms/mac/hmac-sha2-256-96.js"
import HMACSHA251296 from "./algorithms/mac/hmac-sha2-512-96.js"
import HMACSHA1 from "./algorithms/mac/hmac-sha1.js"
import HMACSHA2256ETM from "./algorithms/mac/hmac-sha2-256-etm.js"
import HMACSHA2512ETM from "./algorithms/mac/hmac-sha2-512-etm.js"
import HMACSHA1ETM from "./algorithms/mac/hmac-sha1-etm.js"
import HMACSHA196 from "./algorithms/mac/hmac-sha1-96.js"
import HMACSHA196ETM from "./algorithms/mac/hmac-sha1-96-etm.js"
import HMACMD5 from "./algorithms/mac/hmac-md5.js"
import HMACMD596 from "./algorithms/mac/hmac-md5-96.js"
import HMACMD5ETM from "./algorithms/mac/hmac-md5-etm.js"
import HMACMD596ETM from "./algorithms/mac/hmac-md5-96-etm.js"
import HMACRIPEMD160 from "./algorithms/mac/hmac-ripemd160.js"
import {
    UMAC128ETMOpenSSH,
    UMAC128OpenSSH,
    UMAC64ETMOpenSSH,
    UMAC64OpenSSH,
} from "./algorithms/mac/umac.js"

import assert from "assert"
import PublicKey from "./utils/PublicKey.js"
import {
    SSH_ECDSA_SECURITY_KEY_ALGORITHM,
    SSH_ED25519_SECURITY_KEY_ALGORITHM,
    SSH_WEBAUTHN_ECDSA_SECURITY_KEY_ALGORITHM,
} from "./utils/Signature.js"
import type { NegotiatedAlgorithms, ResolvedAlgorithmOptions } from "./AlgorithmOptions.js"
import type { InboundPacketProtection, OutboundPacketProtection } from "./BinaryPacket.js"
import { MAXIMUM_BINARY_PACKET_SIZE } from "./BinaryPacket.js"
import type { KexInitData } from "./packets/KexInit.js"

export interface HostKeyAlgorithm {
    readonly alg_name: string
    readonly key_format: string
    readonly signature_algorithm: string
    readonly has_encryption: boolean
    readonly has_signature: boolean
}

export type KeyExchangeRole = "client" | "server"

function hostKeyAlgorithm(
    alg_name: string,
    key_format = alg_name,
    signature_algorithm = alg_name,
    capabilityKeyFormat = key_format,
): HostKeyAlgorithm {
    const key = PublicKey.algorithms.get(capabilityKeyFormat)
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
    [
        "null",
        Object.freeze({
            alg_name: "null",
            key_format: "null",
            signature_algorithm: "null",
            has_encryption: false,
            has_signature: false,
        }),
    ],
    [
        "ssh-ed25519-cert",
        hostKeyAlgorithm("ssh-ed25519-cert", "ssh-ed25519-cert", "ssh-ed25519", "ssh-ed25519"),
    ],
    [
        "ssh-ed448-cert",
        hostKeyAlgorithm("ssh-ed448-cert", "ssh-ed448-cert", "ssh-ed448", "ssh-ed448"),
    ],
    ...["nistp256", "nistp384", "nistp521"].map((curve) => {
        const plain = `ecdsa-sha2-${curve}`
        const certificate = `${plain}-cert`
        return [certificate, hostKeyAlgorithm(certificate, certificate, plain, plain)] as const
    }),
    [
        "rsa-sha2-512-cert",
        hostKeyAlgorithm("rsa-sha2-512-cert", "ssh-rsa-cert", "rsa-sha2-512", "ssh-rsa"),
    ],
    [
        "rsa-sha2-256-cert",
        hostKeyAlgorithm("rsa-sha2-256-cert", "ssh-rsa-cert", "rsa-sha2-256", "ssh-rsa"),
    ],
    ["ssh-rsa-cert", hostKeyAlgorithm("ssh-rsa-cert", "ssh-rsa-cert", "ssh-rsa", "ssh-rsa")],
    ["ssh-dss-cert", hostKeyAlgorithm("ssh-dss-cert", "ssh-dss-cert", "ssh-dss", "ssh-dss")],
    [
        "ssh-ed25519-cert-v01@openssh.com",
        hostKeyAlgorithm(
            "ssh-ed25519-cert-v01@openssh.com",
            "ssh-ed25519-cert-v01@openssh.com",
            "ssh-ed25519",
            "ssh-ed25519",
        ),
    ],
    ...["nistp256", "nistp384", "nistp521"].map((curve) => {
        const plain = `ecdsa-sha2-${curve}`
        const certificate = `${plain}-cert-v01@openssh.com`
        return [certificate, hostKeyAlgorithm(certificate, certificate, plain, plain)] as const
    }),
    [
        "rsa-sha2-512-cert-v01@openssh.com",
        hostKeyAlgorithm(
            "rsa-sha2-512-cert-v01@openssh.com",
            "ssh-rsa-cert-v01@openssh.com",
            "rsa-sha2-512",
            "ssh-rsa",
        ),
    ],
    [
        "rsa-sha2-256-cert-v01@openssh.com",
        hostKeyAlgorithm(
            "rsa-sha2-256-cert-v01@openssh.com",
            "ssh-rsa-cert-v01@openssh.com",
            "rsa-sha2-256",
            "ssh-rsa",
        ),
    ],
    ["ssh-ed25519", hostKeyAlgorithm("ssh-ed25519")],
    ["ssh-ed448", hostKeyAlgorithm("ssh-ed448")],
    ["ecdsa-sha2-nistp256", hostKeyAlgorithm("ecdsa-sha2-nistp256")],
    ["ecdsa-sha2-nistp384", hostKeyAlgorithm("ecdsa-sha2-nistp384")],
    ["ecdsa-sha2-nistp521", hostKeyAlgorithm("ecdsa-sha2-nistp521")],
    ["rsa-sha2-512", hostKeyAlgorithm("rsa-sha2-512", "ssh-rsa")],
    ["rsa-sha2-256", hostKeyAlgorithm("rsa-sha2-256", "ssh-rsa")],
    ["ssh-rsa", hostKeyAlgorithm("ssh-rsa")],
    [
        "ssh-rsa-cert-v01@openssh.com",
        hostKeyAlgorithm(
            "ssh-rsa-cert-v01@openssh.com",
            "ssh-rsa-cert-v01@openssh.com",
            "ssh-rsa",
            "ssh-rsa",
        ),
    ],
    ["ssh-dss", hostKeyAlgorithm("ssh-dss")],
    [
        "ssh-dss-cert-v01@openssh.com",
        hostKeyAlgorithm(
            "ssh-dss-cert-v01@openssh.com",
            "ssh-dss-cert-v01@openssh.com",
            "ssh-dss",
            "ssh-dss",
        ),
    ],
])

function securityKeyCertificateAlgorithm(algorithm: string): string {
    const suffix = "@openssh.com"
    assert(algorithm.endsWith(suffix))
    return `${algorithm.slice(0, -suffix.length)}-cert-v01@openssh.com`
}

export const public_key_signature_algorithms: readonly string[] = Object.freeze([
    ...Array.from(host_key_algorithms.keys()).filter((name) => name !== "null"),
    SSH_ED25519_SECURITY_KEY_ALGORITHM,
    securityKeyCertificateAlgorithm(SSH_ED25519_SECURITY_KEY_ALGORITHM),
    SSH_ECDSA_SECURITY_KEY_ALGORITHM,
    securityKeyCertificateAlgorithm(SSH_ECDSA_SECURITY_KEY_ALGORITHM),
    SSH_WEBAUTHN_ECDSA_SECURITY_KEY_ALGORITHM,
    securityKeyCertificateAlgorithm(SSH_WEBAUTHN_ECDSA_SECURITY_KEY_ALGORITHM),
])

const legacyPublicKeySignatureAlgorithms = new Set([
    "ssh-rsa",
    "ssh-rsa-cert",
    "ssh-rsa-cert-v01@openssh.com",
    "ssh-dss",
    "ssh-dss-cert",
    "ssh-dss-cert-v01@openssh.com",
])

/** User-authentication signature algorithms enabled without an explicit legacy opt-in. */
export const default_public_key_signature_algorithms: readonly string[] = Object.freeze(
    public_key_signature_algorithms.filter(
        (algorithm) => !legacyPublicKeySignatureAlgorithms.has(algorithm),
    ),
)

export abstract class KexAlgorithm {
    static alg_name: string
    static requires_encryption: boolean
    static requires_signature: boolean

    static instantiate(): KexAlgorithm {
        throw new Error("Not implemented")
    }

    abstract readonly exchangeValueEncoding: "mpint" | "string"

    abstract generateKeyPair(role?: KeyExchangeRole): void
    abstract getPublicKey(): Buffer
    abstract computeSharedSecret(peerPublicKey: Buffer): void
    abstract getSharedSecret(): Buffer
    abstract dispose(): void
    abstract computeExchangeHash(context: Readonly<KeyExchangeHashContext>): Buffer

    deriveTransportKeys(
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        exchangeHash: Buffer,
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        sessionID: Buffer,
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        lengths: TransportKeyLengths,
    ): DerivedTransportKeys {
        throw new Error("Not implemented")
    }
}
export interface KeyExchangeHashContext {
    readonly clientVersion: string
    readonly serverVersion: string
    readonly clientKexInit: Buffer
    readonly serverKexInit: Buffer
    readonly serverHostKey: Buffer
    readonly clientExchangeValue?: Buffer
    readonly serverExchangeValue?: Buffer
}
export interface TransportKeyLengths {
    readonly clientIV: number
    readonly serverIV: number
    readonly clientEncryption: number
    readonly serverEncryption: number
    readonly clientIntegrity: number
    readonly serverIntegrity: number
}
export interface DerivedTransportKeys {
    readonly clientIV: Buffer
    readonly serverIV: Buffer
    readonly clientEncryption: Buffer
    readonly serverEncryption: Buffer
    readonly clientIntegrity: Buffer
    readonly serverIntegrity: Buffer
}
export interface KexAlgorithmFactory {
    readonly alg_name: string
    readonly requires_encryption: boolean
    readonly requires_signature: boolean
    instantiate(): KexAlgorithm
}
export const kex_algorithms = new Map<string, KexAlgorithmFactory>([
    ["mlkem768x25519-sha256", MLKEM768X25519SHA256],
    ["mlkem768nistp256-sha256", MLKEM768NISTP256SHA256],
    ["mlkem1024nistp384-sha384", MLKEM1024NISTP384SHA384],
    ["mlkem512-sha256", MLKEM512SHA256],
    ["mlkem768-sha256", MLKEM768SHA256],
    ["mlkem1024-sha384", MLKEM1024SHA384],
    ["sntrup761x25519-sha512", SNTRUP761X25519SHA512],
    ["sntrup761x25519-sha512@openssh.com", SNTRUP761X25519SHA512OpenSSH],
    ["curve25519-sha256", Curve25519SHA256],
    ["curve25519-sha256@libssh.org", Curve25519SHA256LibSSH],
    ["curve448-sha512", Curve448SHA512],
    ["ecdh-sha2-nistp256", ECDHSHA2NISTP256],
    ["ecdh-sha2-nistp384", ECDHSHA2NISTP384],
    ["ecdh-sha2-nistp521", ECDHSHA2NISTP521],
    ["diffie-hellman-group-exchange-sha256", DiffieHellmanGroupExchangeSHA256],
    ["diffie-hellman-group16-sha512", DiffieHellmanGroup16SHA512],
    ["diffie-hellman-group18-sha512", DiffieHellmanGroup18SHA512],
    ["diffie-hellman-group17-sha512", DiffieHellmanGroup17SHA512],
    ["diffie-hellman-group15-sha512", DiffieHellmanGroup15SHA512],
    ["diffie-hellman-group14-sha256", DiffieHellmanGroup14SHA256],
    ["rsa2048-sha256", RSA2048SHA256],

    // RFC 9142 keeps these legacy methods available only for explicit interoperability.
    ["diffie-hellman-group14-sha1", DiffieHellmanGroup14SHA1],
    ["diffie-hellman-group1-sha1", DiffieHellmanGroup1SHA1],
    ["diffie-hellman-group-exchange-sha1", DiffieHellmanGroupExchangeSHA1],
])

export abstract class EncryptionAlgorithm {
    static alg_name: string
    static key_length: number
    static iv_length: number
    static block_size: number
    static aead?: boolean
    static auth_tag_length?: number
    /** RFC AEAD algorithms that occupy both negotiation lists require this exact MAC name. */
    static required_mac?: string
    dispose?(): void

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
        sequenceNumber: number,
        plaintext: Buffer,
    ) => { ciphertext: Buffer; authenticationTag: Buffer }

    decryptPacketLength?: (sequenceNumber: number, encryptedLength: Buffer) => Buffer

    decryptPacket?: (
        sequenceNumber: number,
        ciphertext: Buffer,
        authenticationTag: Buffer,
    ) => Buffer
}
export const encryption_algorithms = new Map<string, typeof EncryptionAlgorithm>([
    ["chacha20-poly1305", ChaCha20Poly1305],
    ["chacha20-poly1305@openssh.com", ChaCha20Poly1305OpenSSH],
    ["aes256-gcm@openssh.com", AES256GCMOpenSSH],
    ["aes128-gcm@openssh.com", AES128GCMOpenSSH],
    ["AEAD_AES_256_GCM", AEADAES256GCM],
    ["AEAD_AES_128_GCM", AEADAES128GCM],
    ["aes256-ctr", AES256CTR],
    ["aes192-ctr", AES192CTR],
    ["aes128-ctr", AES128CTR],
    ["aes256-cbc", AES256CBC],
    ["aes192-cbc", AES192CBC],
    ["aes128-cbc", AES128CBC],
    ["blowfish-cbc", BlowfishCBC],
    ["cast128-cbc", Cast128CBC],
    ["3des-cbc", TripleDESCBC],
])

export abstract class MACAlgorithm {
    static alg_name: string
    static key_length: number
    static digest_length: number
    static encrypt_then_mac = false
    dispose?(): void

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

export function instantiateMACAlgorithm(algorithm: typeof MACAlgorithm, key: Buffer): MACAlgorithm {
    assert(
        Buffer.isBuffer(key) && key.length === algorithm.key_length,
        `${algorithm.alg_name} MAC key must be ${algorithm.key_length} bytes`,
    )
    return algorithm.instantiate(key)
}

export function instantiateEncryptionAlgorithm(
    algorithm: typeof EncryptionAlgorithm,
    key: Buffer,
    iv: Buffer,
): EncryptionAlgorithm {
    assert(
        Buffer.isBuffer(key) && key.length === algorithm.key_length,
        `${algorithm.alg_name} cipher key must be ${algorithm.key_length} bytes`,
    )
    assert(
        Buffer.isBuffer(iv) && iv.length === algorithm.iv_length,
        `${algorithm.alg_name} cipher IV must be ${algorithm.iv_length} bytes`,
    )
    return algorithm.instantiate(key, iv)
}

export const mac_algorithms = new Map<string, typeof MACAlgorithm>([
    ["umac-64-etm@openssh.com", UMAC64ETMOpenSSH],
    ["umac-128-etm@openssh.com", UMAC128ETMOpenSSH],
    ["hmac-sha2-256-etm@openssh.com", HMACSHA2256ETM],
    ["hmac-sha2-512-etm@openssh.com", HMACSHA2512ETM],
    ["hmac-sha1-etm@openssh.com", HMACSHA1ETM],
    ["hmac-sha1-96-etm@openssh.com", HMACSHA196ETM],
    ["umac-64@openssh.com", UMAC64OpenSSH],
    ["umac-128@openssh.com", UMAC128OpenSSH],
    ["hmac-sha2-256", HMACSHA2256],
    ["hmac-sha2-512", HMACSHA2512],
    ["hmac-sha2-256-96", HMACSHA225696],
    ["hmac-sha2-512-96", HMACSHA251296],
    ["hmac-sha1", HMACSHA1],
    ["hmac-sha1-96", HMACSHA196],
    ["hmac-md5-etm@openssh.com", HMACMD5ETM],
    ["hmac-md5-96-etm@openssh.com", HMACMD596ETM],
    ["hmac-md5", HMACMD5],
    ["hmac-md5-96", HMACMD596],
    ["hmac-ripemd160", HMACRIPEMD160],
])

export const mac_algorithm_names: readonly string[] = Object.freeze([
    ...mac_algorithms.keys(),
    AEADAES256GCM.required_mac,
    AEADAES128GCM.required_mac,
])

export interface CompressionAlgorithm {
    readonly alg_name: "none" | "zlib" | "zlib@openssh.com"
    readonly delayed: boolean
    readonly enabled: boolean
}

export const compression_algorithms = new Map<string, CompressionAlgorithm>([
    ["none", Object.freeze({ alg_name: "none", delayed: false, enabled: false })],
    [
        "zlib@openssh.com",
        Object.freeze({ alg_name: "zlib@openssh.com", delayed: true, enabled: true }),
    ],
    ["zlib", Object.freeze({ alg_name: "zlib", delayed: false, enabled: true })],
])

export const default_algorithm_names: ResolvedAlgorithmOptions = Object.freeze({
    kex: Object.freeze([
        "mlkem768x25519-sha256",
        "mlkem768nistp256-sha256",
        "mlkem1024nistp384-sha384",
        "sntrup761x25519-sha512",
        "sntrup761x25519-sha512@openssh.com",
        "curve25519-sha256",
        "curve25519-sha256@libssh.org",
        "curve448-sha512",
        "ecdh-sha2-nistp256",
        "ecdh-sha2-nistp384",
        "ecdh-sha2-nistp521",
        "diffie-hellman-group-exchange-sha256",
        "diffie-hellman-group16-sha512",
        "diffie-hellman-group18-sha512",
        "diffie-hellman-group17-sha512",
        "diffie-hellman-group15-sha512",
        "diffie-hellman-group14-sha256",
    ]),
    serverHostKey: Object.freeze([
        "ssh-ed25519-cert-v01@openssh.com",
        "ecdsa-sha2-nistp256-cert-v01@openssh.com",
        "ecdsa-sha2-nistp384-cert-v01@openssh.com",
        "ecdsa-sha2-nistp521-cert-v01@openssh.com",
        "rsa-sha2-512-cert-v01@openssh.com",
        "rsa-sha2-256-cert-v01@openssh.com",
        "ssh-ed25519",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "rsa-sha2-512",
        "rsa-sha2-256",
    ]),
    cipher: Object.freeze([
        "chacha20-poly1305",
        "chacha20-poly1305@openssh.com",
        "aes256-gcm@openssh.com",
        "aes128-gcm@openssh.com",
        "aes256-ctr",
        "aes192-ctr",
        "aes128-ctr",
    ]),
    hmac: Object.freeze([
        "umac-128-etm@openssh.com",
        "umac-64-etm@openssh.com",
        "hmac-sha2-256-etm@openssh.com",
        "hmac-sha2-512-etm@openssh.com",
        "hmac-sha2-256",
        "hmac-sha2-512",
    ]),
    compress: Object.freeze(["none", "zlib@openssh.com", "zlib"]),
})

export interface ChosenAlgorithms {
    readonly keyExchange: KexAlgorithm
    readonly hostKey: HostKeyAlgorithm
    readonly clientEncryption: typeof EncryptionAlgorithm
    readonly serverEncryption: typeof EncryptionAlgorithm
    readonly clientMac?: typeof MACAlgorithm
    readonly serverMac?: typeof MACAlgorithm
    readonly clientCompression: CompressionAlgorithm
    readonly serverCompression: CompressionAlgorithm
}

export interface InstantiatedTransportAlgorithms {
    readonly clientEncryption: EncryptionAlgorithm
    readonly serverEncryption: EncryptionAlgorithm
    readonly clientMac?: MACAlgorithm
    readonly serverMac?: MACAlgorithm
}

export function instantiateTransportAlgorithms(
    algorithms: Pick<
        ChosenAlgorithms,
        "clientEncryption" | "serverEncryption" | "clientMac" | "serverMac"
    >,
    keys: DerivedTransportKeys,
): InstantiatedTransportAlgorithms {
    let clientEncryption: EncryptionAlgorithm | undefined
    let serverEncryption: EncryptionAlgorithm | undefined
    let clientMac: MACAlgorithm | undefined
    let serverMac: MACAlgorithm | undefined
    try {
        clientEncryption = instantiateEncryptionAlgorithm(
            algorithms.clientEncryption,
            keys.clientEncryption,
            keys.clientIV,
        )
        serverEncryption = instantiateEncryptionAlgorithm(
            algorithms.serverEncryption,
            keys.serverEncryption,
            keys.serverIV,
        )
        clientMac = algorithms.clientMac
            ? instantiateMACAlgorithm(algorithms.clientMac, keys.clientIntegrity)
            : undefined
        serverMac = algorithms.serverMac
            ? instantiateMACAlgorithm(algorithms.serverMac, keys.serverIntegrity)
            : undefined
        return { clientEncryption, serverEncryption, clientMac, serverMac }
    } catch (error) {
        clientEncryption?.dispose?.()
        serverEncryption?.dispose?.()
        clientMac?.dispose?.()
        serverMac?.dispose?.()
        throw error
    }
}

export interface AlgorithmSelectionInput {
    readonly clientOffer: Readonly<KexInitData>
    readonly serverOffer: Readonly<KexInitData>
    readonly keyExchanges: ReadonlyMap<string, KexAlgorithmFactory>
    readonly debug?: (...message: unknown[]) => void
}

export function chooseAlgorithms(input: AlgorithmSelectionInput): ChosenAlgorithms {
    const { clientOffer, serverOffer, keyExchanges } = input
    const debug = input.debug ?? (() => undefined)
    debug("Choosing algorithms...")

    const server_host_key_algorithms: HostKeyAlgorithm[] = []
    for (const alg of serverOffer.server_host_key_algorithms) {
        const algorithm = host_key_algorithms.get(alg)
        if (!algorithm) continue

        server_host_key_algorithms.push(algorithm)
    }
    const mutual_host_key_algorithms: HostKeyAlgorithm[] = []
    for (const alg of clientOffer.server_host_key_algorithms) {
        const algorithm = host_key_algorithms.get(alg)
        if (!algorithm) continue
        if (!server_host_key_algorithms.includes(algorithm)) continue

        mutual_host_key_algorithms.push(algorithm)
    }

    let keyExchange: KexAlgorithm | undefined
    let hostKey: HostKeyAlgorithm | undefined
    for (const name of clientOffer.kex_algorithms) {
        if (!serverOffer.kex_algorithms.includes(name)) continue
        const algorithm = keyExchanges.get(name)
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
        keyExchange = algorithm.instantiate()
        hostKey = hostKeyAlgorithm
        break
    }
    assert(
        keyExchange,
        `No key exchange algorithm found (client KEX: ${clientOffer.kex_algorithms.join(",")}; server KEX: ${serverOffer.kex_algorithms.join(",")}; client host keys: ${clientOffer.server_host_key_algorithms.join(",")}; server host keys: ${serverOffer.server_host_key_algorithms.join(",")})`,
    )
    assert(hostKey, "No host key algorithm found")

    const clientEncryption = firstRegisteredMutual(
        clientOffer.encryption_algorithms_client_to_server,
        serverOffer.encryption_algorithms_client_to_server,
        encryption_algorithms,
    )
    assert(clientEncryption, "No client to server encryption algorithm found")
    const serverEncryption = firstRegisteredMutual(
        clientOffer.encryption_algorithms_server_to_client,
        serverOffer.encryption_algorithms_server_to_client,
        encryption_algorithms,
    )
    assert(serverEncryption, "No server to client encryption algorithm found")

    const clientMac = negotiateMACAlgorithm(
        "client to server",
        clientEncryption,
        clientOffer.mac_algorithms_client_to_server,
        serverOffer.mac_algorithms_client_to_server,
    )
    const serverMac = negotiateMACAlgorithm(
        "server to client",
        serverEncryption,
        clientOffer.mac_algorithms_server_to_client,
        serverOffer.mac_algorithms_server_to_client,
    )

    const clientCompression = firstRegisteredMutual(
        clientOffer.compression_algorithms_client_to_server,
        serverOffer.compression_algorithms_client_to_server,
        compression_algorithms,
    )
    assert(clientCompression, "No client to server compression algorithm found")
    const serverCompression = firstRegisteredMutual(
        clientOffer.compression_algorithms_server_to_client,
        serverOffer.compression_algorithms_server_to_client,
        compression_algorithms,
    )
    assert(serverCompression, "No server to client compression algorithm found")

    debug(
        "Key Exchange Algorithm chosen:",
        (keyExchange.constructor as typeof KexAlgorithm).alg_name,
    )
    debug("Host Key Algorithm chosen:", hostKey.alg_name)
    debug("Client to Server Encryption Algorithm chosen:", clientEncryption.alg_name)
    debug("Server to Client Encryption Algorithm chosen:", serverEncryption.alg_name)
    debug(
        "Client to Server MAC Algorithm chosen:",
        negotiatedMACName(clientEncryption, clientMac) || "<implicit>",
    )
    debug(
        "Server to Client MAC Algorithm chosen:",
        negotiatedMACName(serverEncryption, serverMac) || "<implicit>",
    )
    debug("Client to Server Compression Algorithm chosen:", clientCompression.alg_name)
    debug("Server to Client Compression Algorithm chosen:", serverCompression.alg_name)

    return {
        keyExchange,
        hostKey,
        clientEncryption,
        serverEncryption,
        clientMac,
        serverMac,
        clientCompression,
        serverCompression,
    }
}

export function describeNegotiatedAlgorithms(
    algorithms: ChosenAlgorithms,
): Readonly<NegotiatedAlgorithms> {
    return Object.freeze({
        kex: (algorithms.keyExchange.constructor as typeof KexAlgorithm).alg_name,
        srvHostKey: algorithms.hostKey.alg_name,
        cs: Object.freeze({
            cipher: algorithms.clientEncryption.alg_name,
            mac: negotiatedMACName(algorithms.clientEncryption, algorithms.clientMac),
            compress: algorithms.clientCompression.alg_name,
            lang: "",
        }),
        sc: Object.freeze({
            cipher: algorithms.serverEncryption.alg_name,
            mac: negotiatedMACName(algorithms.serverEncryption, algorithms.serverMac),
            compress: algorithms.serverCompression.alg_name,
            lang: "",
        }),
    })
}

export function createPacketCompressor(
    algorithm: CompressionAlgorithm,
    authenticated: boolean,
): SSHZlibCompressor | undefined {
    if (!algorithm.enabled || (algorithm.delayed && !authenticated)) return undefined
    return new SSHZlibCompressor()
}

export function createPacketDecompressor(
    algorithm: CompressionAlgorithm,
    authenticated: boolean,
): SSHZlibDecompressor | undefined {
    if (!algorithm.enabled || (algorithm.delayed && !authenticated)) return undefined
    return new SSHZlibDecompressor(MAXIMUM_BINARY_PACKET_SIZE)
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
            dispose: () => cipher.dispose?.(),
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
        dispose: () => {
            cipher.dispose?.()
            mac.dispose?.()
        },
    }
}

export function createInboundPacketProtection(
    algorithm: typeof EncryptionAlgorithm,
    cipher: EncryptionAlgorithm,
    macAlgorithm: typeof MACAlgorithm | undefined,
    mac: MACAlgorithm | undefined,
): InboundPacketProtection {
    if (algorithm.aead) {
        assert(cipher.decryptPacketLength, "AEAD cipher does not implement length decryption")
        assert(cipher.decryptPacket, "AEAD cipher does not implement packet decryption")
        const authTagLength = validateAEADAlgorithm(algorithm)
        return {
            aead: true,
            cipher: {
                decryptPacketLength: cipher.decryptPacketLength.bind(cipher),
                decryptPacket: cipher.decryptPacket.bind(cipher),
            },
            blockSize: algorithm.block_size,
            authTagLength,
            dispose: () => cipher.dispose?.(),
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
        dispose: () => {
            cipher.dispose?.()
            mac.dispose?.()
        },
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

function negotiatedMACName(
    encryption: typeof EncryptionAlgorithm,
    mac: typeof MACAlgorithm | undefined,
): string {
    return encryption.required_mac ?? mac?.alg_name ?? ""
}

function negotiateMACAlgorithm(
    direction: string,
    encryption: typeof EncryptionAlgorithm,
    preferred: readonly string[],
    offered: readonly string[],
): typeof MACAlgorithm | undefined {
    if (encryption.aead && encryption.required_mac === undefined) return undefined

    const selectedName = firstMutualName(preferred, offered, mac_algorithm_names)
    assert(selectedName, `No ${direction} mac algorithm found`)
    if (encryption.required_mac !== undefined) {
        assert(
            selectedName === encryption.required_mac,
            `${encryption.alg_name} requires ${encryption.required_mac} as the ${direction} MAC algorithm`,
        )
        return undefined
    }

    const algorithm = mac_algorithms.get(selectedName)
    assert(
        algorithm,
        `${selectedName} may only be selected with the same RFC 5647 encryption algorithm`,
    )
    return algorithm
}

function firstMutualName(
    preferred: readonly string[],
    offered: readonly string[],
    supported: readonly string[],
): string | undefined {
    return preferred.find((name) => offered.includes(name) && supported.includes(name))
}
