import assert from "assert"
import {
    readNextBuffer,
    readNextCString,
    readNextUint8,
    readNextUint32,
    serializeBuffer,
    serializeCString,
    serializeUint8,
    serializeUint32,
} from "./Buffer.js"
import PublicKey, {
    ECDSA_CURVES,
    type ECDSACurve,
    SSHED25519PublicKey,
    SSHED448PublicKey,
    SSHDSSPublicKey,
    SSHECDSAPublicKey,
    SSHRSAPublicKey,
    SSHCertificatePublicKey,
    SSHECDSASecurityKeyPublicKey,
    SSHED25519SecurityKeyPublicKey,
    encodeSSHKeyComment,
} from "./PublicKey.js"
import nacl from "tweetnacl"
import {
    checkPrimeSync,
    createECDH,
    createPrivateKey,
    createSign,
    generateKeyPair as generateNodeKeyPair,
    generateKeyPairSync as generateNodeKeyPairSync,
    KeyObject,
    randomBytes,
} from "crypto"
import EncodedSignature from "./Signature.js"
import asn1js from "asn1js"
import { decodeBigIntBE, encodeBigIntBE } from "./BigInt.js"
import {
    decryptOpenSSHPrivateKey,
    encryptOpenSSHPrivateKey,
    getOpenSSHPrivateKeyCipherBlockLength,
    type OpenSSHPrivateKeyEncryptionOptions,
} from "./OpenSSHPrivateKeyCipher.js"
import { parseBufferToMpintBuffer, serializeMpintBufferToBuffer } from "./mpint.js"
import {
    dsaPrivateKey,
    dsaParametersFromPrivateKey,
    signDSA,
    type DSAPrivateParameters,
    validateDSAPrivateParameters,
} from "./DSA.js"
import { ed448 } from "@noble/curves/ed448.js"
import { p256, p384, p521 } from "@noble/curves/nist.js"
import { decodeSSHName, encodeSSHName } from "./SSHName.js"
import { decodeSSHUTF8 } from "./SSHText.js"
import {
    isPuTTYPrivateKey,
    parsePuTTYPrivateKey,
    type ParsedPuTTYPrivateKey,
} from "./PuTTYPrivateKey.js"

const OPENSSH_PRIVATE_KEY_MAGIC = Buffer.from("openssh-key-v1", "ascii")
const OPENSSH_PRIVATE_KEY_BEGIN_MARKER = "-----BEGIN OPENSSH PRIVATE KEY-----"
const OPENSSH_PRIVATE_KEY_END_MARKER = "-----END OPENSSH PRIVATE KEY-----"
const OPENSSH_PRIVATE_KEY_ARMOR_LINE_LENGTH = 70
const MAX_OPENSSH_PRIVATE_KEY_LENGTH = 16 * 1024 * 1024
const MAX_OPENSSH_PRIVATE_KEY_ARMOR_LENGTH = 24 * 1024 * 1024
const MAX_OPENSSH_PRIVATE_KEYS = 1024

function decodeOpenSSHPrivateKeyArmor(data: string): Buffer {
    assert(
        Buffer.byteLength(data, "utf8") <= MAX_OPENSSH_PRIVATE_KEY_ARMOR_LENGTH,
        `OpenSSH private key armor exceeds ${MAX_OPENSSH_PRIVATE_KEY_ARMOR_LENGTH} bytes`,
    )
    assert(/^[\x20-\x7e\r\n]*$/u.test(data), "OpenSSH private key armor must contain ASCII text")

    const lines = data.split(/\r\n|\n/u)
    if (lines.at(-1) === "") lines.pop()
    assert(lines[0] === OPENSSH_PRIVATE_KEY_BEGIN_MARKER, "Invalid private key begin marker")
    assert(lines.at(-1) === OPENSSH_PRIVATE_KEY_END_MARKER, "Invalid private key end marker")
    assert(lines.length >= 3, "OpenSSH private key armor has no body")

    const body = lines.slice(1, -1)
    assert(
        body.every((line) => line.length > 0),
        "OpenSSH private key armor contains a blank line",
    )
    const base64 = body.join("")
    assert(/^[A-Za-z0-9+/]+={0,2}$/u.test(base64), "Invalid private key base64")
    assert(base64.length % 4 === 0, "Invalid private key base64 length")
    const decoded = Buffer.from(base64, "base64")
    assert(decoded.toString("base64") === base64, "Non-canonical private key base64")
    return decoded
}

export interface PrivateKeyData {
    publicKey: PublicKey
    alg: string
    algorithm: PrivateKeyAlgorithm
    comment?: string
}

export default class PrivateKey {
    static algorithms = new Map<string, typeof PrivateKeyAlgorithm>()

    data: PrivateKeyData
    constructor(data: PrivateKeyData) {
        encodeSSHName(data.alg, "SSH private key algorithm")
        assert(
            data.alg === data.publicKey.data.alg,
            "Private key algorithm does not match public key",
        )
        const expectedPublicKey = data.algorithm.getPublicKey()
        const suppliedPublicKey =
            data.publicKey.data.algorithm instanceof SSHCertificatePublicKey
                ? data.publicKey.data.algorithm.publicKey
                : data.publicKey
        assert(
            suppliedPublicKey.equals(expectedPublicKey),
            "Private and public key data do not match",
        )
        if (data.comment !== undefined) encodeSSHKeyComment(data.comment)
        this.data = { ...data }
    }

    sign(
        data: Buffer,
        algorithm = this.data.publicKey.data.algorithm instanceof SSHCertificatePublicKey
            ? this.data.publicKey.data.alg
            : this.data.alg,
    ): EncodedSignature {
        const signatureAlgorithm =
            this.data.publicKey.data.algorithm instanceof SSHCertificatePublicKey
                ? this.data.publicKey.signatureAlgorithmFor(algorithm)
                : algorithm
        return this.data.algorithm.sign(data, signatureAlgorithm)
    }

    withCertificate(certificate: PublicKey): PrivateKey {
        assert(
            certificate.data.algorithm instanceof SSHCertificatePublicKey,
            "A certificate public key is required",
        )
        assert(
            certificate.data.algorithm.publicKey.equals(this.data.publicKey),
            "Certificate does not match the private key",
        )
        return new PrivateKey({ ...this.data, alg: certificate.data.alg, publicKey: certificate })
    }

    serialize(options?: OpenSSHPrivateKeyEncryptionOptions): Buffer {
        return PrivateKey.serializeMany([this], options)
    }

    static serializeMany(
        keys: readonly PrivateKey[],
        options?: OpenSSHPrivateKeyEncryptionOptions,
    ): Buffer {
        assert(keys.length > 0, "At least one private key is required")
        assert(
            keys.length <= MAX_OPENSSH_PRIVATE_KEYS,
            `Private key container exceeds the ${MAX_OPENSSH_PRIVATE_KEYS}-key limit`,
        )
        const cipherName = options?.cipher ?? "aes256-ctr"
        const blockLength = options ? getOpenSSHPrivateKeyCipherBlockLength(cipherName) : 8
        const prv: Buffer[] = []
        const algorithmPayloads: Buffer[] = []
        const rnd = randomBytes(4)
        prv.push(rnd, rnd)
        for (const key of keys) {
            assert(
                !(key.data.publicKey.data.algorithm instanceof SSHCertificatePublicKey),
                "Serialize the underlying private key separately from its certificate",
            )
            const algorithmPayload = key.data.algorithm.serialize()
            prv.push(serializeBuffer(encodeSSHName(key.data.alg, "SSH private key algorithm")))
            prv.push(algorithmPayload)
            prv.push(
                serializeBuffer(
                    key.data.comment === undefined
                        ? Buffer.alloc(0)
                        : encodeSSHKeyComment(key.data.comment),
                ),
            )
            algorithmPayloads.push(algorithmPayload)
        }
        let prvPayload = Buffer.concat(prv)
        if (options) {
            for (const payload of algorithmPayloads) payload.fill(0)
        }
        if (prvPayload.length % blockLength !== 0) {
            const pad_len = blockLength - (prvPayload.length % blockLength)
            const pad = Buffer.alloc(pad_len, pad_len)
            for (let i = 0; i < pad_len; i++) {
                pad[i] = i + 1
            }
            const unpadded = prvPayload
            prvPayload = Buffer.concat([unpadded, pad])
            if (options) unpadded.fill(0)
        }

        let kdfName = "none"
        let kdfOptions: Buffer = Buffer.alloc(0)
        let privatePayload: Buffer = prvPayload
        let authenticationTag: Buffer = Buffer.alloc(0)
        let serializedCipherName = "none"
        if (options) {
            let encrypted: ReturnType<typeof encryptOpenSSHPrivateKey>
            try {
                encrypted = encryptOpenSSHPrivateKey(prvPayload, options)
            } finally {
                prvPayload.fill(0)
            }
            serializedCipherName = encrypted.cipherName
            kdfName = encrypted.kdfName
            kdfOptions = encrypted.kdfOptions
            privatePayload = encrypted.ciphertext
            authenticationTag = encrypted.authenticationTag
        }

        const serialized = Buffer.concat([
            serializeCString(OPENSSH_PRIVATE_KEY_MAGIC),
            serializeBuffer(Buffer.from(serializedCipherName)),
            serializeBuffer(Buffer.from(kdfName)),
            serializeBuffer(kdfOptions),
            serializeUint32(keys.length),
            ...keys.map((key) => serializeBuffer(key.data.publicKey.serialize())),
            serializeBuffer(privatePayload),
            authenticationTag,
        ])
        assert(
            serialized.length <= MAX_OPENSSH_PRIVATE_KEY_LENGTH,
            `OpenSSH private key exceeds ${MAX_OPENSSH_PRIVATE_KEY_LENGTH} bytes`,
        )
        return serialized
    }

    static parse(raw: Buffer, passphrase?: string | Buffer): PrivateKey {
        const keys = PrivateKey.parseAll(raw, passphrase)
        assert(keys.length === 1, "Private key container contains multiple keys; use parseAll()")
        return keys[0]
    }

    static parseAll(raw: Buffer, passphrase?: string | Buffer): PrivateKey[] {
        assert(
            raw.length <= MAX_OPENSSH_PRIVATE_KEY_LENGTH,
            `OpenSSH private key exceeds ${MAX_OPENSSH_PRIVATE_KEY_LENGTH} bytes`,
        )
        let authMagic: Buffer
        ;[authMagic, raw] = readNextCString(raw)

        assert(authMagic.equals(OPENSSH_PRIVATE_KEY_MAGIC), "Invalid magic string")

        let cipherName: Buffer
        ;[cipherName, raw] = readNextBuffer(raw)

        let kdfName: Buffer
        ;[kdfName, raw] = readNextBuffer(raw)

        let kdfOptions: Buffer
        ;[kdfOptions, raw] = readNextBuffer(raw)

        const cipher = decodeSSHName(cipherName, "OpenSSH private key cipher")
        const kdf = decodeSSHName(kdfName, "OpenSSH private key KDF")
        if (cipher === "none") {
            assert(kdf === "none", "Invalid KDF for unencrypted OpenSSH private key")
            assert(kdfOptions.length === 0, "Invalid unencrypted OpenSSH private key KDF options")
        } else {
            assert(kdf !== "none", "Encrypted OpenSSH private key is missing a KDF")
        }

        let numKeys: number
        ;[numKeys, raw] = readNextUint32(raw)
        assert(numKeys > 0, "Private key container must contain at least one key")
        assert(
            numKeys <= MAX_OPENSSH_PRIVATE_KEYS,
            `Private key container exceeds the ${MAX_OPENSSH_PRIVATE_KEYS}-key limit`,
        )
        assert(numKeys <= Math.floor(raw.length / 4), "Invalid private key count")

        const publicKeys: PublicKey[] = []
        for (let index = 0; index < numKeys; index++) {
            let sshpubkey: Buffer
            ;[sshpubkey, raw] = readNextBuffer(raw)
            publicKeys.push(PublicKey.parse(sshpubkey))
        }

        let privatePayload: Buffer
        ;[privatePayload, raw] = readNextBuffer(raw)
        let blockLength = 8
        if (cipher === "none") {
            assert(raw.length === 0, "Unexpected data after OpenSSH private key")
        } else {
            const decrypted = decryptOpenSSHPrivateKey(
                cipher,
                kdf,
                kdfOptions,
                privatePayload,
                raw,
                passphrase,
            )
            privatePayload = decrypted.plaintext
            blockLength = decrypted.blockLength
            raw = Buffer.alloc(0)
        }
        assert(
            privatePayload.length % blockLength === 0,
            "Unexpected OpenSSH private key block length",
        )
        raw = privatePayload

        let rnd1: number
        ;[rnd1, raw] = readNextUint32(raw)
        let rnd2: number
        ;[rnd2, raw] = readNextUint32(raw)
        assert(rnd1 === rnd2, "OpenSSH key integrity check failed; wrong passphrase?")

        const keys: PrivateKey[] = []
        for (const publicKey of publicKeys) {
            let alg: Buffer
            ;[alg, raw] = readNextBuffer(raw)
            const algorithmName = decodeSSHName(alg, "SSH private key algorithm")
            assert(
                algorithmName === publicKey.data.alg,
                "Private key algorithm does not match public key algorithm",
            )

            const algorithm = PrivateKey.algorithms.get(algorithmName)
            assert(algorithm, `Unsupported algorithm: ${algorithmName}`)

            let prv: PrivateKeyAlgorithm
            ;[prv, raw] = algorithm.parse(raw)
            assert(publicKey.equals(prv.getPublicKey()), "Private and public key data do not match")

            let comment: Buffer
            ;[comment, raw] = readNextBuffer(raw)
            keys.push(
                new PrivateKey({
                    publicKey,
                    alg: algorithmName,
                    algorithm: prv,
                    comment:
                        comment.length > 0 ? decodeSSHUTF8(comment, "SSH key comment") : undefined,
                }),
            )
        }

        // check padding
        for (let i = 0; i < raw.length; i++) {
            assert(raw[i] === i + 1, "Invalid padding byte at index " + i)
        }

        return keys
    }

    toString(options?: OpenSSHPrivateKeyEncryptionOptions): string {
        return PrivateKey.toStringMany([this], options)
    }

    /** Export the locally held private scalar as unencrypted PKCS#8 PEM. */
    toPEM(): string {
        return privateKeyObject(this.data.algorithm).export({
            format: "pem",
            type: "pkcs8",
        }) as string
    }

    static toStringMany(
        keys: readonly PrivateKey[],
        options?: OpenSSHPrivateKeyEncryptionOptions,
    ): string {
        const lines = [OPENSSH_PRIVATE_KEY_BEGIN_MARKER]
        const b64 = PrivateKey.serializeMany(keys, options).toString("base64")
        for (let i = 0; i < b64.length; i += OPENSSH_PRIVATE_KEY_ARMOR_LINE_LENGTH) {
            lines.push(b64.slice(i, i + OPENSSH_PRIVATE_KEY_ARMOR_LINE_LENGTH))
        }
        lines.push(OPENSSH_PRIVATE_KEY_END_MARKER)

        return lines.join("\n")
    }

    static fromString(data: string, passphrase?: string | Buffer): PrivateKey {
        const keys = PrivateKey.fromStringAll(data, passphrase)
        assert(
            keys.length === 1,
            "Private key container contains multiple keys; use fromStringAll()",
        )
        return keys[0]
    }

    static fromStringAll(data: string, passphrase?: string | Buffer): PrivateKey[] {
        if (isPuTTYPrivateKey(data)) {
            return [PrivateKey.fromPuTTY(data, passphrase)]
        }
        if (!data.trimStart().startsWith(OPENSSH_PRIVATE_KEY_BEGIN_MARKER)) {
            return [PrivateKey.fromPEM(data, passphrase)]
        }
        return PrivateKey.parseAll(decodeOpenSSHPrivateKeyArmor(data), passphrase)
    }

    static fromPuTTY(data: string | Buffer, passphrase?: string | Buffer): PrivateKey {
        const parsed = parsePuTTYPrivateKey(data, passphrase)
        try {
            return privateKeyFromPuTTY(parsed)
        } finally {
            parsed.privateKey.fill(0)
        }
    }

    static fromPEM(data: string, passphrase?: string | Buffer): PrivateKey {
        const key = createPrivateKey({ key: data, format: "pem", passphrase })
        return privateKeyFromKeyObject(key)
    }

    static generate(alg: string): Promise<PrivateKey> {
        const algo = PrivateKey.algorithms.get(alg)
        assert(algo, `Unsupported algorithm: ${alg}`)

        return algo.generate()
    }

    static generateSync(alg: string): PrivateKey {
        const algo = PrivateKey.algorithms.get(alg)
        assert(algo, `Unsupported algorithm: ${alg}`)

        return algo.generateSync()
    }
}

function jwkInteger(value: Buffer): string {
    let first = 0
    while (first < value.length - 1 && value[first] === 0) first++
    return value.subarray(first).toString("base64url")
}

function privateKeyObject(algorithm: PrivateKeyAlgorithm): KeyObject {
    if (
        algorithm instanceof SSHED25519SecurityKeyPrivateKey ||
        algorithm instanceof SSHECDSASecurityKeyPrivateKey
    ) {
        throw new Error("Hardware-backed SSH private keys cannot be exported as PEM")
    }
    if (algorithm instanceof SSHED25519PrivateKey) {
        return createPrivateKey({
            key: {
                kty: "OKP",
                crv: "Ed25519",
                x: algorithm.data.publicKey.toString("base64url"),
                d: algorithm.data.privateKey.subarray(0, 32).toString("base64url"),
            },
            format: "jwk",
        })
    }
    if (algorithm instanceof SSHED448PrivateKey) {
        return createPrivateKey({
            key: {
                kty: "OKP",
                crv: "Ed448",
                x: algorithm.data.publicKey.toString("base64url"),
                d: algorithm.data.privateKey.subarray(0, 57).toString("base64url"),
            },
            format: "jwk",
        })
    }
    if (algorithm instanceof SSHRSAPrivateKey) {
        const d = decodeBigIntBE(algorithm.data.privateExponent)
        const p = decodeBigIntBE(algorithm.data.p)
        const q = decodeBigIntBE(algorithm.data.q)
        return createPrivateKey({
            key: {
                kty: "RSA",
                n: jwkInteger(algorithm.data.modulus),
                e: jwkInteger(algorithm.data.publicExponent),
                d: jwkInteger(algorithm.data.privateExponent),
                p: jwkInteger(algorithm.data.p),
                q: jwkInteger(algorithm.data.q),
                dp: jwkInteger(encodeBigIntBE(d % (p - 1n))),
                dq: jwkInteger(encodeBigIntBE(d % (q - 1n))),
                qi: jwkInteger(algorithm.data.iqmp),
            },
            format: "jwk",
        })
    }
    if (algorithm instanceof SSHECDSAPrivateKey) {
        const publicKey = algorithm.getPublicKey().data.algorithm
        assert(publicKey instanceof SSHECDSAPublicKey)
        return createPrivateKey({
            key: {
                ...publicKey.toJWK(),
                d: fixedWidthInteger(
                    algorithm.data.privateKey,
                    algorithm.curve.coordinateLength,
                ).toString("base64url"),
            },
            format: "jwk",
        })
    }
    if (algorithm instanceof SSHDSSPrivateKey) return dsaPrivateKey(algorithm.data)
    throw new Error("SSH private key cannot be exported as PEM")
}

function readPuTTYPrivateMpint(raw: Buffer): [Buffer, Buffer] {
    let value: Buffer
    ;[value, raw] = readNextBuffer(raw)
    parseBufferToMpintBuffer(value)
    assert(value.length > 0, "PuTTY private key integer must be positive")
    return [value, raw]
}

function privateKeyFromPuTTY(parsed: ParsedPuTTYPrivateKey): PrivateKey {
    const publicKey = PublicKey.parse(parsed.publicKey)
    assert(
        publicKey.data.alg === parsed.algorithmName,
        "PuTTY key algorithm does not match its public key",
    )
    assert(
        !(publicKey.data.algorithm instanceof SSHCertificatePublicKey),
        "PuTTY certificate private keys are not supported",
    )

    const publicAlgorithm = publicKey.data.algorithm
    let raw = parsed.privateKey
    let algorithm: PrivateKeyAlgorithm
    if (publicAlgorithm instanceof SSHRSAPublicKey) {
        let privateExponent: Buffer
        let p: Buffer
        let q: Buffer
        let iqmp: Buffer
        ;[privateExponent, raw] = readPuTTYPrivateMpint(raw)
        ;[p, raw] = readPuTTYPrivateMpint(raw)
        ;[q, raw] = readPuTTYPrivateMpint(raw)
        ;[iqmp, raw] = readPuTTYPrivateMpint(raw)
        algorithm = new SSHRSAPrivateKey({
            ...publicAlgorithm.data,
            privateExponent,
            p,
            q,
            iqmp,
        })
    } else if (publicAlgorithm instanceof SSHDSSPublicKey) {
        let x: Buffer
        ;[x, raw] = readPuTTYPrivateMpint(raw)
        algorithm = new SSHDSSPrivateKey({ ...publicAlgorithm.data, x })
    } else if (publicAlgorithm instanceof SSHECDSAPublicKey) {
        let scalar: Buffer
        ;[scalar, raw] = readPuTTYPrivateMpint(raw)
        const RegisteredAlgorithm = PrivateKey.algorithms.get(parsed.algorithmName)
        assert(RegisteredAlgorithm, `Unsupported algorithm: ${parsed.algorithmName}`)
        const Algorithm = RegisteredAlgorithm as unknown as new (
            data: SSHECDSAPrivateKeyData,
        ) => PrivateKeyAlgorithm
        algorithm = new Algorithm({
            publicKey: publicAlgorithm.data.publicKey,
            privateKey: unsignedInteger(scalar),
        })
    } else if (
        publicAlgorithm instanceof SSHED25519PublicKey ||
        publicAlgorithm instanceof SSHED448PublicKey
    ) {
        const width = publicAlgorithm instanceof SSHED25519PublicKey ? 32 : 57
        let seed: Buffer
        ;[seed, raw] = readNextBuffer(raw)
        assert(seed.length === width, `Invalid PuTTY EdDSA private key length`)
        const privateKey = Buffer.concat([seed, publicAlgorithm.data.publicKey])
        try {
            algorithm =
                publicAlgorithm instanceof SSHED25519PublicKey
                    ? new SSHED25519PrivateKey({
                          publicKey: publicAlgorithm.data.publicKey,
                          privateKey,
                      })
                    : new SSHED448PrivateKey({
                          publicKey: publicAlgorithm.data.publicKey,
                          privateKey,
                      })
        } finally {
            seed.fill(0)
            privateKey.fill(0)
        }
    } else {
        throw new Error(`Unsupported PuTTY private key algorithm: ${parsed.algorithmName}`)
    }

    if (parsed.encryption === "none") {
        assert(raw.length === 0, "Unexpected data after PuTTY private key fields")
    } else {
        assert(raw.length < 16, "Invalid PuTTY private key encryption padding")
    }
    return new PrivateKey({
        alg: parsed.algorithmName,
        publicKey,
        algorithm,
        comment: parsed.comment.length > 0 ? parsed.comment : undefined,
    })
}

function jwkBuffer(jwk: JsonWebKey, name: keyof JsonWebKey): Buffer {
    const value = jwk[name]
    assert(typeof value === "string" && value.length > 0, `Private JWK is missing ${String(name)}`)
    return Buffer.from(value, "base64url")
}

function positiveMpint(value: Buffer): Buffer {
    assert(value.length > 0, "Private key integer must be positive")
    return (value[0] & 0x80) !== 0 ? Buffer.concat([Buffer.from([0]), value]) : value
}

function privateKeyFromKeyObject(key: KeyObject): PrivateKey {
    if (key.asymmetricKeyType === "dsa") {
        const algorithm = new SSHDSSPrivateKey(dsaParametersFromPrivateKey(key))
        return new PrivateKey({
            alg: SSHDSSPrivateKey.alg_name,
            publicKey: algorithm.getPublicKey(),
            algorithm,
        })
    }
    const jwk = key.export({ format: "jwk" })
    if (jwk.kty === "OKP" && jwk.crv === "Ed25519") {
        const publicKey = jwkBuffer(jwk, "x")
        const seed = jwkBuffer(jwk, "d")
        assert(publicKey.length === 32 && seed.length === 32, "Invalid Ed25519 JWK")
        const algorithm = new SSHED25519PrivateKey({
            publicKey,
            privateKey: Buffer.concat([seed, publicKey]),
        })
        seed.fill(0)
        return new PrivateKey({
            alg: SSHED25519PrivateKey.alg_name,
            publicKey: algorithm.getPublicKey(),
            algorithm,
        })
    }
    if (jwk.kty === "OKP" && jwk.crv === "Ed448") {
        const publicKey = jwkBuffer(jwk, "x")
        const seed = jwkBuffer(jwk, "d")
        assert(publicKey.length === 57 && seed.length === 57, "Invalid Ed448 JWK")
        const algorithm = new SSHED448PrivateKey({
            publicKey,
            privateKey: Buffer.concat([seed, publicKey]),
        })
        seed.fill(0)
        return new PrivateKey({
            alg: SSHED448PrivateKey.alg_name,
            publicKey: algorithm.getPublicKey(),
            algorithm,
        })
    }
    if (jwk.kty === "RSA") {
        const algorithm = new SSHRSAPrivateKey({
            modulus: positiveMpint(jwkBuffer(jwk, "n")),
            publicExponent: positiveMpint(jwkBuffer(jwk, "e")),
            privateExponent: positiveMpint(jwkBuffer(jwk, "d")),
            p: positiveMpint(jwkBuffer(jwk, "p")),
            q: positiveMpint(jwkBuffer(jwk, "q")),
            iqmp: positiveMpint(jwkBuffer(jwk, "qi")),
        })
        return new PrivateKey({
            alg: SSHRSAPrivateKey.alg_name,
            publicKey: algorithm.getPublicKey(),
            algorithm,
        })
    }
    if (jwk.kty === "EC") {
        const curve = ECDSA_CURVES.find(({ jwkName }) => jwkName === jwk.crv)
        assert(curve, `Unsupported PEM ECDSA curve: ${jwk.crv}`)
        const x = jwkBuffer(jwk, "x")
        const y = jwkBuffer(jwk, "y")
        assert(
            x.length === curve.coordinateLength && y.length === curve.coordinateLength,
            `Invalid ${curve.identifier} JWK point`,
        )
        const RegisteredAlgorithm = PrivateKey.algorithms.get(curve.algorithm)
        assert(RegisteredAlgorithm, `Unsupported algorithm: ${curve.algorithm}`)
        const Algorithm = RegisteredAlgorithm as unknown as new (
            data: SSHECDSAPrivateKeyData,
        ) => PrivateKeyAlgorithm
        const algorithm = new Algorithm({
            publicKey: Buffer.concat([Buffer.from([4]), x, y]),
            privateKey: jwkBuffer(jwk, "d"),
        })
        return new PrivateKey({
            alg: curve.algorithm,
            publicKey: algorithm.getPublicKey(),
            algorithm,
        })
    }
    throw new Error(`Unsupported PEM private key type: ${jwk.kty ?? key.asymmetricKeyType}`)
}

export abstract class PrivateKeyAlgorithm {
    static alg_name: string

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    constructor(data: unknown) {
        throw new Error("Not implemented")
    }

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    sign(data: Buffer, algorithm?: string): EncodedSignature {
        throw new Error("Not implemented")
    }

    getPublicKey(): PublicKey {
        throw new Error("Not implemented")
    }

    serialize(): Buffer {
        throw new Error("Not implemented")
    }

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    static parse(raw: Buffer): [PrivateKeyAlgorithm, Buffer] {
        throw new Error("Not implemented")
    }

    static generate(): Promise<PrivateKey> {
        throw new Error("Not implemented")
    }

    static generateSync(): PrivateKey {
        throw new Error("Not implemented")
    }
}

/**
 * Serialize the key material that follows a certificate key type in an agent add request.
 * Standard certificate names carry only the private fields after the certificate; deployed
 * aliases carry the complete corresponding private-key fields.
 */
export function serializeCertificatePrivateKey(privateKey: PrivateKey): Buffer {
    const certificateAlgorithm = privateKey.data.publicKey.data.algorithm
    assert(
        certificateAlgorithm instanceof SSHCertificatePublicKey,
        "Certificate private-key serialization requires a certificate",
    )
    const publicFields = certificateAlgorithm.publicKey.data.algorithm.serialize()
    const plainPrivateKey = privateKey.data.algorithm.serialize()
    try {
        assert(
            plainPrivateKey.subarray(0, publicFields.length).equals(publicFields),
            "Certificate private key does not match its public fields",
        )
        return Buffer.concat([
            serializeBuffer(privateKey.data.publicKey.serialize()),
            privateKey.data.alg.endsWith("-cert")
                ? plainPrivateKey.subarray(publicFields.length)
                : plainPrivateKey,
        ])
    } finally {
        publicFields.fill(0)
        plainPrivateKey.fill(0)
    }
}

/**
 * Parse either standard or deployed certificate private-key fields while leaving following agent
 * request fields untouched.
 */
export function parseCertificatePrivateKey(
    algorithmName: string,
    raw: Buffer,
): [PrivateKey, Buffer] {
    let certificateBlob: Buffer
    ;[certificateBlob, raw] = readNextBuffer(raw)
    const certificate = PublicKey.parse(certificateBlob)
    assert(certificate.data.alg === algorithmName, "Certificate private key type mismatch")
    assert(
        certificate.data.algorithm instanceof SSHCertificatePublicKey,
        "Certificate private key does not contain a certificate",
    )
    const publicKey = certificate.data.algorithm.publicKey
    const Algorithm = PrivateKey.algorithms.get(publicKey.data.alg)
    assert(Algorithm, `Unsupported certificate private key type: ${publicKey.data.alg}`)
    const standard = algorithmName.endsWith("-cert")
    const publicFields = publicKey.data.algorithm.serialize()
    const combined = standard ? Buffer.concat([publicFields, raw]) : Buffer.from(raw)
    try {
        const [algorithm, remainingCombined] = Algorithm.parse(combined)
        const privateBytesConsumed = raw.length - remainingCombined.length
        assert(privateBytesConsumed >= 0, "Invalid certificate private key fields")
        assert(
            algorithm.getPublicKey().equals(publicKey),
            "Certificate private key does not match its certificate",
        )
        return [
            new PrivateKey({
                alg: algorithmName,
                publicKey: certificate,
                algorithm,
            }),
            raw.subarray(privateBytesConsumed),
        ]
    } finally {
        publicFields.fill(0)
        combined.fill(0)
    }
}

export interface SSHED25519PrivateKeyData {
    publicKey: Buffer
    privateKey: Buffer
}
export class SSHED25519PrivateKey implements PrivateKeyAlgorithm {
    static alg_name = "ssh-ed25519"

    readonly data: SSHED25519PrivateKeyData
    constructor(data: SSHED25519PrivateKeyData) {
        assert(data.publicKey.length === 32, "Invalid Ed25519 public key length")
        assert(data.privateKey.length === 64, "Invalid Ed25519 private key length")
        const derived = Buffer.from(
            nacl.sign.keyPair.fromSeed(data.privateKey.subarray(0, 32)).publicKey,
        )
        assert(
            derived.equals(data.publicKey) && data.privateKey.subarray(32).equals(data.publicKey),
            "Ed25519 private and public key data do not match",
        )
        this.data = {
            publicKey: Buffer.from(data.publicKey),
            privateKey: Buffer.from(data.privateKey),
        }
    }

    sign(data: Buffer, algorithm = SSHED25519PrivateKey.alg_name): EncodedSignature {
        assert(
            algorithm === SSHED25519PrivateKey.alg_name,
            `Unsupported Ed25519 signature algorithm: ${algorithm}`,
        )
        return new EncodedSignature({
            alg: algorithm,
            data: Buffer.from(nacl.sign.detached(data, this.data.privateKey)),
        })
    }

    getPublicKey(): PublicKey {
        return new PublicKey({
            alg: SSHED25519PrivateKey.alg_name,
            algorithm: new SSHED25519PublicKey({ publicKey: this.data.publicKey }),
        })
    }

    serialize(): Buffer {
        return Buffer.concat([
            serializeBuffer(this.data.publicKey),
            serializeBuffer(this.data.privateKey),
        ])
    }

    static parse(raw: Buffer): [PrivateKeyAlgorithm, Buffer] {
        let publicKey: Buffer
        ;[publicKey, raw] = readNextBuffer(raw)

        let privateKey: Buffer
        ;[privateKey, raw] = readNextBuffer(raw)

        return [new SSHED25519PrivateKey({ publicKey, privateKey }), raw]
    }

    static generateSync(): PrivateKey {
        const keyPair = nacl.sign.keyPair()

        const publicKey = Buffer.from(keyPair.publicKey)
        const privateKey = Buffer.from(keyPair.secretKey)

        return new PrivateKey({
            alg: SSHED25519PrivateKey.alg_name,
            publicKey: new PublicKey({
                alg: SSHED25519PrivateKey.alg_name,
                algorithm: new SSHED25519PublicKey({
                    publicKey: publicKey,
                }),
            }),
            algorithm: new SSHED25519PrivateKey({
                privateKey: privateKey,
                publicKey: publicKey,
            }),
        })
    }

    static async generate(): Promise<PrivateKey> {
        return SSHED25519PrivateKey.generateSync()
    }
}
PrivateKey.algorithms.set(SSHED25519PrivateKey.alg_name, SSHED25519PrivateKey)

export interface SSHED25519SecurityKeyPrivateKeyData {
    publicKey: Buffer
    application: string
    flags: number
    keyHandle: Buffer
    reserved: Buffer
}

export class SSHED25519SecurityKeyPrivateKey implements PrivateKeyAlgorithm {
    static alg_name = SSHED25519SecurityKeyPublicKey.alg_name

    readonly data: SSHED25519SecurityKeyPrivateKeyData

    constructor(data: SSHED25519SecurityKeyPrivateKeyData) {
        new SSHED25519SecurityKeyPublicKey({
            publicKey: data.publicKey,
            application: data.application,
        })
        serializeUint8(data.flags)
        assert(Buffer.isBuffer(data.keyHandle), "Security-key handle must be a buffer")
        assert(Buffer.isBuffer(data.reserved), "Security-key reserved data must be a buffer")
        this.data = {
            publicKey: Buffer.from(data.publicKey),
            application: data.application,
            flags: data.flags,
            keyHandle: Buffer.from(data.keyHandle),
            reserved: Buffer.from(data.reserved),
        }
    }

    sign(): EncodedSignature {
        throw new Error("Security-key signing requires an SSH agent security-key provider")
    }

    getPublicKey(): PublicKey {
        return new PublicKey({
            alg: SSHED25519SecurityKeyPrivateKey.alg_name,
            algorithm: new SSHED25519SecurityKeyPublicKey({
                publicKey: this.data.publicKey,
                application: this.data.application,
            }),
        })
    }

    serialize(): Buffer {
        assert(Buffer.isBuffer(this.data.keyHandle), "Security-key handle must be a buffer")
        assert(Buffer.isBuffer(this.data.reserved), "Security-key reserved data must be a buffer")
        return Buffer.concat([
            this.getPublicKey().data.algorithm.serialize(),
            serializeUint8(this.data.flags),
            serializeBuffer(Buffer.from(this.data.keyHandle)),
            serializeBuffer(Buffer.from(this.data.reserved)),
        ])
    }

    static parse(raw: Buffer): [PrivateKeyAlgorithm, Buffer] {
        let publicKey: Buffer
        let application: Buffer
        let flags: number
        let keyHandle: Buffer
        let reserved: Buffer
        ;[publicKey, raw] = readNextBuffer(raw)
        ;[application, raw] = readNextBuffer(raw)
        ;[flags, raw] = readNextUint8(raw)
        ;[keyHandle, raw] = readNextBuffer(raw)
        ;[reserved, raw] = readNextBuffer(raw)
        return [
            new SSHED25519SecurityKeyPrivateKey({
                publicKey,
                application: decodeSSHUTF8(application, "security-key application"),
                flags,
                keyHandle,
                reserved,
            }),
            raw,
        ]
    }

    static generate(): Promise<PrivateKey> {
        return Promise.reject(
            new Error("Security-key generation requires an SSH agent security-key provider"),
        )
    }

    static generateSync(): PrivateKey {
        throw new Error("Security-key generation requires an SSH agent security-key provider")
    }
}
PrivateKey.algorithms.set(SSHED25519SecurityKeyPrivateKey.alg_name, SSHED25519SecurityKeyPrivateKey)

export interface SSHECDSASecurityKeyPrivateKeyData {
    publicKey: Buffer
    application: string
    flags: number
    keyHandle: Buffer
    reserved: Buffer
}

export class SSHECDSASecurityKeyPrivateKey implements PrivateKeyAlgorithm {
    static alg_name = SSHECDSASecurityKeyPublicKey.alg_name

    readonly data: SSHECDSASecurityKeyPrivateKeyData

    constructor(data: SSHECDSASecurityKeyPrivateKeyData) {
        new SSHECDSASecurityKeyPublicKey({
            publicKey: data.publicKey,
            application: data.application,
        })
        serializeUint8(data.flags)
        assert(Buffer.isBuffer(data.keyHandle), "Security-key handle must be a buffer")
        assert(Buffer.isBuffer(data.reserved), "Security-key reserved data must be a buffer")
        this.data = {
            publicKey: Buffer.from(data.publicKey),
            application: data.application,
            flags: data.flags,
            keyHandle: Buffer.from(data.keyHandle),
            reserved: Buffer.from(data.reserved),
        }
    }

    sign(): EncodedSignature {
        throw new Error("Security-key signing requires an SSH agent security-key provider")
    }

    getPublicKey(): PublicKey {
        return new PublicKey({
            alg: SSHECDSASecurityKeyPrivateKey.alg_name,
            algorithm: new SSHECDSASecurityKeyPublicKey({
                publicKey: this.data.publicKey,
                application: this.data.application,
            }),
        })
    }

    serialize(): Buffer {
        assert(Buffer.isBuffer(this.data.keyHandle), "Security-key handle must be a buffer")
        assert(Buffer.isBuffer(this.data.reserved), "Security-key reserved data must be a buffer")
        return Buffer.concat([
            this.getPublicKey().data.algorithm.serialize(),
            serializeUint8(this.data.flags),
            serializeBuffer(Buffer.from(this.data.keyHandle)),
            serializeBuffer(Buffer.from(this.data.reserved)),
        ])
    }

    static parse(raw: Buffer): [PrivateKeyAlgorithm, Buffer] {
        let identifier: Buffer
        let publicKey: Buffer
        let application: Buffer
        let flags: number
        let keyHandle: Buffer
        let reserved: Buffer
        ;[identifier, raw] = readNextBuffer(raw)
        ;[publicKey, raw] = readNextBuffer(raw)
        ;[application, raw] = readNextBuffer(raw)
        ;[flags, raw] = readNextUint8(raw)
        ;[keyHandle, raw] = readNextBuffer(raw)
        ;[reserved, raw] = readNextBuffer(raw)
        assert(
            identifier.equals(Buffer.from(ECDSA_CURVES[0].identifier, "ascii")),
            "Invalid ECDSA security-key curve",
        )
        return [
            new SSHECDSASecurityKeyPrivateKey({
                publicKey,
                application: decodeSSHUTF8(application, "security-key application"),
                flags,
                keyHandle,
                reserved,
            }),
            raw,
        ]
    }

    static generate(): Promise<PrivateKey> {
        return Promise.reject(
            new Error("Security-key generation requires an SSH agent security-key provider"),
        )
    }

    static generateSync(): PrivateKey {
        throw new Error("Security-key generation requires an SSH agent security-key provider")
    }
}
PrivateKey.algorithms.set(SSHECDSASecurityKeyPrivateKey.alg_name, SSHECDSASecurityKeyPrivateKey)

export interface SSHED448PrivateKeyData {
    publicKey: Buffer
    /** RFC 8032 private seed followed by the public key. */
    privateKey: Buffer
}

export class SSHED448PrivateKey implements PrivateKeyAlgorithm {
    static alg_name = "ssh-ed448"

    readonly data: SSHED448PrivateKeyData
    constructor(data: SSHED448PrivateKeyData) {
        assert(data.publicKey.length === 57, "Invalid Ed448 public key length")
        assert(data.privateKey.length === 114, "Invalid Ed448 private key length")
        const derived = Buffer.from(ed448.getPublicKey(data.privateKey.subarray(0, 57)))
        assert(
            derived.equals(data.publicKey) && data.privateKey.subarray(57).equals(data.publicKey),
            "Ed448 private and public key data do not match",
        )
        this.data = {
            publicKey: Buffer.from(data.publicKey),
            privateKey: Buffer.from(data.privateKey),
        }
    }

    sign(data: Buffer, algorithm = SSHED448PrivateKey.alg_name): EncodedSignature {
        assert(
            algorithm === SSHED448PrivateKey.alg_name,
            `Unsupported Ed448 signature algorithm: ${algorithm}`,
        )
        return new EncodedSignature({
            alg: algorithm,
            data: Buffer.from(ed448.sign(data, this.data.privateKey.subarray(0, 57))),
        })
    }

    getPublicKey(): PublicKey {
        return new PublicKey({
            alg: SSHED448PrivateKey.alg_name,
            algorithm: new SSHED448PublicKey({ publicKey: this.data.publicKey }),
        })
    }

    serialize(): Buffer {
        return Buffer.concat([
            serializeBuffer(this.data.publicKey),
            serializeBuffer(this.data.privateKey),
        ])
    }

    static parse(raw: Buffer): [PrivateKeyAlgorithm, Buffer] {
        let publicKey: Buffer
        let privateKey: Buffer
        ;[publicKey, raw] = readNextBuffer(raw)
        ;[privateKey, raw] = readNextBuffer(raw)
        return [new SSHED448PrivateKey({ publicKey, privateKey }), raw]
    }

    static generateSync(): PrivateKey {
        const key = ed448.keygen()
        const publicKey = Buffer.from(key.publicKey)
        const algorithm = new SSHED448PrivateKey({
            publicKey,
            privateKey: Buffer.concat([Buffer.from(key.secretKey), publicKey]),
        })
        key.secretKey.fill(0)
        return new PrivateKey({
            alg: SSHED448PrivateKey.alg_name,
            publicKey: algorithm.getPublicKey(),
            algorithm,
        })
    }

    static async generate(): Promise<PrivateKey> {
        return SSHED448PrivateKey.generateSync()
    }
}
PrivateKey.algorithms.set(SSHED448PrivateKey.alg_name, SSHED448PrivateKey)

export type SSHDSSPrivateKeyData = DSAPrivateParameters

export class SSHDSSPrivateKey implements PrivateKeyAlgorithm {
    static alg_name = "ssh-dss"

    readonly data: SSHDSSPrivateKeyData
    constructor(data: SSHDSSPrivateKeyData) {
        this.data = {
            p: Buffer.from(data.p),
            q: Buffer.from(data.q),
            g: Buffer.from(data.g),
            y: Buffer.from(data.y),
            x: Buffer.from(data.x),
        }
        validateDSAPrivateParameters(this.data)
    }

    sign(data: Buffer, algorithm = SSHDSSPrivateKey.alg_name): EncodedSignature {
        assert(
            algorithm === SSHDSSPrivateKey.alg_name,
            `Unsupported DSA signature algorithm: ${algorithm}`,
        )
        const signature = signDSA(data, this.data)
        assert(signature.length === 40, "Invalid DSA signature length")
        return new EncodedSignature({ alg: algorithm, data: signature })
    }

    getPublicKey(): PublicKey {
        return new PublicKey({
            alg: SSHDSSPrivateKey.alg_name,
            algorithm: new SSHDSSPublicKey(this.data),
        })
    }

    serialize(): Buffer {
        return Buffer.concat([
            serializeBuffer(this.data.p),
            serializeBuffer(this.data.q),
            serializeBuffer(this.data.g),
            serializeBuffer(this.data.y),
            serializeBuffer(this.data.x),
        ])
    }

    static parse(raw: Buffer): [PrivateKeyAlgorithm, Buffer] {
        let p: Buffer
        let q: Buffer
        let g: Buffer
        let y: Buffer
        let x: Buffer
        ;[p, raw] = readNextBuffer(raw)
        ;[q, raw] = readNextBuffer(raw)
        ;[g, raw] = readNextBuffer(raw)
        ;[y, raw] = readNextBuffer(raw)
        ;[x, raw] = readNextBuffer(raw)
        return [new SSHDSSPrivateKey({ p, q, g, y, x }), raw]
    }

    static async generate(): Promise<PrivateKey> {
        const key = await new Promise<KeyObject>((resolve, reject) => {
            generateNodeKeyPair(
                "dsa",
                { modulusLength: 1024, divisorLength: 160 },
                (error, _publicKey, privateKey) => (error ? reject(error) : resolve(privateKey)),
            )
        })
        return privateKeyFromKeyObject(key)
    }

    static generateSync(): PrivateKey {
        const { privateKey } = generateNodeKeyPairSync("dsa", {
            modulusLength: 1024,
            divisorLength: 160,
        })
        return privateKeyFromKeyObject(privateKey)
    }
}
PrivateKey.algorithms.set(SSHDSSPrivateKey.alg_name, SSHDSSPrivateKey)

// BTW ssh-rsa is a disabled host key algorithm?
export interface SSHRSAPrivateKeyData {
    modulus: Buffer
    publicExponent: Buffer
    privateExponent: Buffer
    iqmp: Buffer
    p: Buffer
    q: Buffer
}
export class SSHRSAPrivateKey implements PrivateKeyAlgorithm {
    static alg_name = "ssh-rsa"

    readonly data: SSHRSAPrivateKeyData
    constructor(data: SSHRSAPrivateKeyData) {
        for (const value of Object.values(data)) parseBufferToMpintBuffer(value)
        const modulus = decodeBigIntBE(data.modulus)
        const publicExponent = decodeBigIntBE(data.publicExponent)
        const privateExponent = decodeBigIntBE(data.privateExponent)
        const p = decodeBigIntBE(data.p)
        const q = decodeBigIntBE(data.q)
        const iqmp = decodeBigIntBE(data.iqmp)
        new SSHRSAPublicKey({ modulus: data.modulus, publicExponent: data.publicExponent })
        assert(
            p > 2n && q > 2n && p !== q && (p & 1n) === 1n && (q & 1n) === 1n,
            "Invalid RSA primes",
        )
        assert(
            checkPrimeSync(unsignedInteger(data.p), { checks: 64 }) &&
                checkPrimeSync(unsignedInteger(data.q), { checks: 64 }),
            "Invalid RSA primes",
        )
        assert(p * q === modulus, "RSA modulus does not match its prime factors")
        assert((iqmp * q) % p === 1n, "Invalid RSA inverse coefficient")
        const lambda = ((p - 1n) / greatestCommonDivisor(p - 1n, q - 1n)) * (q - 1n)
        assert((privateExponent * publicExponent) % lambda === 1n, "Invalid RSA private exponent")
        this.data = {
            modulus: Buffer.from(data.modulus),
            publicExponent: Buffer.from(data.publicExponent),
            privateExponent: Buffer.from(data.privateExponent),
            iqmp: Buffer.from(data.iqmp),
            p: Buffer.from(data.p),
            q: Buffer.from(data.q),
        }
    }

    sign(data: Buffer, algorithm = SSHRSAPrivateKey.alg_name): EncodedSignature {
        const hash =
            algorithm === "rsa-sha2-512"
                ? "sha512"
                : algorithm === "rsa-sha2-256"
                  ? "sha256"
                  : algorithm === SSHRSAPrivateKey.alg_name
                    ? "sha1"
                    : undefined
        assert(hash, `Unsupported RSA signature algorithm: ${algorithm}`)
        const d = decodeBigIntBE(this.data.privateExponent)
        const p = decodeBigIntBE(this.data.p)
        const q = decodeBigIntBE(this.data.q)
        const base64URL = (value: Buffer): string =>
            value.subarray(value.findIndex((byte) => byte !== 0)).toString("base64url")
        const key = createPrivateKey({
            key: {
                kty: "RSA",
                n: base64URL(this.data.modulus),
                e: base64URL(this.data.publicExponent),
                d: base64URL(this.data.privateExponent),
                p: base64URL(this.data.p),
                q: base64URL(this.data.q),
                dp: base64URL(encodeBigIntBE(d % (p - 1n))),
                dq: base64URL(encodeBigIntBE(d % (q - 1n))),
                qi: base64URL(this.data.iqmp),
            },
            format: "jwk",
        })

        const signer = createSign(hash)
        signer.update(data)

        return new EncodedSignature({
            alg: algorithm,
            data: signer.sign(key),
        })
    }

    getPublicKey(): PublicKey {
        return new PublicKey({
            alg: SSHRSAPrivateKey.alg_name,
            algorithm: new SSHRSAPublicKey({
                modulus: this.data.modulus,
                publicExponent: this.data.publicExponent,
            }),
        })
    }

    serialize(): Buffer {
        return Buffer.concat([
            serializeBuffer(this.data.modulus),
            serializeBuffer(this.data.publicExponent),
            serializeBuffer(this.data.privateExponent),
            serializeBuffer(this.data.iqmp),
            serializeBuffer(this.data.p),
            serializeBuffer(this.data.q),
        ])
    }

    static parse(raw: Buffer): [PrivateKeyAlgorithm, Buffer] {
        let N: Buffer
        ;[N, raw] = readNextBuffer(raw)

        let e: Buffer
        ;[e, raw] = readNextBuffer(raw)

        let d: Buffer
        ;[d, raw] = readNextBuffer(raw)

        let iqmp: Buffer
        ;[iqmp, raw] = readNextBuffer(raw)

        let p: Buffer
        ;[p, raw] = readNextBuffer(raw)

        let q: Buffer
        ;[q, raw] = readNextBuffer(raw)

        return [
            new SSHRSAPrivateKey({
                modulus: N,
                publicExponent: e,
                privateExponent: d,
                iqmp: iqmp,
                p: p,
                q: q,
            }),
            raw,
        ]
    }

    // https://www.rfc-editor.org/rfc/rfc3447#appendix-A.1.2
    static asn1Schema = new asn1js.Sequence({
        value: [
            new asn1js.Integer({
                name: "version",
                value: 0,
            }),
            new asn1js.Integer({
                name: "modulus",
            }),
            new asn1js.Integer({
                name: "publicExponent",
            }),
            new asn1js.Integer({
                name: "privateExponent",
            }),
            new asn1js.Integer({
                name: "prime1",
            }),
            new asn1js.Integer({
                name: "prime2",
            }),
            new asn1js.Integer({
                name: "exponent1",
            }),
            new asn1js.Integer({
                name: "exponent2",
            }),
            new asn1js.Integer({
                name: "coefficient",
            }),
        ],
    })
    static fromPEM(pem: string): PrivateKey {
        const lines = pem
            .trim()
            .split(/[\n\r]+/)
            .map((line) => line.trim())

        assert(lines[0] === "-----BEGIN RSA PRIVATE KEY-----")
        assert(lines[lines.length - 1] === "-----END RSA PRIVATE KEY-----")

        const base64 = lines.slice(1, -1).join("")
        const raw = Buffer.from(base64, "base64")

        const variant = asn1js.verifySchema(raw, SSHRSAPrivateKey.asn1Schema)
        assert(variant.verified, "Couldn't read PEM. Is it pkcs#1 ?")

        const result = variant.result
        const values = (result as asn1js.Sequence).valueBlock.value
        const [
            version,
            modulus,
            publicExponent,
            privateExponent,
            prime1,
            prime2,
            ,
            ,
            // we don't care about exponent1 and exponent2
            coefficient,
        ] = values.map((value) => {
            return Buffer.from((value as asn1js.Integer).valueBlock.valueHexView)
        })

        assert(version.equals(Buffer.from([0x00])), "Invalid rsa private key version")

        return new PrivateKey({
            alg: SSHRSAPrivateKey.alg_name,
            publicKey: new PublicKey({
                alg: SSHRSAPrivateKey.alg_name,
                algorithm: new SSHRSAPublicKey({
                    modulus: modulus,
                    publicExponent: publicExponent,
                }),
            }),
            algorithm: new SSHRSAPrivateKey({
                modulus: modulus,
                publicExponent: publicExponent,
                privateExponent: privateExponent,
                p: prime1,
                q: prime2,
                iqmp: coefficient,
            }),
        })
    }

    toPEM(): string {
        const d = decodeBigIntBE(this.data.privateExponent)
        const p = decodeBigIntBE(this.data.p)
        const q = decodeBigIntBE(this.data.q)
        // exponent1 is d mod (p - 1).
        const exponent1 = encodeBigIntBE(d % (p - 1n))
        // exponent2 is d mod (q - 1).
        const exponent2 = encodeBigIntBE(d % (q - 1n))

        const sequence = new asn1js.Sequence({
            value: [
                new asn1js.Integer({
                    name: "version",
                    value: 0,
                }),
                new asn1js.Integer({
                    name: "modulus",
                    isHexOnly: true,
                    valueHex: this.data.modulus,
                }),
                new asn1js.Integer({
                    name: "publicExponent",
                    isHexOnly: true,
                    valueHex: this.data.publicExponent,
                }),
                new asn1js.Integer({
                    name: "privateExponent",
                    isHexOnly: true,
                    valueHex: this.data.privateExponent,
                }),
                new asn1js.Integer({
                    name: "prime1",
                    isHexOnly: true,
                    valueHex: this.data.p,
                }),
                new asn1js.Integer({
                    name: "prime2",
                    isHexOnly: true,
                    valueHex: this.data.q,
                }),
                new asn1js.Integer({
                    name: "exponent1",
                    isHexOnly: true,
                    valueHex: exponent1,
                }),
                new asn1js.Integer({
                    name: "exponent2",
                    isHexOnly: true,
                    valueHex: exponent2,
                }),
                new asn1js.Integer({
                    name: "coefficient",
                    isHexOnly: true,
                    valueHex: this.data.iqmp,
                }),
            ],
        })
        const buffer = Buffer.from(sequence.toBER(false)).toString("base64")
        let key = ""
        for (let i = 0; i < buffer.length; i += 64) {
            key += buffer.slice(i, i + 64) + "\n"
        }
        return `-----BEGIN RSA PRIVATE KEY-----\n${key}-----END RSA PRIVATE KEY-----`
    }

    // 3072 is still good today.
    // in case you need more security, you can increase that value
    static async generate(bitsize = 3072): Promise<PrivateKey> {
        const privateKey = await new Promise<KeyObject>((res, rej) => {
            generateNodeKeyPair(
                "rsa",
                {
                    modulusLength: bitsize,
                },
                (err, publicKey, privateKey) => {
                    if (err) return rej(err)
                    res(privateKey)
                },
            )
        })

        return SSHRSAPrivateKey.fromPEM(
            privateKey.export({
                format: "pem",
                type: "pkcs1",
            }) as string,
        )
    }

    static generateSync(bitsize = 3072): PrivateKey {
        const { privateKey } = generateNodeKeyPairSync("rsa", { modulusLength: bitsize })
        return SSHRSAPrivateKey.fromPEM(
            privateKey.export({ format: "pem", type: "pkcs1" }) as string,
        )
    }
}
PrivateKey.algorithms.set(SSHRSAPrivateKey.alg_name, SSHRSAPrivateKey)

function greatestCommonDivisor(a: bigint, b: bigint): bigint {
    while (b !== 0n) [a, b] = [b, a % b]
    return a
}

export interface SSHECDSAPrivateKeyData {
    publicKey: Buffer
    privateKey: Buffer
}

export class SSHECDSAPrivateKey implements PrivateKeyAlgorithm {
    static alg_name: string
    static curve: ECDSACurve

    readonly curve: ECDSACurve
    readonly data: SSHECDSAPrivateKeyData

    constructor(curve: ECDSACurve, data: SSHECDSAPrivateKeyData) {
        this.curve = curve
        const ecdh = createECDH(curve.nodeName)
        try {
            ecdh.setPrivateKey(unsignedInteger(data.privateKey))
        } catch (error) {
            throw new Error(`Invalid ${curve.identifier} private key`, { cause: error })
        }
        const derivedPublicKey = ecdh.getPublicKey(undefined, "uncompressed")
        const suppliedPublicKey = new SSHECDSAPublicKey(curve, {
            publicKey: data.publicKey,
        })
        const derived = new SSHECDSAPublicKey(curve, { publicKey: derivedPublicKey })
        assert(suppliedPublicKey.equals(derived), "ECDSA private and public keys do not match")
        this.data = {
            publicKey: Buffer.from(data.publicKey),
            privateKey: Buffer.from(data.privateKey),
        }
    }

    sign(data: Buffer, algorithm = this.curve.algorithm): EncodedSignature {
        assert(algorithm === this.curve.algorithm, `Unsupported ECDSA signature: ${algorithm}`)
        const signer =
            this.curve.identifier === "nistp256"
                ? p256
                : this.curve.identifier === "nistp384"
                  ? p384
                  : p521
        const p1363 = Buffer.from(
            signer.sign(
                data,
                fixedWidthInteger(this.data.privateKey, this.curve.coordinateLength),
                { extraEntropy: false, format: "compact", lowS: false },
            ),
        )
        const width = this.curve.coordinateLength
        return new EncodedSignature({
            alg: algorithm,
            data: Buffer.concat([
                serializeBuffer(serializeMpintBufferToBuffer(p1363.subarray(0, width))),
                serializeBuffer(serializeMpintBufferToBuffer(p1363.subarray(width))),
            ]),
        })
    }

    getPublicKey(): PublicKey {
        return new PublicKey({
            alg: this.curve.algorithm,
            algorithm: new SSHECDSAPublicKey(this.curve, {
                publicKey: this.data.publicKey,
            }),
        })
    }

    serialize(): Buffer {
        return Buffer.concat([
            serializeBuffer(Buffer.from(this.curve.identifier, "ascii")),
            serializeBuffer(this.data.publicKey),
            serializeBuffer(serializeMpintBufferToBuffer(this.data.privateKey)),
        ])
    }
}

function unsignedInteger(value: Buffer): Buffer {
    let first = 0
    while (first < value.length && value[first] === 0) first++
    return value.subarray(first)
}

function parsePositiveMpint(value: Buffer): Buffer {
    assert(value.length > 0, "ECDSA private key must be positive")
    if (value[0] === 0) {
        assert(value.length > 1 && (value[1] & 0x80) !== 0, "Non-canonical ECDSA private key")
        return value.subarray(1)
    }
    assert((value[0] & 0x80) === 0, "ECDSA private key must not be negative")
    return value
}

function fixedWidthInteger(value: Buffer, width: number): Buffer {
    const unsigned = unsignedInteger(value)
    assert(unsigned.length > 0 && unsigned.length <= width, "Invalid ECDSA integer width")
    const result = Buffer.alloc(width)
    unsigned.copy(result, width - unsigned.length)
    return result
}

function registerECDSAPrivateKey(curve: ECDSACurve): void {
    class CurvePrivateKey extends SSHECDSAPrivateKey {
        static alg_name = curve.algorithm
        static curve = curve

        constructor(data: SSHECDSAPrivateKeyData) {
            super(curve, data)
        }

        static parse(raw: Buffer): [PrivateKeyAlgorithm, Buffer] {
            let identifier: Buffer
            let publicKey: Buffer
            let privateKey: Buffer
            ;[identifier, raw] = readNextBuffer(raw)
            ;[publicKey, raw] = readNextBuffer(raw)
            ;[privateKey, raw] = readNextBuffer(raw)
            assert(
                identifier.equals(Buffer.from(curve.identifier, "ascii")),
                `Invalid ECDSA curve identifier ${curve.identifier}`,
            )
            return [
                new CurvePrivateKey({ publicKey, privateKey: parsePositiveMpint(privateKey) }),
                raw,
            ]
        }

        static generateSync(): PrivateKey {
            const ecdh = createECDH(curve.nodeName)
            const publicKey = ecdh.generateKeys()
            const algorithm = new CurvePrivateKey({
                publicKey,
                privateKey: ecdh.getPrivateKey(),
            })
            return new PrivateKey({
                alg: curve.algorithm,
                publicKey: algorithm.getPublicKey(),
                algorithm,
            })
        }

        static async generate(): Promise<PrivateKey> {
            return CurvePrivateKey.generateSync()
        }
    }
    PrivateKey.algorithms.set(curve.algorithm, CurvePrivateKey)
}

for (const curve of ECDSA_CURVES) registerECDSAPrivateKey(curve)
