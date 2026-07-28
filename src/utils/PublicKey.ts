import assert from "assert"
import {
    readNextBuffer,
    readNextUint32,
    readNextUint64,
    serializeBuffer,
    serializeUint8,
    serializeUint32,
} from "./Buffer.js"
import EncodedSignature, {
    SSH_ECDSA_SECURITY_KEY_ALGORITHM,
    SSH_ED25519_SECURITY_KEY_ALGORITHM,
    SSH_WEBAUTHN_ECDSA_SECURITY_KEY_ALGORITHM,
    type EncodedSecurityKeySignatureData,
} from "./Signature.js"
import asn1js from "asn1js"
import crypto, { createHash, ECDH, type JsonWebKey } from "crypto"
import { ed448 } from "@noble/curves/ed448.js"
import nacl from "tweetnacl"
import { decodeBigIntBE } from "./BigInt.js"
import { parseBufferToMpintBuffer } from "./mpint.js"
import { decodeSSHName, encodeSSHName } from "./SSHName.js"
import { decodeSSHUTF8, encodeSSHUTF8 } from "./SSHText.js"
import {
    dsaPublicKey,
    dsaParametersFromPublicKey,
    type DSAParameters,
    validateDSAParameters,
    verifyDSA,
} from "./DSA.js"

export interface ECDSACurve {
    readonly algorithm: string
    readonly identifier: string
    readonly nodeName: string
    readonly jwkName: "P-256" | "P-384" | "P-521"
    readonly hash: "sha256" | "sha384" | "sha512"
    readonly coordinateLength: number
}

export const ECDSA_CURVES: readonly ECDSACurve[] = Object.freeze([
    Object.freeze({
        algorithm: "ecdsa-sha2-nistp256",
        identifier: "nistp256",
        nodeName: "prime256v1",
        jwkName: "P-256",
        hash: "sha256",
        coordinateLength: 32,
    }),
    Object.freeze({
        algorithm: "ecdsa-sha2-nistp384",
        identifier: "nistp384",
        nodeName: "secp384r1",
        jwkName: "P-384",
        hash: "sha384",
        coordinateLength: 48,
    }),
    Object.freeze({
        algorithm: "ecdsa-sha2-nistp521",
        identifier: "nistp521",
        nodeName: "secp521r1",
        jwkName: "P-521",
        hash: "sha512",
        coordinateLength: 66,
    }),
])

export interface PublicKeyData {
    alg: string
    algorithm: PublicKeyAlgorithm
    comment?: string
}

export function encodeSSHKeyComment(comment: string, field = "SSH key comment"): Buffer {
    if (/[\0\r\n]/u.test(comment)) {
        throw new Error(`${field} must not contain NUL or a line ending`)
    }
    return encodeSSHUTF8(comment, field)
}

export default class PublicKey {
    static algorithms = new Map<string, typeof PublicKeyAlgorithm>()

    data: PublicKeyData
    constructor(data: PublicKeyData) {
        encodeSSHName(data.alg, "SSH public key algorithm")
        const expectedAlgorithm =
            data.algorithm instanceof SSHCertificatePublicKey
                ? data.algorithm.algorithmName
                : data.algorithm instanceof SSHECDSAPublicKey
                  ? data.algorithm.curve.algorithm
                  : (data.algorithm.constructor as typeof PublicKeyAlgorithm).alg_name
        assert(data.alg === expectedAlgorithm, "Public key algorithm does not match key data")
        if (data.comment !== undefined) encodeSSHKeyComment(data.comment)
        this.data = { ...data }
    }

    get signatureAlgorithms(): readonly string[] {
        if (this.data.algorithm instanceof SSHCertificatePublicKey) {
            const suffix = this.data.alg.endsWith(CERTIFICATE_SUFFIX)
                ? CERTIFICATE_SUFFIX
                : STANDARD_CERTIFICATE_SUFFIX
            if (
                this.data.algorithm.publicKey.data.algorithm instanceof SSHECDSASecurityKeyPublicKey
            ) {
                return [
                    suffix === CERTIFICATE_SUFFIX
                        ? securityKeyCertificateAlgorithm(SSH_ECDSA_SECURITY_KEY_ALGORITHM)
                        : `${SSH_ECDSA_SECURITY_KEY_ALGORITHM}${suffix}`,
                    suffix === CERTIFICATE_SUFFIX
                        ? securityKeyCertificateAlgorithm(SSH_WEBAUTHN_ECDSA_SECURITY_KEY_ALGORITHM)
                        : `${SSH_WEBAUTHN_ECDSA_SECURITY_KEY_ALGORITHM}${suffix}`,
                ]
            }
            return this.data.algorithm.publicKey.data.alg === SSHRSAPublicKey.alg_name
                ? [`rsa-sha2-512${suffix}`, `rsa-sha2-256${suffix}`, this.data.alg]
                : [this.data.alg]
        }
        if (this.data.algorithm instanceof SSHECDSASecurityKeyPublicKey) {
            return [SSH_ECDSA_SECURITY_KEY_ALGORITHM, SSH_WEBAUTHN_ECDSA_SECURITY_KEY_ALGORITHM]
        }
        return this.data.alg === SSHRSAPublicKey.alg_name
            ? ["rsa-sha2-512", "rsa-sha2-256", SSHRSAPublicKey.alg_name]
            : [this.data.alg]
    }

    supportsSignatureAlgorithm(algorithm: string): boolean {
        return this.signatureAlgorithms.includes(algorithm)
    }

    signatureAlgorithmFor(algorithm: string): string {
        if (
            this.data.algorithm instanceof SSHCertificatePublicKey &&
            this.data.algorithm.publicKey.supportsSignatureAlgorithm(algorithm)
        ) {
            return algorithm
        }
        assert(
            this.supportsSignatureAlgorithm(algorithm),
            `Signature algorithm ${algorithm} is incompatible with ${this.data.alg}`,
        )
        if (!(this.data.algorithm instanceof SSHCertificatePublicKey)) return algorithm
        if (algorithm === this.data.alg) return this.data.algorithm.publicKey.data.alg
        if (algorithm.endsWith(CERTIFICATE_SUFFIX) && algorithm.startsWith("sk-")) {
            return `${algorithm.slice(0, -CERTIFICATE_SUFFIX.length)}@openssh.com`
        }
        if (algorithm.endsWith(CERTIFICATE_SUFFIX) && algorithm.startsWith("webauthn-sk-")) {
            return `${algorithm.slice(0, -CERTIFICATE_SUFFIX.length)}@openssh.com`
        }
        const suffix = algorithm.endsWith(CERTIFICATE_SUFFIX)
            ? CERTIFICATE_SUFFIX
            : STANDARD_CERTIFICATE_SUFFIX
        assert(algorithm.endsWith(suffix))
        return algorithm.slice(0, -suffix.length)
    }

    verifySignature(data: Buffer, signature: EncodedSignature): boolean {
        return this.data.algorithm.verifySignature(
            data,
            signature.data.data,
            signature.data.alg,
            signature.data.securityKey,
        )
    }

    toString(): string {
        if (this.data.comment !== undefined) encodeSSHKeyComment(this.data.comment)
        return `${this.data.alg} ${this.serialize().toString("base64")}${this.data.comment ? ` ${this.data.comment}` : ""}`
    }

    /** Export the underlying cryptographic public key as SubjectPublicKeyInfo PEM. */
    toPEM(): string {
        return publicKeyObject(this).export({ format: "pem", type: "spki" }) as string
    }

    hash(algorithm: "md5" | "sha256" | "sha512"): string {
        if (algorithm === "md5") {
            return `MD5:${createHash("md5")
                .update(this.serialize())
                .digest("hex")
                .match(/.{2}/gu)!
                .join(":")}`
        }
        // generate an hash in the format
        // SHA256:wQpFbMmpXdJJtm6bwaHiBrEq827/0/n8RzBo7yIUlEg
        const hash = createHash(algorithm)
            .update(this.serialize())
            .digest("base64")
            // remove trailing padding
            .replace(/=+$/, "")

        return algorithm.toUpperCase() + ":" + hash
    }

    serialize(): Buffer {
        const buffers = []

        buffers.push(serializeBuffer(encodeSSHName(this.data.alg, "SSH public key algorithm")))
        buffers.push(this.data.algorithm.serialize())

        return Buffer.concat(buffers)
    }

    equals(other: PublicKey): boolean {
        return this.data.alg === other.data.alg && this.data.algorithm.equals(other.data.algorithm)
    }

    static parse(raw: Buffer): PublicKey {
        let alg: Buffer
        ;[alg, raw] = readNextBuffer(raw)

        const algorithmName = decodeSSHName(alg, "SSH public key algorithm")
        const certificateKeyAlgorithm = CERTIFICATE_KEY_ALGORITHMS.get(algorithmName)
        if (certificateKeyAlgorithm) {
            return new PublicKey({
                alg: algorithmName,
                algorithm: SSHCertificatePublicKey.parse(
                    algorithmName,
                    certificateKeyAlgorithm,
                    raw,
                ),
            })
        }

        const algorithm = PublicKey.algorithms.get(algorithmName)
        assert(algorithm, `Unsupported algorithm: ${alg.toString("utf8")}`)

        return new PublicKey({
            alg: algorithmName,
            algorithm: algorithm.parse(raw),
        })
    }

    static parseString(content: string): PublicKey {
        const match = /^(\S+)\s+(\S+)(?:\s+(.+))?$/u.exec(content.trim())
        assert(match, "Invalid text public key")
        const [, alg, key, comment] = match

        assert(/^[A-Za-z0-9+/]+={0,2}$/u.test(key), "Invalid public key base64")
        assert(key.length % 4 !== 1, "Invalid public key base64 length")
        const decoded = Buffer.from(key, "base64")
        const padded = key.padEnd(Math.ceil(key.length / 4) * 4, "=")
        assert(decoded.toString("base64") === padded, "Non-canonical public key base64")
        const publicKey = PublicKey.parse(decoded)
        assert(
            alg === publicKey.data.alg,
            `blob public key algorithm does not match the text public key algorithm`,
        )

        return comment ? new PublicKey({ ...publicKey.data, comment }) : publicKey
    }

    static fromPEM(data: string | Buffer): PublicKey {
        let key: crypto.KeyObject
        let jwk: JsonWebKey
        try {
            key = crypto.createPublicKey(data)
            if (key.asymmetricKeyType === "dsa") {
                return new PublicKey({
                    alg: SSHDSSPublicKey.alg_name,
                    algorithm: new SSHDSSPublicKey(dsaParametersFromPublicKey(key)),
                })
            }
            jwk = key.export({ format: "jwk" })
        } catch (error) {
            throw new Error("Invalid public key PEM", { cause: error })
        }

        if (jwk.kty === "OKP" && jwk.crv === "Ed25519" && jwk.x) {
            const publicKey = decodeJWKField(jwk.x, "Ed25519 public key")
            assert(publicKey.length === 32, "Invalid Ed25519 public key length")
            return new PublicKey({
                alg: SSHED25519PublicKey.alg_name,
                algorithm: new SSHED25519PublicKey({ publicKey }),
            })
        }

        if (jwk.kty === "OKP" && jwk.crv === "Ed448" && jwk.x) {
            const publicKey = decodeJWKField(jwk.x, "Ed448 public key")
            assert(publicKey.length === 57, "Invalid Ed448 public key length")
            return new PublicKey({
                alg: SSHED448PublicKey.alg_name,
                algorithm: new SSHED448PublicKey({ publicKey }),
            })
        }

        if (jwk.kty === "RSA" && jwk.e && jwk.n) {
            return new PublicKey({
                alg: SSHRSAPublicKey.alg_name,
                algorithm: new SSHRSAPublicKey({
                    publicExponent: positiveMpint(decodeJWKField(jwk.e, "RSA public exponent")),
                    modulus: positiveMpint(decodeJWKField(jwk.n, "RSA modulus")),
                }),
            })
        }

        if (jwk.kty === "EC" && jwk.crv && jwk.x && jwk.y) {
            const curve = ECDSA_CURVES.find(({ jwkName }) => jwkName === jwk.crv)
            assert(curve, `Unsupported ECDSA curve: ${jwk.crv}`)
            const x = decodeJWKField(jwk.x, "ECDSA x coordinate")
            const y = decodeJWKField(jwk.y, "ECDSA y coordinate")
            assert(
                x.length === curve.coordinateLength && y.length === curve.coordinateLength,
                `Invalid ${curve.identifier} public key coordinates`,
            )
            return new PublicKey({
                alg: curve.algorithm,
                algorithm: new SSHECDSAPublicKey(curve, {
                    publicKey: Buffer.concat([Buffer.from([4]), x, y]),
                }),
            })
        }

        throw new Error(`Unsupported public key type: ${jwk.crv ?? jwk.kty ?? "unknown"}`)
    }

    static parseAuthorizedKeysFile(content: string): PublicKey[] {
        // ~/.ssh/authorized_keys is just a text file, where each
        // line is a new public key.
        const keys: PublicKey[] = []
        const lines = content.trim().split(/[\n\r]+/)

        for (const line of lines) {
            if (!line) continue

            try {
                const publicKey = PublicKey.parseString(line.trim())
                keys.push(publicKey)
            } catch {}
        }

        return keys
    }
}

function jwkInteger(value: Buffer): string {
    let first = 0
    while (first < value.length - 1 && value[first] === 0) first++
    return value.subarray(first).toString("base64url")
}

function publicKeyObject(key: PublicKey): crypto.KeyObject {
    const algorithm = key.data.algorithm
    if (algorithm instanceof SSHCertificatePublicKey) {
        return publicKeyObject(algorithm.publicKey)
    }
    if (algorithm instanceof SSHED25519SecurityKeyPublicKey) {
        return crypto.createPublicKey({
            key: {
                kty: "OKP",
                crv: "Ed25519",
                x: algorithm.data.publicKey.toString("base64url"),
            },
            format: "jwk",
        })
    }
    if (algorithm instanceof SSHECDSASecurityKeyPublicKey) {
        return crypto.createPublicKey({
            key: new SSHECDSAPublicKey(ECDSA_CURVES[0], {
                publicKey: algorithm.data.publicKey,
            }).toJWK(),
            format: "jwk",
        })
    }
    if (algorithm instanceof SSHED25519PublicKey) {
        return crypto.createPublicKey({
            key: {
                kty: "OKP",
                crv: "Ed25519",
                x: algorithm.data.publicKey.toString("base64url"),
            },
            format: "jwk",
        })
    }
    if (algorithm instanceof SSHED448PublicKey) {
        return crypto.createPublicKey({
            key: {
                kty: "OKP",
                crv: "Ed448",
                x: algorithm.data.publicKey.toString("base64url"),
            },
            format: "jwk",
        })
    }
    if (algorithm instanceof SSHRSAPublicKey) {
        return crypto.createPublicKey({
            key: {
                kty: "RSA",
                n: jwkInteger(algorithm.data.modulus),
                e: jwkInteger(algorithm.data.publicExponent),
            },
            format: "jwk",
        })
    }
    if (algorithm instanceof SSHECDSAPublicKey) {
        return crypto.createPublicKey({ key: algorithm.toJWK(), format: "jwk" })
    }
    if (algorithm instanceof SSHDSSPublicKey) return dsaPublicKey(algorithm.data)
    throw new Error(`SSH public key ${key.data.alg} cannot be exported as PEM`)
}

export type SSHCertificateRole = "user" | "host"

export interface SSHCertificateOption {
    readonly name: string
    readonly data: Buffer
}

export interface SSHCertificateData {
    readonly nonce: Buffer
    readonly publicKey: PublicKey
    readonly serial: bigint
    readonly role: SSHCertificateRole
    readonly identifier: string
    readonly principals: readonly string[]
    readonly validAfter: bigint
    readonly validBefore: bigint
    readonly criticalOptions: readonly SSHCertificateOption[]
    readonly extensions: readonly SSHCertificateOption[]
    readonly reserved: Buffer
    readonly signatureKey: PublicKey
    readonly signature: EncodedSignature
}

const CERTIFICATE_SUFFIX = "-cert-v01@openssh.com"
const STANDARD_CERTIFICATE_SUFFIX = "-cert"
const OPENSSH_ALGORITHM_SUFFIX = "@openssh.com"

function securityKeyCertificateAlgorithm(algorithm: string): string {
    assert(algorithm.endsWith(OPENSSH_ALGORITHM_SUFFIX))
    return `${algorithm.slice(0, -OPENSSH_ALGORITHM_SUFFIX.length)}${CERTIFICATE_SUFFIX}`
}

const CERTIFICATE_KEY_ALGORITHMS = new Map<string, string>([
    [
        securityKeyCertificateAlgorithm(SSH_ED25519_SECURITY_KEY_ALGORITHM),
        SSH_ED25519_SECURITY_KEY_ALGORITHM,
    ],
    [
        securityKeyCertificateAlgorithm(SSH_ECDSA_SECURITY_KEY_ALGORITHM),
        SSH_ECDSA_SECURITY_KEY_ALGORITHM,
    ],
    [`ssh-ed25519${CERTIFICATE_SUFFIX}`, "ssh-ed25519"],
    [`ssh-rsa${CERTIFICATE_SUFFIX}`, "ssh-rsa"],
    [`ssh-dss${CERTIFICATE_SUFFIX}`, "ssh-dss"],
    ...ECDSA_CURVES.map(
        ({ algorithm }) => [`${algorithm}${CERTIFICATE_SUFFIX}`, algorithm] as const,
    ),
    [`ssh-ed25519${STANDARD_CERTIFICATE_SUFFIX}`, "ssh-ed25519"],
    [`ssh-ed448${STANDARD_CERTIFICATE_SUFFIX}`, "ssh-ed448"],
    [`ssh-rsa${STANDARD_CERTIFICATE_SUFFIX}`, "ssh-rsa"],
    [`ssh-dss${STANDARD_CERTIFICATE_SUFFIX}`, "ssh-dss"],
    ...ECDSA_CURVES.map(
        ({ algorithm }) => [`${algorithm}${STANDARD_CERTIFICATE_SUFFIX}`, algorithm] as const,
    ),
])

export function isCertificateKeyAlgorithm(algorithm: string): boolean {
    return CERTIFICATE_KEY_ALGORITHMS.has(algorithm)
}

export class SSHCertificatePublicKey implements PublicKeyAlgorithm {
    static has_encryption = false
    static has_signature = true

    readonly algorithmName: string
    readonly data: SSHCertificateData
    private readonly payload: Buffer
    private readonly signedData: Buffer

    private constructor(
        algorithmName: string,
        data: SSHCertificateData,
        payload: Buffer,
        signedData: Buffer,
    ) {
        this.algorithmName = algorithmName
        this.data = data
        this.payload = Buffer.from(payload)
        this.signedData = Buffer.from(signedData)
    }

    get publicKey(): PublicKey {
        return this.data.publicKey
    }

    verifyCertificateSignature(): boolean {
        return this.data.signatureKey.verifySignature(this.signedData, this.data.signature)
    }

    verifyHostCertificate(hostname: string, at = BigInt(Math.floor(Date.now() / 1000))): boolean {
        return (
            this.data.role === "host" &&
            this.verifyCertificateSignature() &&
            this.data.validAfter <= at &&
            at < this.data.validBefore &&
            this.data.criticalOptions.length === 0 &&
            (this.data.principals.length === 0 ||
                this.data.principals.some(
                    (principal) => principal.toLowerCase() === hostname.toLowerCase(),
                ))
        )
    }

    verifySignature(
        data: Buffer,
        signature: Buffer,
        algorithm?: string,
        securityKey?: EncodedSecurityKeySignatureData,
    ): boolean {
        return this.publicKey.data.algorithm.verifySignature(
            data,
            signature,
            algorithm,
            securityKey,
        )
    }

    serialize(): Buffer {
        return Buffer.from(this.payload)
    }

    equals(other: PublicKeyAlgorithm): boolean {
        return other instanceof SSHCertificatePublicKey && this.payload.equals(other.payload)
    }

    static parse(
        algorithmName: string,
        keyAlgorithm: string,
        payload: Buffer,
    ): SSHCertificatePublicKey {
        const originalPayload = payload
        let nonce: Buffer
        ;[nonce, payload] = readNextBuffer(payload)
        assert(nonce.length >= 16, "Certificate nonce must be at least 16 bytes")

        const [publicKey, remaining] = parseCertifiedPublicKey(keyAlgorithm, payload)
        payload = remaining
        let serial: bigint
        let roleNumber: number
        let identifier: Buffer
        let principalsRaw: Buffer
        let validAfter: bigint
        let validBefore: bigint
        let criticalOptionsRaw: Buffer
        let extensionsRaw: Buffer
        let reserved: Buffer
        let signatureKeyRaw: Buffer
        ;[serial, payload] = readNextUint64(payload)
        ;[roleNumber, payload] = readNextUint32(payload)
        assert(roleNumber === 1 || roleNumber === 2, "Invalid certificate role")
        ;[identifier, payload] = readNextBuffer(payload)
        ;[principalsRaw, payload] = readNextBuffer(payload)
        ;[validAfter, payload] = readNextUint64(payload)
        ;[validBefore, payload] = readNextUint64(payload)
        ;[criticalOptionsRaw, payload] = readNextBuffer(payload)
        ;[extensionsRaw, payload] = readNextBuffer(payload)
        ;[reserved, payload] = readNextBuffer(payload)
        ;[signatureKeyRaw, payload] = readNextBuffer(payload)
        const signedPayloadLength = originalPayload.length - payload.length
        let signatureRaw: Buffer
        ;[signatureRaw, payload] = readNextBuffer(payload)
        assert(payload.length === 0, "Unexpected certificate data")

        const signatureKey = PublicKey.parse(signatureKeyRaw)
        assert(
            !(signatureKey.data.algorithm instanceof SSHCertificatePublicKey),
            "Certificate authority key must not be a certificate",
        )
        const principals = parseCertificatePrincipals(principalsRaw)
        if (algorithmName.endsWith(STANDARD_CERTIFICATE_SUFFIX)) {
            assert(principals.length > 0, "Standard certificate must contain a principal")
        }
        const outerAlgorithm = serializeBuffer(Buffer.from(algorithmName, "utf8"))
        return new SSHCertificatePublicKey(
            algorithmName,
            {
                nonce: Buffer.from(nonce),
                publicKey,
                serial,
                role: roleNumber === 1 ? "user" : "host",
                identifier: decodeUTF8(identifier, "certificate identifier"),
                principals,
                validAfter,
                validBefore,
                criticalOptions: parseCertificateOptions(criticalOptionsRaw),
                extensions: parseCertificateOptions(extensionsRaw),
                reserved: Buffer.from(reserved),
                signatureKey,
                signature: EncodedSignature.parse(signatureRaw),
            },
            originalPayload,
            Buffer.concat([outerAlgorithm, originalPayload.subarray(0, signedPayloadLength)]),
        )
    }
}

function parseCertifiedPublicKey(keyAlgorithm: string, raw: Buffer): [PublicKey, Buffer] {
    const fields =
        keyAlgorithm === SSH_ED25519_SECURITY_KEY_ALGORITHM
            ? 2
            : keyAlgorithm === SSH_ECDSA_SECURITY_KEY_ALGORITHM
              ? 3
              : keyAlgorithm === "ssh-ed25519" || keyAlgorithm === "ssh-ed448"
                ? 1
                : keyAlgorithm === "ssh-rsa" || keyAlgorithm.startsWith("ecdsa-")
                  ? 2
                  : 4
    const fieldBuffers: Buffer[] = []
    let remaining = raw
    for (let index = 0; index < fields; index++) {
        let field: Buffer
        ;[field, remaining] = readNextBuffer(remaining)
        fieldBuffers.push(serializeBuffer(field))
    }
    const algorithm = PublicKey.algorithms.get(keyAlgorithm)
    assert(algorithm, `Unsupported certified key algorithm: ${keyAlgorithm}`)
    return [
        new PublicKey({
            alg: keyAlgorithm,
            algorithm: algorithm.parse(Buffer.concat(fieldBuffers)),
        }),
        remaining,
    ]
}

function parseCertificatePrincipals(raw: Buffer): string[] {
    const principals: string[] = []
    while (raw.length > 0) {
        let principal: Buffer
        ;[principal, raw] = readNextBuffer(raw)
        principals.push(decodeUTF8(principal, "certificate principal"))
    }
    return principals
}

export function parseCertificateOptions(raw: Buffer): SSHCertificateOption[] {
    const options: SSHCertificateOption[] = []
    let previousName: Buffer | undefined
    while (raw.length > 0) {
        let nameRaw: Buffer
        let data: Buffer
        ;[nameRaw, raw] = readNextBuffer(raw)
        ;[data, raw] = readNextBuffer(raw)
        const name = decodeUTF8(nameRaw, "certificate option name")
        assert(
            previousName === undefined || Buffer.compare(previousName, nameRaw) < 0,
            "Certificate options are not sorted",
        )
        previousName = Buffer.from(nameRaw)
        options.push(Object.freeze({ name, data: Buffer.from(data) }))
    }
    return options
}

function decodeUTF8(raw: Buffer, name: string): string {
    const value = raw.toString("utf8")
    assert(Buffer.from(value, "utf8").equals(raw), `Invalid UTF-8 ${name}`)
    return value
}

function decodeJWKField(value: string, name: string): Buffer {
    assert(/^[A-Za-z0-9_-]+$/.test(value), `Invalid ${name}`)
    const decoded = Buffer.from(value, "base64url")
    assert(decoded.length > 0, `Invalid ${name}`)
    return decoded
}

function positiveMpint(value: Buffer): Buffer {
    let first = 0
    while (first < value.length - 1 && value[first] === 0) first++
    const unsigned = value.subarray(first)
    return (unsigned[0] & 0x80) === 0 ? unsigned : Buffer.concat([Buffer.from([0]), unsigned])
}

export abstract class PublicKeyAlgorithm {
    static alg_name: string
    static has_encryption: boolean
    static has_signature: boolean

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    constructor(data: unknown) {
        throw new Error("Not implemented")
    }

    verifySignature(
        data: Buffer,
        signature: Buffer,
        algorithm?: string,
        securityKey?: EncodedSecurityKeySignatureData,
    ): boolean {
        void securityKey
        throw new Error("Not implemented")
    }

    serialize(): Buffer {
        throw new Error("Not implemented")
    }

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    equals(other: PublicKeyAlgorithm): boolean {
        throw new Error("Not implemented")
    }

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    static parse(raw: Buffer): PublicKeyAlgorithm {
        throw new Error("Not implemented")
    }
}

export interface SSHED25519PublicKeyData {
    publicKey: Buffer
}
export class SSHED25519PublicKey implements PublicKeyAlgorithm {
    static alg_name = "ssh-ed25519"
    static has_encryption = false
    static has_signature = true

    readonly data: SSHED25519PublicKeyData
    constructor(data: SSHED25519PublicKeyData) {
        assert(data.publicKey.length === 32, "Invalid Ed25519 public key length")
        this.data = { publicKey: Buffer.from(data.publicKey) }
    }

    verifySignature(
        data: Buffer,
        signature: Buffer,
        algorithm = SSHED25519PublicKey.alg_name,
    ): boolean {
        if (algorithm !== SSHED25519PublicKey.alg_name) return false
        if (signature.length != 64) return false

        return nacl.sign.detached.verify(data, signature, this.data.publicKey)
    }

    serialize(): Buffer {
        return serializeBuffer(this.data.publicKey)
    }

    equals(other: PublicKeyAlgorithm): boolean {
        if (!(other instanceof SSHED25519PublicKey)) return false

        return this.data.publicKey.equals(other.data.publicKey)
    }

    static parse(raw: Buffer): SSHED25519PublicKey {
        let publicKey: Buffer
        ;[publicKey, raw] = readNextBuffer(raw)

        assert(raw.length === 0)

        return new SSHED25519PublicKey({
            publicKey: publicKey,
        })
    }
}
PublicKey.algorithms.set(SSHED25519PublicKey.alg_name, SSHED25519PublicKey)

export interface SSHED448PublicKeyData {
    publicKey: Buffer
}

export class SSHED448PublicKey implements PublicKeyAlgorithm {
    static alg_name = "ssh-ed448"
    static has_encryption = false
    static has_signature = true

    readonly data: SSHED448PublicKeyData
    constructor(data: SSHED448PublicKeyData) {
        assert(data.publicKey.length === 57, "Invalid Ed448 public key length")
        this.data = { publicKey: Buffer.from(data.publicKey) }
    }

    verifySignature(
        data: Buffer,
        signature: Buffer,
        algorithm = SSHED448PublicKey.alg_name,
    ): boolean {
        if (algorithm !== SSHED448PublicKey.alg_name || signature.length !== 114) return false
        try {
            return ed448.verify(signature, data, this.data.publicKey)
        } catch {
            return false
        }
    }

    serialize(): Buffer {
        return serializeBuffer(this.data.publicKey)
    }

    equals(other: PublicKeyAlgorithm): boolean {
        return (
            other instanceof SSHED448PublicKey && this.data.publicKey.equals(other.data.publicKey)
        )
    }

    static parse(raw: Buffer): SSHED448PublicKey {
        let publicKey: Buffer
        ;[publicKey, raw] = readNextBuffer(raw)
        assert(raw.length === 0, "Unexpected Ed448 public key data")
        return new SSHED448PublicKey({ publicKey })
    }
}
PublicKey.algorithms.set(SSHED448PublicKey.alg_name, SSHED448PublicKey)

export type SSHDSSPublicKeyData = DSAParameters

export class SSHDSSPublicKey implements PublicKeyAlgorithm {
    static alg_name = "ssh-dss"
    static has_encryption = false
    static has_signature = true

    readonly data: SSHDSSPublicKeyData
    constructor(data: SSHDSSPublicKeyData) {
        this.data = {
            p: Buffer.from(data.p),
            q: Buffer.from(data.q),
            g: Buffer.from(data.g),
            y: Buffer.from(data.y),
        }
        validateDSAParameters(this.data)
    }

    verifySignature(
        data: Buffer,
        signature: Buffer,
        algorithm = SSHDSSPublicKey.alg_name,
    ): boolean {
        return algorithm === SSHDSSPublicKey.alg_name && verifyDSA(data, signature, this.data)
    }

    serialize(): Buffer {
        return Buffer.concat([
            serializeBuffer(this.data.p),
            serializeBuffer(this.data.q),
            serializeBuffer(this.data.g),
            serializeBuffer(this.data.y),
        ])
    }

    equals(other: PublicKeyAlgorithm): boolean {
        return (
            other instanceof SSHDSSPublicKey &&
            this.data.p.equals(other.data.p) &&
            this.data.q.equals(other.data.q) &&
            this.data.g.equals(other.data.g) &&
            this.data.y.equals(other.data.y)
        )
    }

    static parse(raw: Buffer): SSHDSSPublicKey {
        let p: Buffer
        let q: Buffer
        let g: Buffer
        let y: Buffer
        ;[p, raw] = readNextBuffer(raw)
        ;[q, raw] = readNextBuffer(raw)
        ;[g, raw] = readNextBuffer(raw)
        ;[y, raw] = readNextBuffer(raw)
        assert(raw.length === 0)
        return new SSHDSSPublicKey({ p, q, g, y })
    }
}
PublicKey.algorithms.set(SSHDSSPublicKey.alg_name, SSHDSSPublicKey)

export interface SSHRSAData {
    publicExponent: Buffer
    modulus: Buffer
}
export class SSHRSAPublicKey implements PublicKeyAlgorithm {
    static alg_name = "ssh-rsa"
    static has_encryption = false
    static has_signature = true

    readonly data: SSHRSAData
    constructor(data: SSHRSAData) {
        parseBufferToMpintBuffer(data.publicExponent)
        parseBufferToMpintBuffer(data.modulus)
        const publicExponent = decodeBigIntBE(data.publicExponent)
        const modulus = decodeBigIntBE(data.modulus)
        assert(publicExponent >= 3n && (publicExponent & 1n) === 1n, "Invalid RSA public exponent")
        assert(modulus > publicExponent && (modulus & 1n) === 1n, "Invalid RSA modulus")
        this.data = {
            publicExponent: Buffer.from(data.publicExponent),
            modulus: Buffer.from(data.modulus),
        }
    }

    // encode the public key to PKCS#1 in PEM
    toPEM(): string {
        const sequence = new asn1js.Sequence({
            value: [
                new asn1js.Integer({
                    isHexOnly: true,
                    valueHex: this.data.modulus,
                }),
                new asn1js.Integer({
                    isHexOnly: true,
                    valueHex: this.data.publicExponent,
                }),
            ],
        })
        const buffer = Buffer.from(sequence.toBER(false)).toString("base64")
        let key = ""
        for (let i = 0; i < buffer.length; i += 64) {
            key += buffer.slice(i, i + 64) + "\n"
        }
        return `-----BEGIN RSA PUBLIC KEY-----\n${key}-----END RSA PUBLIC KEY-----`
    }

    verifySignature(
        data: Buffer,
        signature: Buffer,
        algorithm = SSHRSAPublicKey.alg_name,
    ): boolean {
        const hash =
            algorithm === "rsa-sha2-512"
                ? "sha512"
                : algorithm === "rsa-sha2-256"
                  ? "sha256"
                  : algorithm === SSHRSAPublicKey.alg_name
                    ? "sha1"
                    : undefined
        if (!hash) return false
        const key = crypto.createPublicKey({
            key: this.toPEM(),
            format: "pem",
            type: "pkcs1",
        })

        const verifier = crypto.createVerify(hash)
        verifier.update(data)

        return verifier.verify(key, signature)
    }

    serialize(): Buffer {
        const buffers = []

        buffers.push(serializeBuffer(this.data.publicExponent))
        buffers.push(serializeBuffer(this.data.modulus))

        return Buffer.concat(buffers)
    }

    equals(other: PublicKeyAlgorithm): boolean {
        if (!(other instanceof SSHRSAPublicKey)) return false

        return (
            this.data.publicExponent.equals(other.data.publicExponent) &&
            this.data.modulus.equals(other.data.modulus)
        )
    }

    static parse(raw: Buffer): SSHRSAPublicKey {
        let publicExponent: Buffer
        ;[publicExponent, raw] = readNextBuffer(raw)

        let modulus: Buffer
        ;[modulus, raw] = readNextBuffer(raw)

        assert(raw.length === 0)

        return new SSHRSAPublicKey({
            publicExponent: publicExponent,
            modulus: modulus,
        })
    }
}
PublicKey.algorithms.set(SSHRSAPublicKey.alg_name, SSHRSAPublicKey)

export interface SSHECDSAPublicKeyData {
    publicKey: Buffer
}

export class SSHECDSAPublicKey implements PublicKeyAlgorithm {
    static alg_name: string
    static has_encryption = false
    static has_signature = true
    static curve: ECDSACurve

    readonly curve: ECDSACurve
    readonly data: SSHECDSAPublicKeyData
    private readonly normalizedPublicKey: Buffer

    constructor(curve: ECDSACurve, data: SSHECDSAPublicKeyData) {
        this.curve = curve
        try {
            this.normalizedPublicKey = Buffer.from(
                ECDH.convertKey(
                    data.publicKey,
                    curve.nodeName,
                    undefined,
                    undefined,
                    "uncompressed",
                ),
            )
        } catch (error) {
            throw new Error(`Invalid ${curve.identifier} public key`, { cause: error })
        }
        this.data = { publicKey: Buffer.from(data.publicKey) }
    }

    verifySignature(data: Buffer, signature: Buffer, algorithm = this.curve.algorithm): boolean {
        if (algorithm !== this.curve.algorithm) return false
        try {
            const [r, afterR] = readNextBuffer(signature)
            const [s, raw] = readNextBuffer(afterR)
            if (raw.length !== 0) return false
            const p1363 = Buffer.concat([
                fixedWidthMpint(r, this.curve.coordinateLength),
                fixedWidthMpint(s, this.curve.coordinateLength),
            ])
            const key = crypto.createPublicKey({ key: this.toJWK(), format: "jwk" })
            const verifier = crypto.createVerify(this.curve.hash)
            verifier.update(data)
            return verifier.verify({ key, dsaEncoding: "ieee-p1363" }, p1363)
        } catch {
            return false
        }
    }

    toJWK(): JsonWebKey {
        const coordinateLength = this.curve.coordinateLength
        return {
            kty: "EC",
            crv: this.curve.jwkName,
            x: this.normalizedPublicKey.subarray(1, 1 + coordinateLength).toString("base64url"),
            y: this.normalizedPublicKey.subarray(1 + coordinateLength).toString("base64url"),
        }
    }

    serialize(): Buffer {
        return Buffer.concat([
            serializeBuffer(Buffer.from(this.curve.identifier, "ascii")),
            serializeBuffer(this.data.publicKey),
        ])
    }

    equals(other: PublicKeyAlgorithm): boolean {
        return (
            other instanceof SSHECDSAPublicKey &&
            other.curve.algorithm === this.curve.algorithm &&
            other.normalizedPublicKey.equals(this.normalizedPublicKey)
        )
    }
}

function fixedWidthMpint(value: Buffer, width: number): Buffer {
    if (value.length === 0) throw new Error("ECDSA integers must be positive")
    let unsigned = value
    if (value[0] === 0) {
        if (value.length === 1 || (value[1] & 0x80) === 0) {
            throw new Error("Non-canonical ECDSA integer")
        }
        unsigned = value.subarray(1)
    } else if ((value[0] & 0x80) !== 0) {
        throw new Error("Negative ECDSA integer")
    }
    if (unsigned.length > width) {
        throw new Error("Invalid ECDSA integer width")
    }
    const result = Buffer.alloc(width)
    unsigned.copy(result, width - unsigned.length)
    return result
}

function registerECDSAPublicKey(curve: ECDSACurve): void {
    class CurvePublicKey extends SSHECDSAPublicKey {
        static alg_name = curve.algorithm
        static curve = curve

        constructor(data: SSHECDSAPublicKeyData) {
            super(curve, data)
        }

        static parse(raw: Buffer): SSHECDSAPublicKey {
            let identifier: Buffer
            let publicKey: Buffer
            ;[identifier, raw] = readNextBuffer(raw)
            ;[publicKey, raw] = readNextBuffer(raw)
            assert(raw.length === 0)
            assert(
                identifier.equals(Buffer.from(curve.identifier, "ascii")),
                `Invalid ECDSA curve identifier ${curve.identifier}`,
            )
            return new CurvePublicKey({ publicKey })
        }
    }
    PublicKey.algorithms.set(curve.algorithm, CurvePublicKey)
}

for (const curve of ECDSA_CURVES) registerECDSAPublicKey(curve)

function encodeSecurityKeyApplication(application: string): Buffer {
    const encoded = encodeSSHUTF8(application, "security-key application")
    assert(encoded.length > 0, "Security-key application must not be empty")
    assert(!encoded.includes(0), "Security-key application must not contain NUL")
    return encoded
}

function securityKeySignedData(
    application: string,
    data: Buffer,
    details: EncodedSecurityKeySignatureData,
    webAuthn: boolean,
): Buffer {
    let extensions: Buffer = Buffer.alloc(0)
    let messageHash: Buffer
    if (webAuthn) {
        const metadata = details.webAuthn
        assert(metadata, "Missing WebAuthn signature metadata")
        const origin = encodeSSHUTF8(metadata.origin, "WebAuthn signature origin")
        assert(!origin.includes(0), "WebAuthn signature origin must not contain NUL")
        assert(!origin.includes(0x22), "WebAuthn origin must not contain a quote")
        assert(Buffer.isBuffer(metadata.clientData), "WebAuthn client data must be a buffer")
        assert(Buffer.isBuffer(metadata.extensions), "WebAuthn extensions must be a buffer")
        assert((details.flags & 0x40) === 0, "WebAuthn authenticator-data flag is not permitted")
        assert(
            ((details.flags & 0x80) !== 0) === (metadata.extensions.length !== 0),
            "WebAuthn extension flag does not match the extension data",
        )
        const preamble = Buffer.from(
            `{"type":"webauthn.get","challenge":"${data.toString("base64url")}","origin":"${origin.toString("utf8")}"`,
        )
        assert(
            metadata.clientData.subarray(0, preamble.length).equals(preamble),
            "WebAuthn client data does not contain the signed SSH message",
        )
        extensions = metadata.extensions
        messageHash = createHash("sha256").update(metadata.clientData).digest()
    } else {
        assert(details.webAuthn === undefined, "Unexpected WebAuthn signature metadata")
        messageHash = createHash("sha256").update(data).digest()
    }
    return Buffer.concat([
        createHash("sha256").update(encodeSecurityKeyApplication(application)).digest(),
        serializeUint8(details.flags),
        serializeUint32(details.counter),
        extensions,
        messageHash,
    ])
}

export interface SSHED25519SecurityKeyPublicKeyData {
    publicKey: Buffer
    application: string
}

export class SSHED25519SecurityKeyPublicKey implements PublicKeyAlgorithm {
    static alg_name = SSH_ED25519_SECURITY_KEY_ALGORITHM
    static has_encryption = false
    static has_signature = true

    readonly data: SSHED25519SecurityKeyPublicKeyData

    constructor(data: SSHED25519SecurityKeyPublicKeyData) {
        new SSHED25519PublicKey({ publicKey: data.publicKey })
        encodeSecurityKeyApplication(data.application)
        this.data = {
            publicKey: Buffer.from(data.publicKey),
            application: data.application,
        }
    }

    verifySignature(
        data: Buffer,
        signature: Buffer,
        algorithm = SSH_ED25519_SECURITY_KEY_ALGORITHM,
        securityKey?: EncodedSecurityKeySignatureData,
    ): boolean {
        if (
            algorithm !== SSH_ED25519_SECURITY_KEY_ALGORITHM ||
            securityKey === undefined ||
            securityKey.webAuthn !== undefined
        ) {
            return false
        }
        try {
            return new SSHED25519PublicKey({ publicKey: this.data.publicKey }).verifySignature(
                securityKeySignedData(this.data.application, data, securityKey, false),
                signature,
            )
        } catch {
            return false
        }
    }

    serialize(): Buffer {
        new SSHED25519PublicKey({ publicKey: this.data.publicKey })
        return Buffer.concat([
            serializeBuffer(this.data.publicKey),
            serializeBuffer(encodeSecurityKeyApplication(this.data.application)),
        ])
    }

    equals(other: PublicKeyAlgorithm): boolean {
        return (
            other instanceof SSHED25519SecurityKeyPublicKey &&
            this.data.publicKey.equals(other.data.publicKey) &&
            this.data.application === other.data.application
        )
    }

    static parse(raw: Buffer): SSHED25519SecurityKeyPublicKey {
        let publicKey: Buffer
        let application: Buffer
        ;[publicKey, raw] = readNextBuffer(raw)
        ;[application, raw] = readNextBuffer(raw)
        assert(raw.length === 0, "Unexpected Ed25519 security-key data")
        return new SSHED25519SecurityKeyPublicKey({
            publicKey,
            application: decodeSSHUTF8(application, "security-key application"),
        })
    }
}
PublicKey.algorithms.set(SSHED25519SecurityKeyPublicKey.alg_name, SSHED25519SecurityKeyPublicKey)

export interface SSHECDSASecurityKeyPublicKeyData {
    publicKey: Buffer
    application: string
}

export class SSHECDSASecurityKeyPublicKey implements PublicKeyAlgorithm {
    static alg_name = SSH_ECDSA_SECURITY_KEY_ALGORITHM
    static has_encryption = false
    static has_signature = true

    readonly data: SSHECDSASecurityKeyPublicKeyData

    constructor(data: SSHECDSASecurityKeyPublicKeyData) {
        new SSHECDSAPublicKey(ECDSA_CURVES[0], {
            publicKey: data.publicKey,
        })
        encodeSecurityKeyApplication(data.application)
        this.data = {
            publicKey: Buffer.from(data.publicKey),
            application: data.application,
        }
    }

    verifySignature(
        data: Buffer,
        signature: Buffer,
        algorithm = SSH_ECDSA_SECURITY_KEY_ALGORITHM,
        securityKey?: EncodedSecurityKeySignatureData,
    ): boolean {
        const webAuthn = algorithm === SSH_WEBAUTHN_ECDSA_SECURITY_KEY_ALGORITHM
        if (
            (algorithm !== SSH_ECDSA_SECURITY_KEY_ALGORITHM && !webAuthn) ||
            securityKey === undefined
        ) {
            return false
        }
        try {
            return new SSHECDSAPublicKey(ECDSA_CURVES[0], {
                publicKey: this.data.publicKey,
            }).verifySignature(
                securityKeySignedData(this.data.application, data, securityKey, webAuthn),
                signature,
            )
        } catch {
            return false
        }
    }

    serialize(): Buffer {
        new SSHECDSAPublicKey(ECDSA_CURVES[0], { publicKey: this.data.publicKey })
        return Buffer.concat([
            serializeBuffer(Buffer.from(ECDSA_CURVES[0].identifier, "ascii")),
            serializeBuffer(this.data.publicKey),
            serializeBuffer(encodeSecurityKeyApplication(this.data.application)),
        ])
    }

    equals(other: PublicKeyAlgorithm): boolean {
        return (
            other instanceof SSHECDSASecurityKeyPublicKey &&
            this.data.publicKey.equals(other.data.publicKey) &&
            this.data.application === other.data.application
        )
    }

    static parse(raw: Buffer): SSHECDSASecurityKeyPublicKey {
        let identifier: Buffer
        let publicKey: Buffer
        let application: Buffer
        ;[identifier, raw] = readNextBuffer(raw)
        ;[publicKey, raw] = readNextBuffer(raw)
        ;[application, raw] = readNextBuffer(raw)
        assert(raw.length === 0, "Unexpected ECDSA security-key data")
        assert(identifier.equals(Buffer.from(ECDSA_CURVES[0].identifier, "ascii")))
        return new SSHECDSASecurityKeyPublicKey({
            publicKey,
            application: decodeSSHUTF8(application, "security-key application"),
        })
    }
}
PublicKey.algorithms.set(SSHECDSASecurityKeyPublicKey.alg_name, SSHECDSASecurityKeyPublicKey)
