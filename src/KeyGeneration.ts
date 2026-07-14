import PrivateKey, { SSHRSAPrivateKey } from "./utils/PrivateKey.js"
import PublicKey from "./utils/PublicKey.js"

export type KeyPairType = "ed25519" | "ed448" | "rsa" | "ecdsa" | "dsa"

export interface GenerateKeyPairOptions {
    /** RSA modulus or ECDSA curve size. RSA defaults to 3072; ECDSA defaults to 256; fixed-size keys reject it. */
    bits?: number
    /** Optional comment embedded in both OpenSSH serializations. */
    comment?: string
}

export interface GeneratedKeyPair {
    readonly privateKey: PrivateKey
    readonly publicKey: PublicKey
}

function validateComment(comment: string | undefined): void {
    if (comment === undefined) return
    if (comment.includes("\0") || comment.includes("\n") || comment.includes("\r")) {
        throw new TypeError("SSH key comment must not contain NUL or a line ending")
    }
}

function algorithm(type: KeyPairType, bits: number | undefined): string | undefined {
    if (type === "ed25519") {
        if (bits !== undefined) throw new TypeError("Ed25519 key generation does not accept bits")
        return "ssh-ed25519"
    }
    if (type === "ed448") {
        if (bits !== undefined) throw new TypeError("Ed448 key generation does not accept bits")
        return "ssh-ed448"
    }
    if (type === "ecdsa") {
        const size = bits ?? 256
        if (size !== 256 && size !== 384 && size !== 521) {
            throw new RangeError("ECDSA bits must be 256, 384, or 521")
        }
        return `ecdsa-sha2-nistp${size}`
    }
    if (type === "dsa") {
        if (bits !== undefined) throw new TypeError("DSA key generation does not accept bits")
        return "ssh-dss"
    }
    if (type === "rsa") {
        const size = bits ?? 3072
        if (!Number.isInteger(size)) throw new TypeError("RSA bits must be an integer")
        if (size < 1024 || size > 16_384) {
            throw new RangeError("RSA bits must be between 1024 and 16384")
        }
        return undefined
    }
    throw new TypeError(`Unsupported SSH key type: ${String(type)}`)
}

function attachComment(key: PrivateKey, comment: string | undefined): GeneratedKeyPair {
    const publicKey = new PublicKey({ ...key.data.publicKey.data, comment })
    const privateKey = new PrivateKey({ ...key.data, publicKey, comment })
    return Object.freeze({ privateKey, publicKey })
}

/** Generate a supported SSH key pair using Node's cryptographic random source. */
export async function generateKeyPair(
    type: KeyPairType,
    options: GenerateKeyPairOptions = {},
): Promise<GeneratedKeyPair> {
    validateComment(options.comment)
    const name = algorithm(type, options.bits)
    const privateKey =
        type === "rsa"
            ? await SSHRSAPrivateKey.generate(options.bits ?? 3072)
            : await PrivateKey.generate(name!)
    return attachComment(privateKey, options.comment)
}
