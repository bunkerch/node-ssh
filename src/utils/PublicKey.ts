import assert from "assert"
import { readNextBuffer, serializeBuffer } from "./Buffer.js"
import EncodedSignature from "./Signature.js"
import asn1js from "asn1js"
import crypto, { createHash } from "crypto"
import nacl from "tweetnacl"

export interface PublicKeyData {
    alg: string
    algorithm: PublicKeyAlgoritm
    comment?: string
}

export default class PublicKey {
    static algorithms = new Map<string, typeof PublicKeyAlgoritm>()

    data: PublicKeyData
    constructor(data: PublicKeyData) {
        this.data = data
    }

    verifySignature(data: Buffer, signature: EncodedSignature): boolean {
        if (signature.data.alg !== this.data.alg) {
            return false
        }

        return this.data.algorithm.verifySignature(data, signature.data.data)
    }

    toString(): string {
        return `${this.data.alg} ${this.serialize().toString("base64")}${this.data.comment ? ` ${this.data.comment}` : ""}`
    }

    hash(algorithm: "sha256" | "sha512"): string {
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

        buffers.push(serializeBuffer(Buffer.from(this.data.alg, "utf8")))
        buffers.push(this.data.algorithm.serialize())

        return Buffer.concat(buffers)
    }

    equals(other: PublicKey): boolean {
        return this.data.alg === other.data.alg && this.data.algorithm.equals(other.data.algorithm)
    }

    static parse(raw: Buffer): PublicKey {
        let alg: Buffer
        ;[alg, raw] = readNextBuffer(raw)

        const algorithm = PublicKey.algorithms.get(alg.toString("utf8"))
        assert(algorithm, `Unsupported algorithm: ${alg.toString("utf8")}`)

        return new PublicKey({
            alg: alg.toString("utf8"),
            algorithm: algorithm.parse(raw),
        })
    }

    static parseString(content: string): PublicKey {
        const parts = content.trim().split(/\s+/)

        assert(
            parts.length === 3 || parts.length === 2,
            `Invalid number of parts in the public key`,
        )
        const [alg, key, comment] = parts

        const publicKey = PublicKey.parse(Buffer.from(key, "base64"))
        assert(
            alg === publicKey.data.alg,
            `blob public key algorithm does not match the text public key algorithm`,
        )

        if (comment) {
            publicKey.data.comment = comment
        }

        return publicKey
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

export abstract class PublicKeyAlgoritm {
    static alg_name: string
    static has_encryption: boolean
    static has_signature: boolean

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    constructor(data: unknown) {
        throw new Error("Not implemented")
    }

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    verifySignature(data: Buffer, signature: Buffer): boolean {
        throw new Error("Not implemented")
    }

    serialize(): Buffer {
        throw new Error("Not implemented")
    }

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    equals(other: PublicKeyAlgoritm): boolean {
        throw new Error("Not implemented")
    }

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    static parse(raw: Buffer): PublicKeyAlgoritm {
        throw new Error("Not implemented")
    }
}

export interface SSHED25519PublicKeyData {
    publicKey: Buffer
}
export class SSHED25519PublicKey implements PublicKeyAlgoritm {
    static alg_name = "ssh-ed25519"
    static has_encryption = false
    static has_signature = true

    data: SSHED25519PublicKeyData
    constructor(data: SSHED25519PublicKeyData) {
        this.data = data
    }

    verifySignature(data: Buffer, signature: Buffer): boolean {
        if (signature.length != 64) return false

        return nacl.sign.detached.verify(data, signature, this.data.publicKey)
    }

    serialize(): Buffer {
        return serializeBuffer(this.data.publicKey)
    }

    equals(other: PublicKeyAlgoritm): boolean {
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

export interface SSHRSAData {
    publicExponent: Buffer
    modulus: Buffer
}
export class SSHRSAPublicKey implements PublicKeyAlgoritm {
    static alg_name = "ssh-rsa"
    static has_encryption = false
    static has_signature = true

    data: SSHRSAData
    constructor(data: SSHRSAData) {
        this.data = data
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

    verifySignature(data: Buffer, signature: Buffer): boolean {
        const key = crypto.createPublicKey({
            key: this.toPEM(),
            format: "pem",
            type: "pkcs1",
        })

        const verifier = crypto.createVerify("sha1")
        verifier.update(data)

        return verifier.verify(key, signature)
    }

    serialize(): Buffer {
        const buffers = []

        buffers.push(serializeBuffer(this.data.publicExponent))
        buffers.push(serializeBuffer(this.data.modulus))

        return Buffer.concat(buffers)
    }

    equals(other: PublicKeyAlgoritm): boolean {
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
