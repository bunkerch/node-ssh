import assert from "assert"
import {
    readNextBuffer,
    readNextCString,
    readNextUint32,
    serializeBuffer,
    serializeCString,
    serializeUint32,
} from "./Buffer.js"
import PublicKey, { SSHED25519PublicKey, SSHRSAPublicKey } from "./PublicKey.js"
import nacl from "tweetnacl"
import { createPrivateKey, createSign, generateKeyPair, KeyObject, randomBytes } from "crypto"
import EncodedSignature from "./Signature.js"
import asn1js from "asn1js"
import { decodeBigIntBE, encodeBigIntBE } from "./BigInt.js"

// TODO: Find a way to implement private key encryption
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
        this.data = data
    }

    sign(data: Buffer): EncodedSignature {
        return this.data.algorithm.sign(data)
    }

    serialize(): Buffer {
        const buffers = []

        // auth magic
        buffers.push(serializeCString(Buffer.from("openssh-key-v1")))
        // cipher name
        buffers.push(serializeBuffer(Buffer.from("none")))
        // kdf name
        buffers.push(serializeBuffer(Buffer.from("none")))
        // kdf options
        buffers.push(serializeBuffer(Buffer.alloc(0)))

        // number of keys
        buffers.push(serializeUint32(1))
        // public key
        buffers.push(serializeBuffer(this.data.publicKey.serialize()))

        const prv = []

        const rnd = randomBytes(4)
        prv.push(rnd, rnd)
        prv.push(serializeBuffer(Buffer.from(this.data.alg, "utf8")))
        prv.push(this.data.algorithm.serialize())
        prv.push(Buffer.from(this.data.comment ?? "", "utf8"))

        let prvPayload = Buffer.concat(prv)
        if (prvPayload.length % 8 !== 0) {
            const pad_len = 8 - (prvPayload.length % 8)
            const pad = Buffer.alloc(pad_len, pad_len)
            for (let i = 0; i < pad_len; i++) {
                pad[i] = i + 1
            }

            prvPayload = Buffer.concat([prvPayload, pad])
        }

        // rnd_prv_comment_pad_len
        buffers.push(serializeUint32(prvPayload.length))
        buffers.push(prvPayload)

        return Buffer.concat(buffers)
    }

    static parse(raw: Buffer): PrivateKey {
        let authMagic: Buffer
        ;[authMagic, raw] = readNextCString(raw)

        assert(authMagic.toString() === "openssh-key-v1", "Invalid magic string")

        // TODO: Support encrypted private keys
        let cipherName: Buffer
        ;[cipherName, raw] = readNextBuffer(raw)
        assert(cipherName.toString() === "none", "Unsupported cipher")

        let kdfName: Buffer
        ;[kdfName, raw] = readNextBuffer(raw)
        assert(kdfName.toString() === "none", "Unsupported kdf")

        let kdfOptions: Buffer
        ;[kdfOptions, raw] = readNextBuffer(raw)
        assert(kdfOptions.length === 0, "Unsupported kdf options")

        let numKeys: number
        ;[numKeys, raw] = readNextUint32(raw)
        assert(numKeys === 1, "Multiple keys found (Unsupported)")

        let sshpubkey: Buffer
        ;[sshpubkey, raw] = readNextBuffer(raw)
        const publicKey = PublicKey.parse(sshpubkey)

        let rnd_prv_comment_pad_len: number
        ;[rnd_prv_comment_pad_len, raw] = readNextUint32(raw)
        assert(
            raw.length === rnd_prv_comment_pad_len,
            "Unexpected private key length (Doesn't match rnd_prv_comment_pad_len)",
        )
        assert(raw.length % 8 === 0, "Unexpected private key length (length % 8 != 0)")

        let rnd1: number
        ;[rnd1, raw] = readNextUint32(raw)
        let rnd2: number
        ;[rnd2, raw] = readNextUint32(raw)
        assert(rnd1 === rnd2)

        let alg: Buffer
        ;[alg, raw] = readNextBuffer(raw)
        assert(
            alg.toString("utf8") === publicKey.data.alg,
            "Private key algorithm does not match public key algorithm",
        )

        const algorithm = PrivateKey.algorithms.get(alg.toString("utf8"))
        assert(algorithm, `Unsupported algorithm: ${alg.toString("utf8")}`)

        let prv: PrivateKeyAlgorithm
        ;[prv, raw] = algorithm.parse(raw)

        let comment: Buffer
        ;[comment, raw] = readNextBuffer(raw)

        // check padding
        for (let i = 0; i < raw.length; i++) {
            assert(raw[i] === i + 1, "Invalid padding byte at index " + i)
        }

        return new PrivateKey({
            publicKey,
            alg: alg.toString("utf8"),
            algorithm: prv,
            comment: comment.length > 0 ? comment.toString("utf8") : undefined,
        })
    }

    toString(): string {
        const lines = [`-----BEGIN OPENSSH PRIVATE KEY-----`]
        const b64 = this.serialize().toString("base64")
        for (let i = 0; i < b64.length; i += 70) {
            lines.push(b64.slice(i, i + 70))
        }
        lines.push(`-----END OPENSSH PRIVATE KEY-----`)

        return lines.join("\n")
    }

    static fromString(data: string): PrivateKey {
        const lines = data
            .trim()
            .split(/[\n\r]+/)
            .map((line) => line.trim())

        assert(lines[0] === "-----BEGIN OPENSSH PRIVATE KEY-----")
        assert(lines[lines.length - 1] === "-----END OPENSSH PRIVATE KEY-----")

        const base64 = lines.slice(1, -1).join("")
        const raw = Buffer.from(base64, "base64")

        return PrivateKey.parse(raw)
    }

    static generate(alg: string): Promise<PrivateKey> {
        const algo = PrivateKey.algorithms.get(alg)
        assert(algo, `Unsupported algorithm: ${alg}`)

        return algo.generate()
    }
}

export abstract class PrivateKeyAlgorithm {
    static alg_name: string

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    constructor(data: any) {
        throw new Error("Not implemented")
    }

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    sign(data: Buffer): EncodedSignature {
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
}

export interface SSHED25519PrivateKeyData {
    publicKey: Buffer
    privateKey: Buffer
}
export class SSHED25519PrivateKey implements PrivateKeyAlgorithm {
    static alg_name = "ssh-ed25519"

    data: SSHED25519PrivateKeyData
    constructor(data: SSHED25519PrivateKeyData) {
        assert(data.publicKey.length == 32, "Invalid ed25519 public key length")
        assert(data.privateKey.length == 64, "Invalid d25519 private key length")
        this.data = data
    }

    sign(data: Buffer): EncodedSignature {
        return new EncodedSignature({
            alg: SSHED25519PrivateKey.alg_name,
            data: Buffer.from(nacl.sign.detached(data, this.data.privateKey)),
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

    static async generate(): Promise<PrivateKey> {
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
}
PrivateKey.algorithms.set(SSHED25519PrivateKey.alg_name, SSHED25519PrivateKey)

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

    data: SSHRSAPrivateKeyData
    constructor(data: SSHRSAPrivateKeyData) {
        this.data = data
    }

    sign(data: Buffer): EncodedSignature {
        const key = createPrivateKey({
            key: this.toPEM(),
            format: "pem",
            type: "pkcs1",
        })

        const signer = createSign("sha1")
        signer.update(data)

        return new EncodedSignature({
            alg: SSHRSAPrivateKey.alg_name,
            data: signer.sign(key),
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
    static async generate(bitsize: number = 3072): Promise<PrivateKey> {
        const privateKey = await new Promise<KeyObject>((res, rej) => {
            generateKeyPair(
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
}
PrivateKey.algorithms.set(SSHRSAPrivateKey.alg_name, SSHRSAPrivateKey)
