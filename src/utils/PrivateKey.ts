import assert from "assert"
import {
    readNextBuffer,
    readNextCString,
    readNextUint32,
    serializeBuffer,
    serializeCString,
    serializeUint32,
} from "./Buffer.js"
import PublicKey from "./PublicKey.js"
import nacl from "tweetnacl"
import { randomBytes } from "crypto"

// TODO: Find a way to implement private key encryption
export interface PrivateKeyData {
    publicKey: PublicKey
    alg: string
    algorithm: PrivateKeyAlgorithm
}

export default class PrivateKey {
    static algorithms = new Map<string, typeof PrivateKeyAlgorithm>()

    data: PrivateKeyData
    constructor(data: PrivateKeyData) {
        this.data = data
    }

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    sign(data: Buffer): Buffer {
        return this.data.algorithm.sign(data)
    }

    serialize(): Buffer {
        const buffers = []

        // auth magic
        buffers.push(serializeCString(Buffer.from("openssh-key-v1")))
        // cipher name
        buffers.push(Buffer.from("none"))
        // kdf name
        buffers.push(Buffer.from("none"))
        // kdf options
        buffers.push(Buffer.alloc(0))

        // number of keys
        buffers.push(serializeUint32(1))
        // public key
        buffers.push(serializeBuffer(this.data.publicKey.serialize()))

        const prv = []
        const rnd = randomBytes(4)
        prv.push(rnd, rnd)
        prv.push(serializeBuffer(Buffer.from(this.data.alg, "utf8")))
        prv.push(this.data.algorithm.serialize())
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
        assert(numKeys === 1)

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

        // check padding
        for (let i = 0; i < raw.length; i++) {
            assert(raw[i] === i + 1, "Invalid padding byte at index " + i)
        }

        return new PrivateKey({
            publicKey,
            alg: alg.toString("utf8"),
            algorithm: prv,
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
        const lines = data.trim().split(/[\n\r]/)

        assert(lines[0] === "-----BEGIN OPENSSH PRIVATE KEY-----")
        assert(lines[lines.length - 1] === "-----END OPENSSH PRIVATE KEY-----")

        const base64 = lines.slice(1, -1).join("")
        const raw = Buffer.from(base64, "base64")

        return PrivateKey.parse(raw)
    }
}

export abstract class PrivateKeyAlgorithm {
    static alg_name: string

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    constructor(data: any) {
        throw new Error("Not implemented")
    }

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    sign(data: Buffer): Buffer {
        throw new Error("Not implemented")
    }

    serialize(): Buffer {
        throw new Error("Not implemented")
    }

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    static parse(raw: Buffer): [PrivateKeyAlgorithm, Buffer] {
        throw new Error("Not implemented")
    }

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    static async generate(): Promise<PrivateKeyAlgorithm> {
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

    sign(data: Buffer): Buffer {
        return Buffer.from(nacl.sign.detached(data, this.data.privateKey))
    }

    serialize(): Buffer {
        return Buffer.concat([
            serializeBuffer(this.data.publicKey),
            serializeBuffer(this.data.privateKey),
            serializeBuffer(Buffer.alloc(0)),
        ])
    }

    static parse(raw: Buffer): [PrivateKeyAlgorithm, Buffer] {
        let publicKey: Buffer
        ;[publicKey, raw] = readNextBuffer(raw)

        let privateKey: Buffer
        ;[privateKey, raw] = readNextBuffer(raw)

        // TODO: Haven't figured out what this property is yet, in ed25519
        let prvPayload2: Buffer
        ;[prvPayload2, raw] = readNextBuffer(raw)
        assert(prvPayload2.length === 0, "Unknown data in ed25519 private key")

        return [new SSHED25519PrivateKey({ publicKey, privateKey }), raw]
    }

    static async generate(): Promise<PrivateKeyAlgorithm> {
        const keyPair = nacl.sign.keyPair()

        return new SSHED25519PrivateKey({
            publicKey: Buffer.from(keyPair.publicKey),
            privateKey: Buffer.from(keyPair.secretKey),
        })
    }
}
PrivateKey.algorithms.set(SSHED25519PrivateKey.alg_name, SSHED25519PrivateKey)
