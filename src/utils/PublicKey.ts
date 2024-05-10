import assert from "assert"
import { readNextBuffer } from "./Buffer.js"
import EncodedSignature from "./Signature.js"
import asn1js from "asn1js"
import crypto from "crypto"

export type PublicKeyAlgoritm = SSHRSA
export interface PublicKeyData {
    alg: string,
    publicKey: PublicKeyAlgoritm
}

export default class PublicKey {
    data: PublicKeyData
    constructor(data: PublicKeyData) {
        this.data = data
    }

    verifySignature(data: Buffer, signature: EncodedSignature): boolean {
        if(signature.data.alg !== this.data.alg) {
            return false
        }

        return this.data.publicKey.verifySignature(data, signature.data.data)
    }

    toString(): string  {
        return `${this.data.alg} ${this.serialize().toString("base64")}`
    }

    serialize(): Buffer {
        const buffers = []

        const alg = Buffer.from(this.data.alg, "utf8")
        const algLength = Buffer.alloc(4)
        algLength.writeUInt32BE(alg.length)
        buffers.push(algLength)
        buffers.push(alg)
        
        buffers.push(this.data.publicKey.serialize())

        return Buffer.concat(buffers)
    }

    static parse(raw: Buffer) : PublicKey {
        let alg: Buffer
        [alg, raw] = readNextBuffer(raw)

        switch(alg.toString("utf8")){
            case "ssh-rsa": {
                let publicExponent: Buffer
                [publicExponent, raw] = readNextBuffer(raw)
        
                let modulus: Buffer
                [modulus, raw] = readNextBuffer(raw)
        
                assert(raw.length === 0)
        
                return new PublicKey({
                    alg: alg.toString("utf8"),
                    publicKey: new SSHRSA({
                        publicExponent: publicExponent,
                        modulus: modulus
                    })
                })
            }
            default: {
                throw new Error(`Unsupported algorithm: ${alg.toString("utf8")}`)
            }
        }
    }
}

export interface SSHRSAData {
    publicExponent: Buffer,
    modulus: Buffer
}
export class SSHRSA {
    data: SSHRSAData
    constructor(data: SSHRSAData) {
        this.data = data
    }

    toPEM(): string {
        const sequence = new asn1js.Sequence({
            value: [
                new asn1js.Integer({ 
                    isHexOnly: true,
                    valueHex: this.data.modulus
                }),
                new asn1js.Integer({ 
                    isHexOnly: true,
                    valueHex: this.data.publicExponent
                }),
            ]
        })
        const buffer = Buffer.from(sequence.toBER(false)).toString("base64")
        let key = ""
        for(let i = 0; i < buffer.length; i += 64) {
            key += buffer.slice(i, i + 64) + "\n"
        }
        return `-----BEGIN RSA PUBLIC KEY-----\n${key}-----END RSA PUBLIC KEY-----`
    }

    verifySignature(data: Buffer, signature: Buffer): boolean {
        const key = crypto.createPublicKey({
            key: this.toPEM(),
            format: "pem",
            type: "pkcs1"
        })
        const verifier = crypto.createVerify("sha1")
        verifier.update(data)
        return verifier.verify(key, signature)
    }

    serialize(): Buffer {
        const buffers = []

        const publicExponentLength = Buffer.alloc(4)
        publicExponentLength.writeUInt32BE(this.data.publicExponent.length)
        buffers.push(publicExponentLength)
        buffers.push(this.data.publicExponent)

        const modulusLength = Buffer.alloc(4)
        modulusLength.writeUInt32BE(this.data.modulus.length)
        buffers.push(modulusLength)
        buffers.push(this.data.modulus)

        return Buffer.concat(buffers)
    }
}