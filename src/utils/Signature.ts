import assert from "assert"
import { readNextBuffer, serializeBuffer } from "./Buffer.js"
import { decodeSSHName, encodeSSHName } from "./SSHName.js"

export interface EncodedSignatureData {
    alg: string
    data: Buffer
}
export default class EncodedSignature {
    data: EncodedSignatureData
    constructor(data: EncodedSignatureData) {
        encodeSSHName(data.alg, "SSH signature algorithm")
        this.data = { alg: data.alg, data: Buffer.from(data.data) }
    }

    serialize(): Buffer {
        const buffers = []

        buffers.push(serializeBuffer(encodeSSHName(this.data.alg, "SSH signature algorithm")))
        buffers.push(serializeBuffer(this.data.data))

        return Buffer.concat(buffers)
    }

    static parse(raw: Buffer): EncodedSignature {
        let name: Buffer
        ;[name, raw] = readNextBuffer(raw)

        let data: Buffer
        ;[data, raw] = readNextBuffer(raw)

        assert(raw.length === 0)

        return new EncodedSignature({
            alg: decodeSSHName(name, "SSH signature algorithm"),
            data,
        })
    }
}
