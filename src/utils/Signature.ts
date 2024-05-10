import assert from "assert"
import { readNextBuffer } from "./Buffer.js"

export interface EncodedSignatureData {
    alg: string,
    data: Buffer
}
export default class EncodedSignature {
    data: EncodedSignatureData
    constructor(data: EncodedSignatureData) {
        this.data = data
    }

    serialize(): Buffer {
        const buffers = []

        const alg = Buffer.from(this.data.alg, "utf8")
        const algLength = Buffer.alloc(4)
        algLength.writeUInt32BE(alg.length)
        buffers.push(algLength)
        buffers.push(alg)

        const dataLength = Buffer.alloc(4)
        dataLength.writeUInt32BE(this.data.data.length)
        buffers.push(dataLength)
        buffers.push(this.data.data)

        return Buffer.concat(buffers)
    }

    static parse(raw: Buffer) : EncodedSignature {
        let name: Buffer
        [name, raw] = readNextBuffer(raw)

        let data: Buffer
        [data, raw] = readNextBuffer(raw)

        assert(raw.length === 0)

        return new EncodedSignature({
            alg: name.toString("utf8"),
            data: data
        })
    }
}