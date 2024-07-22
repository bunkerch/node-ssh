import assert from "assert"
import { readNextBuffer, serializeBuffer } from "./Buffer.js"

export interface EncodedSignatureData {
    alg: string
    data: Buffer
}
export default class EncodedSignature {
    data: EncodedSignatureData
    constructor(data: EncodedSignatureData) {
        this.data = data
    }

    serialize(): Buffer {
        const buffers = []

        buffers.push(serializeBuffer(Buffer.from(this.data.alg, "utf8")))
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
            alg: name.toString("utf8"),
            data: data,
        })
    }
}
