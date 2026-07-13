import assert from "node:assert"
import { PacketNameToType } from "../constants.js"
import Packet from "../packet.js"
import { readNextBuffer, readNextUint8, serializeBuffer, serializeUint8 } from "../utils/Buffer.js"

export interface PongData {
    data: Buffer
}

export default class Pong implements Packet {
    static type = PacketNameToType.SSH_MSG_PONG
    data: PongData

    constructor(data: PongData) {
        assert(Buffer.isBuffer(data.data), "SSH transport pong data must be a buffer")
        this.data = { data: Buffer.from(data.data) }
    }

    serialize(): Buffer {
        return Buffer.concat([serializeUint8(Pong.type), serializeBuffer(this.data.data)])
    }

    static parse(raw: Buffer): Pong {
        let type: number
        let data: Buffer
        ;[type, raw] = readNextUint8(raw)
        assert(type === Pong.type)
        ;[data, raw] = readNextBuffer(raw)
        assert(raw.length === 0, "Unexpected data after SSH transport pong")
        return new Pong({ data })
    }
}
