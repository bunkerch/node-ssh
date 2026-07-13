import assert from "node:assert"
import { PacketNameToType } from "../constants.js"
import Packet from "../packet.js"
import { readNextBuffer, readNextUint8, serializeBuffer, serializeUint8 } from "../utils/Buffer.js"

export interface PingData {
    data: Buffer
}

export default class Ping implements Packet {
    static type = PacketNameToType.SSH_MSG_PING
    data: PingData

    constructor(data: PingData) {
        assert(Buffer.isBuffer(data.data), "SSH transport ping data must be a buffer")
        this.data = { data: Buffer.from(data.data) }
    }

    serialize(): Buffer {
        return Buffer.concat([serializeUint8(Ping.type), serializeBuffer(this.data.data)])
    }

    static parse(raw: Buffer): Ping {
        let type: number
        let data: Buffer
        ;[type, raw] = readNextUint8(raw)
        assert(type === Ping.type)
        ;[data, raw] = readNextBuffer(raw)
        assert(raw.length === 0, "Unexpected data after SSH transport ping")
        return new Ping({ data })
    }
}
