import assert from "assert"
import { SSHPacketType } from "../constants.js"
import Packet from "../packet.js"
import { readNextBuffer, readNextUint8, serializeBuffer } from "../utils/Buffer.js"

export interface IgnoreData {
    data: Buffer
}

export default class Ignore implements Packet {
    static type = SSHPacketType.SSH_MSG_IGNORE

    data: IgnoreData
    constructor(data: IgnoreData) {
        this.data = data
    }

    serialize(): Buffer {
        const buffers = []

        buffers.push(Buffer.from([Ignore.type]))

        buffers.push(serializeBuffer(this.data.data))

        return Buffer.concat(buffers)
    }

    static parse(raw: Buffer): Ignore {
        let packetType: number
        ;[packetType, raw] = readNextUint8(raw)
        assert(packetType === Ignore.type)

        let data: Buffer
        ;[data, raw] = readNextBuffer(raw)

        assert(raw.length === 0)

        return new Ignore({
            data: data,
        })
    }
}
