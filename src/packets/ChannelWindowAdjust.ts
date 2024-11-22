import assert from "assert"
import { SSHPacketType } from "../constants.js"
import Packet from "../packet.js"
import { readNextUint32, readNextUint8, serializeUint32 } from "../utils/Buffer.js"

// https://datatracker.ietf.org/doc/html/rfc4254#section-5.2
export interface ChannelWindowAdjustData {
    recipient_channel_id: number
    bytes_to_add: number
}
export default class ChannelWindowAdjust implements Packet {
    static type = SSHPacketType.SSH_MSG_CHANNEL_WINDOW_ADJUST

    data: ChannelWindowAdjustData
    constructor(data: ChannelWindowAdjustData) {
        this.data = data
    }

    serialize(): Buffer {
        const buffers = []

        buffers.push(Buffer.from([ChannelWindowAdjust.type]))

        buffers.push(serializeUint32(this.data.recipient_channel_id))
        buffers.push(serializeUint32(this.data.bytes_to_add))

        return Buffer.concat(buffers)
    }

    static parse(raw: Buffer): ChannelWindowAdjust {
        let packetType: number
        ;[packetType, raw] = readNextUint8(raw)
        assert(packetType === ChannelWindowAdjust.type)

        let recipient_channel_id: number
        ;[recipient_channel_id, raw] = readNextUint32(raw)

        let bytes_to_add: number
        ;[bytes_to_add, raw] = readNextUint32(raw)

        assert(raw.length === 0)

        return new ChannelWindowAdjust({
            recipient_channel_id: recipient_channel_id,
            bytes_to_add: bytes_to_add,
        })
    }
}
