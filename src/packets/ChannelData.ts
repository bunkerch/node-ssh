import assert from "assert"
import { SSHPacketType } from "../constants.js"
import Packet from "../packet.js"
import {
    readNextBuffer,
    readNextUint32,
    readNextUint8,
    serializeBuffer,
    serializeUint32,
} from "../utils/Buffer.js"

// https://datatracker.ietf.org/doc/html/rfc4254#section-5.2
export interface ChannelDataData {
    recipient_channel_id: number
    data: Buffer
}
export default class ChannelData implements Packet {
    static type = SSHPacketType.SSH_MSG_CHANNEL_DATA

    data: ChannelDataData
    constructor(data: ChannelDataData) {
        this.data = data
    }

    serialize(): Buffer {
        const buffers = []

        buffers.push(Buffer.from([ChannelData.type]))

        buffers.push(serializeUint32(this.data.recipient_channel_id))
        buffers.push(serializeBuffer(this.data.data))

        return Buffer.concat(buffers)
    }

    static parse(raw: Buffer): ChannelData {
        let packetType: number
        ;[packetType, raw] = readNextUint8(raw)
        assert(packetType === ChannelData.type)

        let recipient_channel_id: number
        ;[recipient_channel_id, raw] = readNextUint32(raw)

        let data: Buffer
        ;[data, raw] = readNextBuffer(raw)

        assert(raw.length === 0)

        return new ChannelData({
            recipient_channel_id: recipient_channel_id,
            data: data,
        })
    }
}
