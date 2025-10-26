import assert from "assert"
import { PacketNameToType } from "../constants.js"
import Packet from "../packet.js"
import { readNextUint32, readNextUint8, serializeUint32 } from "../utils/Buffer.js"

// https://datatracker.ietf.org/doc/html/rfc4254#section-5.2
export interface ChannelSuccessData {
    recipient_channel_id: number
}
export default class ChannelSuccess implements Packet {
    static type = PacketNameToType.SSH_MSG_CHANNEL_SUCCESS

    data: ChannelSuccessData
    constructor(data: ChannelSuccessData) {
        this.data = data
    }

    serialize(): Buffer {
        const buffers = []

        buffers.push(Buffer.from([ChannelSuccess.type]))

        buffers.push(serializeUint32(this.data.recipient_channel_id))

        return Buffer.concat(buffers)
    }

    static parse(raw: Buffer): ChannelSuccess {
        let packetType: number
        ;[packetType, raw] = readNextUint8(raw)
        assert(packetType === ChannelSuccess.type)

        let recipient_channel_id: number
        ;[recipient_channel_id, raw] = readNextUint32(raw)

        assert(raw.length === 0)

        return new ChannelSuccess({
            recipient_channel_id: recipient_channel_id,
        })
    }
}
