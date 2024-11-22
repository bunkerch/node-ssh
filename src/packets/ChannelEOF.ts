import assert from "assert"
import { SSHPacketType } from "../constants.js"
import Packet from "../packet.js"
import { readNextUint32, readNextUint8, serializeUint32 } from "../utils/Buffer.js"

// https://datatracker.ietf.org/doc/html/rfc4254#section-5.2
export interface ChannelEOFData {
    recipient_channel_id: number
}
export default class ChannelEOF implements Packet {
    static type = SSHPacketType.SSH_MSG_CHANNEL_EOF

    data: ChannelEOFData
    constructor(data: ChannelEOFData) {
        this.data = data
    }

    serialize(): Buffer {
        const buffers = []

        buffers.push(Buffer.from([ChannelEOF.type]))

        buffers.push(serializeUint32(this.data.recipient_channel_id))

        return Buffer.concat(buffers)
    }

    static parse(raw: Buffer): ChannelEOF {
        let packetType: number
        ;[packetType, raw] = readNextUint8(raw)
        assert(packetType === ChannelEOF.type)

        let recipient_channel_id: number
        ;[recipient_channel_id, raw] = readNextUint32(raw)

        assert(raw.length === 0)

        return new ChannelEOF({
            recipient_channel_id: recipient_channel_id,
        })
    }
}
