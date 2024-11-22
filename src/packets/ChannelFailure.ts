import assert from "assert"
import { SSHPacketType } from "../constants.js"
import Packet from "../packet.js"
import { readNextUint32, readNextUint8, serializeUint32 } from "../utils/Buffer.js"

// https://datatracker.ietf.org/doc/html/rfc4254#section-5.2
export interface ChannelFailureData {
    recipient_channel_id: number
}
export default class ChannelFailure implements Packet {
    static type = SSHPacketType.SSH_MSG_CHANNEL_FAILURE

    data: ChannelFailureData
    constructor(data: ChannelFailureData) {
        this.data = data
    }

    serialize(): Buffer {
        const buffers = []

        buffers.push(Buffer.from([ChannelFailure.type]))

        buffers.push(serializeUint32(this.data.recipient_channel_id))

        return Buffer.concat(buffers)
    }

    static parse(raw: Buffer): ChannelFailure {
        let packetType: number
        ;[packetType, raw] = readNextUint8(raw)
        assert(packetType === ChannelFailure.type)

        let recipient_channel_id: number
        ;[recipient_channel_id, raw] = readNextUint32(raw)

        assert(raw.length === 0)

        return new ChannelFailure({
            recipient_channel_id: recipient_channel_id,
        })
    }
}
