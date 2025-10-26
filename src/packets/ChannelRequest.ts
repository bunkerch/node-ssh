import assert from "assert"
import { PacketNameToType } from "../constants.js"
import Packet from "../packet.js"
import {
    readNextBinaryBoolean,
    readNextBuffer,
    readNextUint32,
    readNextUint8,
    serializeBuffer,
    serializeUint32,
} from "../utils/Buffer.js"
import { serializeBinaryBoolean } from "../utils/BinaryBoolean.js"

// https://datatracker.ietf.org/doc/html/rfc4254#section-5.2
export interface ChannelRequestData {
    recipient_channel_id: number
    request_type: string
    want_reply: boolean
    args: Buffer
}
export default class ChannelRequest implements Packet {
    static type = PacketNameToType.SSH_MSG_CHANNEL_REQUEST

    data: ChannelRequestData
    constructor(data: ChannelRequestData) {
        this.data = data
    }

    serialize(): Buffer {
        const buffers = []

        buffers.push(Buffer.from([ChannelRequest.type]))

        buffers.push(serializeUint32(this.data.recipient_channel_id))
        buffers.push(serializeBuffer(Buffer.from(this.data.request_type, "ascii")))
        buffers.push(serializeBinaryBoolean(this.data.want_reply))
        buffers.push(this.data.args)

        return Buffer.concat(buffers)
    }

    static parse(raw: Buffer): ChannelRequest {
        let packetType: number
        ;[packetType, raw] = readNextUint8(raw)
        assert(packetType === ChannelRequest.type)

        let recipient_channel_id: number
        ;[recipient_channel_id, raw] = readNextUint32(raw)

        let request_type: Buffer
        ;[request_type, raw] = readNextBuffer(raw)

        let want_reply: boolean
        ;[want_reply, raw] = readNextBinaryBoolean(raw)

        return new ChannelRequest({
            recipient_channel_id: recipient_channel_id,
            request_type: request_type.toString("ascii"),
            want_reply: want_reply,
            args: raw,
        })
    }
}
