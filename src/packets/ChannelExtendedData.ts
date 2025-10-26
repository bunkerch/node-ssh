import assert from "assert"
import { PacketNameToType } from "../constants.js"
import Packet from "../packet.js"
import {
    readNextBuffer,
    readNextUint32,
    readNextUint8,
    serializeBuffer,
    serializeUint32,
} from "../utils/Buffer.js"

// https://datatracker.ietf.org/doc/html/rfc4254#section-5.2
export interface ChannelExtendedDataData {
    recipient_channel_id: number
    data_type_code: number
    data: Buffer
}
export default class ChannelExtendedData implements Packet {
    static type = PacketNameToType.SSH_MSG_CHANNEL_EXTENDED_DATA

    data: ChannelExtendedDataData
    constructor(data: ChannelExtendedDataData) {
        this.data = data
    }

    serialize(): Buffer {
        const buffers = []

        buffers.push(Buffer.from([ChannelExtendedData.type]))

        buffers.push(serializeUint32(this.data.recipient_channel_id))
        buffers.push(serializeUint32(this.data.data_type_code))
        buffers.push(serializeBuffer(this.data.data))

        return Buffer.concat(buffers)
    }

    static parse(raw: Buffer): ChannelExtendedData {
        let packetType: number
        ;[packetType, raw] = readNextUint8(raw)
        assert(packetType === ChannelExtendedData.type)

        let recipient_channel_id: number
        ;[recipient_channel_id, raw] = readNextUint32(raw)

        let data_type_code: number
        ;[data_type_code, raw] = readNextUint32(raw)

        let data: Buffer
        ;[data, raw] = readNextBuffer(raw)

        assert(raw.length === 0)

        return new ChannelExtendedData({
            recipient_channel_id: recipient_channel_id,
            data_type_code: data_type_code,
            data: data,
        })
    }
}
