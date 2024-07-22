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

export interface ChannelOpenData {
    channel_type: string
    sender_channel_id: number
    initial_window_size: number
    maximum_packet_size: number
    args: Buffer
}
export default class ChannelOpen implements Packet {
    static type = SSHPacketType.SSH_MSG_CHANNEL_OPEN

    data: ChannelOpenData
    constructor(data: ChannelOpenData) {
        this.data = data
    }

    serialize(): Buffer {
        const buffers = []

        buffers.push(Buffer.from([ChannelOpen.type]))

        buffers.push(serializeBuffer(Buffer.from(this.data.channel_type, "ascii")))
        buffers.push(serializeUint32(this.data.sender_channel_id))
        buffers.push(serializeUint32(this.data.initial_window_size))
        buffers.push(serializeUint32(this.data.maximum_packet_size))
        buffers.push(this.data.args)

        return Buffer.concat(buffers)
    }

    static parse(raw: Buffer): ChannelOpen {
        let packetType: number
        ;[packetType, raw] = readNextUint8(raw)
        assert(packetType === ChannelOpen.type)

        let channel_type: Buffer
        ;[channel_type, raw] = readNextBuffer(raw)

        let sender_channel_id: number
        ;[sender_channel_id, raw] = readNextUint32(raw)

        let initial_window_size: number
        ;[initial_window_size, raw] = readNextUint32(raw)

        let maximum_packet_size: number
        ;[maximum_packet_size, raw] = readNextUint32(raw)

        return new ChannelOpen({
            channel_type: channel_type.toString("ascii"),
            sender_channel_id: sender_channel_id,
            initial_window_size: initial_window_size,
            maximum_packet_size: maximum_packet_size,
            args: raw,
        })
    }
}
