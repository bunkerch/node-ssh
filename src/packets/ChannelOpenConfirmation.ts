import assert from "assert"
import { PacketNameToType } from "../constants.js"
import Packet from "../packet.js"
import { readNextUint32, readNextUint8, serializeUint32 } from "../utils/Buffer.js"

export interface ChannelOpenConfirmationData {
    recipient_channel_id: number
    sender_channel_id: number
    initial_window_size: number
    maximum_packet_size: number
    args: Buffer
}
export default class ChannelOpenConfirmation implements Packet {
    static type = PacketNameToType.SSH_MSG_CHANNEL_OPEN_CONFIRMATION

    data: ChannelOpenConfirmationData
    constructor(data: ChannelOpenConfirmationData) {
        this.data = data
    }

    serialize(): Buffer {
        const buffers = []

        buffers.push(Buffer.from([ChannelOpenConfirmation.type]))

        buffers.push(serializeUint32(this.data.recipient_channel_id))
        buffers.push(serializeUint32(this.data.sender_channel_id))
        buffers.push(serializeUint32(this.data.initial_window_size))
        buffers.push(serializeUint32(this.data.maximum_packet_size))
        buffers.push(this.data.args)

        return Buffer.concat(buffers)
    }

    static parse(raw: Buffer): ChannelOpenConfirmation {
        let packetType: number
        ;[packetType, raw] = readNextUint8(raw)
        assert(packetType === ChannelOpenConfirmation.type)

        let recipient_channel_id: number
        ;[recipient_channel_id, raw] = readNextUint32(raw)

        let sender_channel_id: number
        ;[sender_channel_id, raw] = readNextUint32(raw)

        let initial_window_size: number
        ;[initial_window_size, raw] = readNextUint32(raw)

        let maximum_packet_size: number
        ;[maximum_packet_size, raw] = readNextUint32(raw)

        return new ChannelOpenConfirmation({
            recipient_channel_id: recipient_channel_id,
            sender_channel_id: sender_channel_id,
            initial_window_size: initial_window_size,
            maximum_packet_size: maximum_packet_size,
            args: raw,
        })
    }
}
