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

export enum ChannelOpenFailureReasonCodes {
    SSH_OPEN_ADMINISTRATIVELY_PROHIBITED = 1,
    SSH_OPEN_CONNECT_FAILED = 2,
    SSH_OPEN_UNKNOWN_CHANNEL_TYPE = 3,
    SSH_OPEN_RESOURCE_SHORTAGE = 4,
}

export interface ChannelOpenFailureData {
    recipient_channel_id: number
    reason_code: ChannelOpenFailureReasonCodes
    description: string
    language_tag: string
}
export default class ChannelOpenFailure implements Packet {
    static type = SSHPacketType.SSH_MSG_CHANNEL_OPEN_FAILURE

    data: ChannelOpenFailureData
    constructor(data: ChannelOpenFailureData) {
        this.data = data
    }

    serialize(): Buffer {
        const buffers = []

        buffers.push(Buffer.from([ChannelOpenFailure.type]))

        buffers.push(serializeUint32(this.data.recipient_channel_id))
        buffers.push(serializeUint32(this.data.reason_code))
        buffers.push(serializeBuffer(Buffer.from(this.data.description, "utf8")))
        buffers.push(serializeBuffer(Buffer.from(this.data.language_tag, "utf8")))

        return Buffer.concat(buffers)
    }

    static parse(raw: Buffer): ChannelOpenFailure {
        let packetType: number
        ;[packetType, raw] = readNextUint8(raw)
        assert(packetType === ChannelOpenFailure.type)

        let recipientChannelId: number
        ;[recipientChannelId, raw] = readNextUint32(raw)

        let reasonCode: ChannelOpenFailureReasonCodes
        ;[reasonCode, raw] = readNextUint32(raw)

        let description: Buffer
        ;[description, raw] = readNextBuffer(raw)

        let languageTag: Buffer
        ;[languageTag, raw] = readNextBuffer(raw)

        assert(raw.length === 0)

        return new ChannelOpenFailure({
            recipient_channel_id: recipientChannelId,
            reason_code: reasonCode,
            description: description.toString("utf8"),
            language_tag: languageTag.toString("utf8"),
        })
    }
}

export class ChannelOpenError extends Error {
    name = "ChannelOpenError"

    reason_code: ChannelOpenFailureReasonCodes
    recipient_channel_id: number

    constructor(
        reason_code: ChannelOpenFailureReasonCodes,
        recipient_channel_id: number,
        message: string,
    ) {
        super(message)
        this.reason_code = reason_code
        this.recipient_channel_id = recipient_channel_id
    }

    getOpenFailurePacket() {
        return new ChannelOpenFailure({
            reason_code: this.reason_code,
            description: this.message,
            language_tag: "",
            recipient_channel_id: this.recipient_channel_id,
        })
    }
}
