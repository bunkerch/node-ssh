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
import {
    decodeSSHLanguageTag,
    decodeSSHUTF8,
    encodeSSHLanguageTag,
    encodeSSHUTF8,
} from "../utils/SSHText.js"

export enum ChannelOpenFailureReasonCodes {
    SSH_OPEN_ADMINISTRATIVELY_PROHIBITED = 1,
    SSH_OPEN_CONNECT_FAILED = 2,
    SSH_OPEN_UNKNOWN_CHANNEL_TYPE = 3,
    SSH_OPEN_RESOURCE_SHORTAGE = 4,
}

export interface ChannelOpenFailureData {
    recipient_channel_id: number
    reason_code: number
    description: string
    language_tag: string
}
export default class ChannelOpenFailure implements Packet {
    static type = PacketNameToType.SSH_MSG_CHANNEL_OPEN_FAILURE

    data: ChannelOpenFailureData
    constructor(data: ChannelOpenFailureData) {
        this.data = {
            recipient_channel_id: data.recipient_channel_id,
            reason_code: data.reason_code,
            description: data.description,
            language_tag: data.language_tag,
        }
    }

    serialize(): Buffer {
        const buffers = []

        buffers.push(Buffer.from([ChannelOpenFailure.type]))

        buffers.push(serializeUint32(this.data.recipient_channel_id))
        buffers.push(serializeUint32(this.data.reason_code))
        buffers.push(
            serializeBuffer(encodeSSHUTF8(this.data.description, "SSH channel-open description")),
        )
        buffers.push(serializeBuffer(encodeSSHLanguageTag(this.data.language_tag)))

        return Buffer.concat(buffers)
    }

    static parse(raw: Buffer): ChannelOpenFailure {
        let packetType: number
        ;[packetType, raw] = readNextUint8(raw)
        assert(packetType === ChannelOpenFailure.type)

        let recipientChannelId: number
        ;[recipientChannelId, raw] = readNextUint32(raw)

        let reasonCode: number
        ;[reasonCode, raw] = readNextUint32(raw)

        let description: Buffer
        ;[description, raw] = readNextBuffer(raw)

        let languageTag: Buffer
        ;[languageTag, raw] = readNextBuffer(raw)

        assert(raw.length === 0)

        return new ChannelOpenFailure({
            recipient_channel_id: recipientChannelId,
            reason_code: reasonCode,
            description: decodeSSHUTF8(description, "SSH channel-open description"),
            language_tag: decodeSSHLanguageTag(languageTag),
        })
    }
}

export class ChannelOpenError extends Error {
    readonly name = "ChannelOpenError"
    readonly reasonCode: number
    readonly reason_code: number
    readonly languageTag: string

    constructor(reasonCode: number, message: string, languageTag = "") {
        super(message)
        if (!Number.isInteger(reasonCode) || reasonCode < 0 || reasonCode > 0xffff_ffff) {
            throw new RangeError("SSH channel-open failure reason must be a uint32")
        }
        encodeSSHUTF8(message, "SSH channel-open description")
        encodeSSHLanguageTag(languageTag, "SSH channel-open language tag")
        this.reasonCode = reasonCode
        this.reason_code = reasonCode
        this.languageTag = languageTag
    }

    getOpenFailurePacket(recipientChannelId: number): ChannelOpenFailure {
        return new ChannelOpenFailure({
            reason_code: this.reason_code,
            description: this.message,
            language_tag: this.languageTag,
            recipient_channel_id: recipientChannelId,
        })
    }
}
