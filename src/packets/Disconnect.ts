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

export enum DisconnectReason {
    SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT = 1,
    SSH_DISCONNECT_PROTOCOL_ERROR = 2,
    SSH_DISCONNECT_KEY_EXCHANGE_FAILED = 3,
    SSH_DISCONNECT_RESERVED = 4,
    SSH_DISCONNECT_MAC_ERROR = 5,
    SSH_DISCONNECT_COMPRESSION_ERROR = 6,
    SSH_DISCONNECT_SERVICE_NOT_AVAILABLE = 7,
    SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED = 8,
    SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE = 9,
    SSH_DISCONNECT_CONNECTION_LOST = 10,
    SSH_DISCONNECT_BY_APPLICATION = 11,
    SSH_DISCONNECT_TOO_MANY_CONNECTIONS = 12,
    SSH_DISCONNECT_AUTH_CANCELLED_BY_USER = 13,
    SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE = 14,
    SSH_DISCONNECT_ILLEGAL_USER_NAME = 15,
}

export interface DisconnectData {
    reason_code: DisconnectReason
    description: string
    language_tag: string
}

export default class Disconnect implements Packet {
    static type = SSHPacketType.SSH_MSG_DISCONNECT

    data: DisconnectData
    constructor(data: DisconnectData) {
        this.data = data
    }

    serialize(): Buffer {
        const buffers = []

        buffers.push(Buffer.from([Disconnect.type]))

        buffers.push(serializeUint32(this.data.reason_code))

        buffers.push(serializeBuffer(Buffer.from(this.data.description, "utf-8")))

        buffers.push(serializeBuffer(Buffer.from(this.data.language_tag, "utf-8")))

        return Buffer.concat(buffers)
    }

    static parse(raw: Buffer): Disconnect {
        let packetType: number
        ;[packetType, raw] = readNextUint8(raw)
        assert(packetType === Disconnect.type)

        let reason_code: number
        ;[reason_code, raw] = readNextUint32(raw)
        assert(reason_code in DisconnectReason)

        let description: Buffer
        ;[description, raw] = readNextBuffer(raw)

        let language_tag: Buffer
        ;[language_tag, raw] = readNextBuffer(raw)

        assert(raw.length === 0)

        return new Disconnect({
            reason_code: reason_code as DisconnectReason,
            description: description.toString("utf-8"),
            language_tag: language_tag.toString("utf-8"),
        })
    }
}
