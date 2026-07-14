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
    reason_code: number
    description: string
    language_tag: string
}

export interface PeerDisconnectInfo {
    readonly reasonCode: number
    readonly description: string
    readonly languageTag: string
}

export function peerDisconnectInfo(data: DisconnectData): Readonly<PeerDisconnectInfo> {
    return Object.freeze({
        reasonCode: data.reason_code,
        description: data.description,
        languageTag: data.language_tag,
    })
}
export default class Disconnect implements Packet {
    static type = PacketNameToType.SSH_MSG_DISCONNECT

    data: DisconnectData
    constructor(data: DisconnectData) {
        this.data = data
    }

    serialize(): Buffer {
        const buffers = []

        buffers.push(Buffer.from([Disconnect.type]))

        if (
            !Number.isInteger(this.data.reason_code) ||
            this.data.reason_code < 0 ||
            this.data.reason_code > 0xffff_ffff
        ) {
            throw new RangeError("SSH disconnect reason must be a uint32")
        }
        buffers.push(serializeUint32(this.data.reason_code))

        buffers.push(
            serializeBuffer(encodeSSHUTF8(this.data.description, "SSH disconnect description")),
        )

        buffers.push(serializeBuffer(encodeSSHLanguageTag(this.data.language_tag)))

        return Buffer.concat(buffers)
    }

    static parse(raw: Buffer): Disconnect {
        let packetType: number
        ;[packetType, raw] = readNextUint8(raw)
        assert(packetType === Disconnect.type)

        let reason_code: number
        ;[reason_code, raw] = readNextUint32(raw)

        let description: Buffer
        ;[description, raw] = readNextBuffer(raw)

        let language_tag: Buffer
        ;[language_tag, raw] = readNextBuffer(raw)

        assert(raw.length === 0)

        return new Disconnect({
            reason_code,
            description: decodeSSHUTF8(description, "SSH disconnect description"),
            language_tag: decodeSSHLanguageTag(language_tag),
        })
    }
}

export class DisconnectError extends Error {
    name = "DisconnectError"
    reason_code: DisconnectReason

    constructor(reason_code: DisconnectReason, message: string) {
        super(message)
        this.reason_code = reason_code
    }
}

export class ProtocolError extends DisconnectError {
    readonly name = "ProtocolError"

    constructor(message: string) {
        super(DisconnectReason.SSH_DISCONNECT_PROTOCOL_ERROR, message)
    }
}

export class PeerDisconnectError extends Error {
    readonly name = "PeerDisconnectError"
    readonly reasonCode: number
    readonly languageTag: string

    constructor(readonly disconnect: Readonly<PeerDisconnectInfo>) {
        super(disconnect.description || `SSH peer disconnected (reason ${disconnect.reasonCode})`)
        this.reasonCode = disconnect.reasonCode
        this.languageTag = disconnect.languageTag
    }
}
