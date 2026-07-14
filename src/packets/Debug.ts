import assert from "assert"
import { PacketNameToType } from "../constants.js"
import Packet from "../packet.js"
import {
    readNextBinaryBoolean,
    readNextBuffer,
    readNextUint8,
    serializeBuffer,
} from "../utils/Buffer.js"
import { serializeBinaryBoolean } from "../utils/BinaryBoolean.js"
import {
    decodeSSHLanguageTag,
    decodeSSHUTF8,
    encodeSSHLanguageTag,
    encodeSSHUTF8,
} from "../utils/SSHText.js"

export interface DebugData {
    always_display: boolean
    message: string
    language_tag: string
}
export interface ProtocolDebugMessage {
    alwaysDisplay: boolean
    message: string
    languageTag: string
}

export function protocolDebugMessage(data: DebugData): Readonly<ProtocolDebugMessage> {
    return Object.freeze({
        alwaysDisplay: data.always_display,
        message: data.message,
        languageTag: data.language_tag,
    })
}
export default class Debug implements Packet {
    static type = PacketNameToType.SSH_MSG_DEBUG

    readonly data: Readonly<DebugData>
    constructor(data: DebugData) {
        encodeSSHUTF8(data.message, "SSH debug message")
        encodeSSHLanguageTag(data.language_tag)
        this.data = Object.freeze({ ...data })
    }

    serialize(): Buffer {
        const buffers = []

        buffers.push(Buffer.from([Debug.type]))

        buffers.push(serializeBinaryBoolean(this.data.always_display))
        buffers.push(serializeBuffer(encodeSSHUTF8(this.data.message, "SSH debug message")))
        buffers.push(serializeBuffer(encodeSSHLanguageTag(this.data.language_tag)))

        return Buffer.concat(buffers)
    }

    static parse(raw: Buffer): Debug {
        let packetType: number
        ;[packetType, raw] = readNextUint8(raw)
        assert(packetType === Debug.type)

        let always_display: boolean
        ;[always_display, raw] = readNextBinaryBoolean(raw)

        let message: Buffer
        ;[message, raw] = readNextBuffer(raw)

        let language_tag: Buffer
        ;[language_tag, raw] = readNextBuffer(raw)

        assert(raw.length === 0)

        return new Debug({
            always_display: always_display,
            message: decodeSSHUTF8(message, "SSH debug message"),
            language_tag: decodeSSHLanguageTag(language_tag),
        })
    }
}
