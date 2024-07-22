import assert from "assert"
import { SSHPacketType } from "../constants.js"
import Packet from "../packet.js"
import {
    readNextBinaryBoolean,
    readNextBuffer,
    readNextUint8,
    serializeBuffer,
} from "../utils/Buffer.js"
import { serializeBinaryBoolean } from "../utils/BinaryBoolean.js"

export interface DebugData {
    always_display: boolean
    message: string
    language_tag: string
}

export default class Debug implements Packet {
    static type = SSHPacketType.SSH_MSG_DEBUG

    data: DebugData
    constructor(data: DebugData) {
        this.data = data
    }

    serialize(): Buffer {
        const buffers = []

        buffers.push(Buffer.from([Debug.type]))

        buffers.push(serializeBinaryBoolean(this.data.always_display))
        buffers.push(serializeBuffer(Buffer.from(this.data.message, "utf8")))
        buffers.push(serializeBuffer(Buffer.from(this.data.language_tag, "utf8")))

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
            message: message.toString("utf8"),
            language_tag: language_tag.toString("utf8"),
        })
    }
}
