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

export interface GlobalRequestData {
    request_name: string
    want_reply: boolean
    args: Buffer
}
export default class GlobalRequest implements Packet {
    static type = SSHPacketType.SSH_MSG_GLOBAL_REQUEST

    data: GlobalRequestData
    constructor(data: GlobalRequestData) {
        this.data = data
    }

    serialize(): Buffer {
        const buffers = []

        buffers.push(Buffer.from([GlobalRequest.type]))

        buffers.push(serializeBuffer(Buffer.from(this.data.request_name, "ascii")))
        buffers.push(serializeBinaryBoolean(this.data.want_reply))

        buffers.push(serializeBuffer(this.data.args))

        return Buffer.concat(buffers)
    }

    static parse(raw: Buffer): GlobalRequest {
        let packetType: number
        ;[packetType, raw] = readNextUint8(raw)
        assert(packetType === GlobalRequest.type)

        let request_name: Buffer
        ;[request_name, raw] = readNextBuffer(raw)

        let want_reply: boolean
        ;[want_reply, raw] = readNextBinaryBoolean(raw)

        return new GlobalRequest({
            request_name: request_name.toString("ascii"),
            want_reply: want_reply,
            args: raw,
        })
    }
}
