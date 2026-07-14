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
import { decodeSSHName, encodeSSHName } from "../utils/SSHName.js"

export interface GlobalRequestData {
    request_name: string
    want_reply: boolean
    args: Buffer
}
export default class GlobalRequest implements Packet {
    static type = PacketNameToType.SSH_MSG_GLOBAL_REQUEST

    data: GlobalRequestData
    constructor(data: GlobalRequestData) {
        this.data = {
            request_name: data.request_name,
            want_reply: data.want_reply,
            args: Buffer.from(data.args),
        }
    }

    serialize(): Buffer {
        const buffers = []

        buffers.push(Buffer.from([GlobalRequest.type]))

        buffers.push(
            serializeBuffer(encodeSSHName(this.data.request_name, "SSH global request name")),
        )
        buffers.push(serializeBinaryBoolean(this.data.want_reply))

        buffers.push(this.data.args)

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
            request_name: decodeSSHName(request_name, "SSH global request name"),
            want_reply: want_reply,
            args: raw,
        })
    }
}
