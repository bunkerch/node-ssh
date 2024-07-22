import assert from "assert"
import { SSHPacketType } from "../constants.js"
import Packet from "../packet.js"
import { readNextUint8 } from "../utils/Buffer.js"

export interface RequestFailureData {}
export default class RequestFailure implements Packet {
    static type = SSHPacketType.SSH_MSG_REQUEST_FAILURE

    data: RequestFailureData
    constructor(data: RequestFailureData) {
        this.data = data
    }

    serialize(): Buffer {
        const buffers = []

        buffers.push(Buffer.from([RequestFailure.type]))

        return Buffer.concat(buffers)
    }

    static parse(raw: Buffer): RequestFailure {
        let packetType: number
        ;[packetType, raw] = readNextUint8(raw)
        assert(packetType === RequestFailure.type)

        assert(raw.length === 0)

        return new RequestFailure({})
    }
}
