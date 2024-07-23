import assert from "assert"
import { SSHPacketType } from "../constants.js"
import Packet from "../packet.js"
import { readNextUint8 } from "../utils/Buffer.js"

// TODO: Request success might hold data, depending on the request.
// need to impl this.
export interface RequestSuccessData {
    args: Buffer
}
export default class RequestSuccess implements Packet {
    static type = SSHPacketType.SSH_MSG_REQUEST_SUCCESS

    data: RequestSuccessData
    constructor(data: RequestSuccessData) {
        this.data = data
    }

    serialize(): Buffer {
        const buffers = []

        buffers.push(Buffer.from([RequestSuccess.type]))
        buffers.push(this.data.args)

        return Buffer.concat(buffers)
    }

    static parse(raw: Buffer): RequestSuccess {
        let packetType: number
        ;[packetType, raw] = readNextUint8(raw)
        assert(packetType === RequestSuccess.type)

        return new RequestSuccess({
            args: raw,
        })
    }
}
