import assert from "assert"
import { SSHPacketType } from "../constants.js"
import Packet from "../packet.js"
import { readNextUint32, readNextUint8, serializeUint32 } from "../utils/Buffer.js"

export interface UnimplementedData {
    sequence_number: number
}

export default class Unimplemented implements Packet {
    static type = SSHPacketType.SSH_MSG_UNIMPLEMENTED

    data: UnimplementedData
    constructor(data: UnimplementedData) {
        this.data = data
    }

    serialize(): Buffer {
        const buffers = []

        buffers.push(Buffer.from([Unimplemented.type]))

        buffers.push(serializeUint32(this.data.sequence_number))

        return Buffer.concat(buffers)
    }

    static parse(raw: Buffer): Unimplemented {
        let packetType: number
        ;[packetType, raw] = readNextUint8(raw)
        assert(packetType === Unimplemented.type)

        let sequence_number: number
        ;[sequence_number, raw] = readNextUint32(raw)

        assert(raw.length === 0)

        return new Unimplemented({
            sequence_number: sequence_number,
        })
    }
}
