import assert from "node:assert"
import { PacketNameToType } from "../constants.js"
import Packet from "../packet.js"
import { readNextUint8, readNextUint32, serializeUint32 } from "../utils/Buffer.js"

export interface KexDHGexRequestData {
    min: number
    preferred: number
    max: number
}

export default class KexDHGexRequest implements Packet {
    static type = PacketNameToType.SSH_MSG_KEX_DH_GEX_REQUEST

    constructor(readonly data: KexDHGexRequestData) {}

    serialize(): Buffer {
        return Buffer.concat([
            Buffer.from([KexDHGexRequest.type]),
            serializeUint32(this.data.min),
            serializeUint32(this.data.preferred),
            serializeUint32(this.data.max),
        ])
    }

    static parse(raw: Buffer): KexDHGexRequest {
        let packetType: number
        ;[packetType, raw] = readNextUint8(raw)
        assert(packetType === KexDHGexRequest.type)

        let min: number
        let preferred: number
        let max: number
        ;[min, raw] = readNextUint32(raw)
        ;[preferred, raw] = readNextUint32(raw)
        ;[max, raw] = readNextUint32(raw)
        assert(raw.length === 0)

        return new KexDHGexRequest({ min, preferred, max })
    }
}
