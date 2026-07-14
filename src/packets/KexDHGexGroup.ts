import assert from "node:assert"
import { PacketNameToType } from "../constants.js"
import Packet from "../packet.js"
import { readNextBuffer, readNextUint8, serializeBuffer } from "../utils/Buffer.js"
import { serializeMpintBufferToBuffer } from "../utils/mpint.js"

export interface KexDHGexGroupData {
    p: Buffer
    g: Buffer
}

export default class KexDHGexGroup implements Packet {
    // RFC 4419 assigns 31 in a KEX-specific namespace. It overlaps KEXDH_REPLY.
    static type = PacketNameToType.SSH_MSG_KEXDH_REPLY

    readonly data: KexDHGexGroupData

    constructor(data: KexDHGexGroupData) {
        this.data = { p: Buffer.from(data.p), g: Buffer.from(data.g) }
    }

    serialize(): Buffer {
        return Buffer.concat([
            Buffer.from([KexDHGexGroup.type]),
            serializeBuffer(serializeMpintBufferToBuffer(this.data.p)),
            serializeBuffer(serializeMpintBufferToBuffer(this.data.g)),
        ])
    }

    static parse(raw: Buffer): KexDHGexGroup {
        let packetType: number
        ;[packetType, raw] = readNextUint8(raw)
        assert(packetType === KexDHGexGroup.type)

        let p: Buffer
        let g: Buffer
        ;[p, raw] = readNextBuffer(raw)
        ;[g, raw] = readNextBuffer(raw)
        assert(raw.length === 0)

        return new KexDHGexGroup({ p, g })
    }
}
