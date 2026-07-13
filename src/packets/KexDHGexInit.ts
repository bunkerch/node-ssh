import assert from "node:assert"
import { PacketNameToType } from "../constants.js"
import Packet from "../packet.js"
import { readNextBuffer, readNextUint8, serializeBuffer } from "../utils/Buffer.js"
import { serializeMpintBufferToBuffer } from "../utils/mpint.js"

export default class KexDHGexInit implements Packet {
    static type = PacketNameToType.SSH_MSG_KEX_DH_GEX_INIT

    constructor(readonly data: { e: Buffer }) {}

    serialize(): Buffer {
        return Buffer.concat([
            Buffer.from([KexDHGexInit.type]),
            serializeBuffer(serializeMpintBufferToBuffer(this.data.e)),
        ])
    }

    static parse(raw: Buffer): KexDHGexInit {
        let packetType: number
        ;[packetType, raw] = readNextUint8(raw)
        assert(packetType === KexDHGexInit.type)

        let e: Buffer
        ;[e, raw] = readNextBuffer(raw)
        assert(raw.length === 0)
        return new KexDHGexInit({ e })
    }
}
