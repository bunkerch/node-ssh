import assert from "node:assert"
import { PacketNameToType } from "../constants.js"
import Packet from "../packet.js"
import { readNextUint8, readNextUint32, serializeUint32 } from "../utils/Buffer.js"

export default class KexDHGexRequestOld implements Packet {
    // RFC 4419 assigns 30 in a KEX-specific namespace. It overlaps KEXDH_INIT.
    static type = PacketNameToType.SSH_MSG_KEXDH_INIT

    constructor(readonly data: { preferred: number }) {}

    serialize(): Buffer {
        return Buffer.concat([
            Buffer.from([KexDHGexRequestOld.type]),
            serializeUint32(this.data.preferred),
        ])
    }

    static parse(raw: Buffer): KexDHGexRequestOld {
        let packetType: number
        ;[packetType, raw] = readNextUint8(raw)
        assert(packetType === KexDHGexRequestOld.type)

        let preferred: number
        ;[preferred, raw] = readNextUint32(raw)
        assert(raw.length === 0)
        return new KexDHGexRequestOld({ preferred })
    }
}
