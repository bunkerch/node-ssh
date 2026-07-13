import assert from "assert"
import { PacketNameToType } from "../constants.js"
import Packet from "../packet.js"
import { serializeMpintBufferToBuffer } from "../utils/mpint.js"
import { readNextBuffer, readNextUint8, serializeBuffer } from "../utils/Buffer.js"

// Message 30 is RFC 4253 KEXDH_INIT or RFC 5656 KEX_ECDH_INIT, depending on negotiated KEX.
export interface KexDHInitData {
    e: Buffer
    encoding?: "mpint" | "string"
}
export default class KexDHInit implements Packet {
    static type = PacketNameToType.SSH_MSG_KEXDH_INIT

    data: KexDHInitData
    constructor(data: KexDHInitData) {
        this.data = data
    }

    serialize(): Buffer {
        const buffers = []

        buffers.push(Buffer.from([KexDHInit.type]))

        const e =
            this.data.encoding === "string"
                ? this.data.e
                : serializeMpintBufferToBuffer(this.data.e)
        buffers.push(serializeBuffer(e))

        return Buffer.concat(buffers)
    }

    static parse(raw: Buffer): KexDHInit {
        let packetType: number
        ;[packetType, raw] = readNextUint8(raw)
        assert(packetType === KexDHInit.type)

        let e: Buffer
        ;[e, raw] = readNextBuffer(raw)

        assert(raw.length === 0)

        return new KexDHInit({
            e,
        })
    }
}
