import assert from "node:assert"
import { PacketNameToType } from "../constants.js"
import Packet from "../packet.js"
import { readNextBuffer, readNextUint8, serializeBuffer } from "../utils/Buffer.js"
import { serializeMpintBufferToBuffer } from "../utils/mpint.js"

export interface KexDHGexReplyData {
    K_S: Buffer
    f: Buffer
    H_sig: Buffer
}

export default class KexDHGexReply implements Packet {
    static type = PacketNameToType.SSH_MSG_KEX_DH_GEX_REPLY

    readonly data: KexDHGexReplyData

    constructor(data: KexDHGexReplyData) {
        this.data = {
            K_S: Buffer.from(data.K_S),
            f: Buffer.from(data.f),
            H_sig: Buffer.from(data.H_sig),
        }
    }

    serialize(): Buffer {
        return Buffer.concat([
            Buffer.from([KexDHGexReply.type]),
            serializeBuffer(this.data.K_S),
            serializeBuffer(serializeMpintBufferToBuffer(this.data.f)),
            serializeBuffer(this.data.H_sig),
        ])
    }

    static parse(raw: Buffer): KexDHGexReply {
        let packetType: number
        ;[packetType, raw] = readNextUint8(raw)
        assert(packetType === KexDHGexReply.type)

        let K_S: Buffer
        let f: Buffer
        let H_sig: Buffer
        ;[K_S, raw] = readNextBuffer(raw)
        ;[f, raw] = readNextBuffer(raw)
        ;[H_sig, raw] = readNextBuffer(raw)
        assert(raw.length === 0)

        return new KexDHGexReply({ K_S, f, H_sig })
    }
}
