import assert from "assert"
import { PacketNameToType } from "../constants.js"
import Packet from "../packet.js"
import { readNextBuffer, readNextUint8, serializeBuffer } from "../utils/Buffer.js"
import { serializeMpintBufferToBuffer } from "../utils/mpint.js"

// Message 31 is RFC 4253 KEXDH_REPLY or RFC 5656 KEX_ECDH_REPLY, depending on negotiated KEX.
export interface KexDHReplyData {
    K_S: Buffer
    f: Buffer
    H_sig: Buffer
    encoding?: "mpint" | "string"
}
export default class KexDHReply implements Packet {
    static type = PacketNameToType.SSH_MSG_KEXDH_REPLY

    data: KexDHReplyData
    constructor(data: KexDHReplyData) {
        this.data = {
            K_S: Buffer.from(data.K_S),
            f: Buffer.from(data.f),
            H_sig: Buffer.from(data.H_sig),
            encoding: data.encoding,
        }
    }

    serialize(): Buffer {
        const buffers = []

        buffers.push(Buffer.from([KexDHReply.type]))

        buffers.push(serializeBuffer(this.data.K_S))
        const f =
            this.data.encoding === "string"
                ? this.data.f
                : serializeMpintBufferToBuffer(this.data.f)
        buffers.push(serializeBuffer(f))
        buffers.push(serializeBuffer(this.data.H_sig))

        return Buffer.concat(buffers)
    }

    static parse(raw: Buffer): KexDHReply {
        let packetType: number
        ;[packetType, raw] = readNextUint8(raw)
        assert(packetType === KexDHReply.type)

        let K_S: Buffer
        ;[K_S, raw] = readNextBuffer(raw)

        let f: Buffer
        ;[f, raw] = readNextBuffer(raw)

        let H_sig: Buffer
        ;[H_sig, raw] = readNextBuffer(raw)

        assert(raw.length === 0)

        return new KexDHReply({
            K_S: K_S,
            f,
            H_sig: H_sig,
        })
    }
}
