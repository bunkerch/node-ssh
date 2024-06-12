import assert from "assert"
import { SSHPacketType } from "../constants.js"
import Packet from "../packet.js"
import { readNextBuffer, readNextUint8 } from "../utils/Buffer.js"

// https://datatracker.ietf.org/doc/html/rfc4253#section-8
export interface KexDHReplyData {
    K_S: Buffer
    f: Buffer
    H_sig: Buffer
}
export default class KexDHReply implements Packet {
    static type = SSHPacketType.SSH_MSG_KEXDH_REPLY

    data: KexDHReplyData
    constructor(data: KexDHReplyData) {
        this.data = data
    }

    serialize(): Buffer {
        const buffers = []

        buffers.push(Buffer.from([KexDHReply.type]))

        const K_SLength = Buffer.allocUnsafe(4)
        K_SLength.writeUInt32BE(this.data.K_S.length)
        buffers.push(K_SLength)
        buffers.push(this.data.K_S)

        const fLength = Buffer.allocUnsafe(4)
        fLength.writeUInt32BE(this.data.f.length)
        buffers.push(fLength)
        buffers.push(this.data.f)

        const H_sigLength = Buffer.allocUnsafe(4)
        H_sigLength.writeUInt32BE(this.data.H_sig.length)
        buffers.push(H_sigLength)
        buffers.push(this.data.H_sig)

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
            f: f,
            H_sig: H_sig,
        })
    }
}
