import assert from "assert";
import { SSHPacketType } from "../constants.js";
import Packet from "../packet.js";
import { parseBufferToMpintBuffer, serializeMpintBufferToBuffer } from "../utils/mpint.js";
import { readNextBuffer, readNextUint8 } from "../utils/Buffer.js";

export interface KexDHInitData {
    e: Buffer
}
export default class KexDHInit implements Packet {
    static type = SSHPacketType.SSH_MSG_KEXDH_INIT

    data: KexDHInitData
    constructor(data: KexDHInitData) {
        this.data = data
    }

    serialize(): Buffer {
        const buffers = []

        buffers.push(Buffer.from([KexDHInit.type]))
        
        const e = serializeMpintBufferToBuffer(this.data.e)
        const eLength = Buffer.allocUnsafe(4)
        eLength.writeUInt32BE(e.length)
        buffers.push(eLength)
        buffers.push(e)

        return Buffer.concat(buffers)
    }
    
    static parse(raw: Buffer): KexDHInit {
        let packetType: number
        [packetType, raw] = readNextUint8(raw)
        assert(packetType === KexDHInit.type)
        
        let e: Buffer
        [e, raw] = readNextBuffer(raw)

        assert(raw.length === 0)
        
        return new KexDHInit({
            e: parseBufferToMpintBuffer(e)
        })
    }
}