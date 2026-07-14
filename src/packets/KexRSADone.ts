import assert from "node:assert"
import { PacketNameToType } from "../constants.js"
import type Packet from "../packet.js"
import { readNextBuffer, readNextUint8, serializeBuffer, serializeUint8 } from "../utils/Buffer.js"

export default class KexRSADone implements Packet {
    static type = PacketNameToType.SSH_MSG_KEX_DH_GEX_INIT
    readonly data: Readonly<{ signature: Buffer }>

    constructor(data: { signature: Buffer }) {
        assert(data.signature.length > 0)
        this.data = Object.freeze({ signature: Buffer.from(data.signature) })
    }

    serialize(): Buffer {
        return Buffer.concat([
            serializeUint8(KexRSADone.type),
            serializeBuffer(this.data.signature),
        ])
    }

    static parse(raw: Buffer): KexRSADone {
        let type: number
        let signature: Buffer
        ;[type, raw] = readNextUint8(raw)
        assert(type === KexRSADone.type)
        ;[signature, raw] = readNextBuffer(raw)
        assert(raw.length === 0)
        return new KexRSADone({ signature })
    }
}
