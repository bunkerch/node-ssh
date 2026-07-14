import assert from "node:assert"
import { PacketNameToType } from "../constants.js"
import type Packet from "../packet.js"
import { readNextBuffer, readNextUint8, serializeBuffer, serializeUint8 } from "../utils/Buffer.js"

export default class KexRSASecret implements Packet {
    static type = PacketNameToType.SSH_MSG_KEXDH_REPLY
    readonly data: Readonly<{ encryptedSecret: Buffer }>

    constructor(data: { encryptedSecret: Buffer }) {
        assert(data.encryptedSecret.length > 0)
        this.data = Object.freeze({ encryptedSecret: Buffer.from(data.encryptedSecret) })
    }

    serialize(): Buffer {
        return Buffer.concat([
            serializeUint8(KexRSASecret.type),
            serializeBuffer(this.data.encryptedSecret),
        ])
    }

    static parse(raw: Buffer): KexRSASecret {
        let type: number
        let encryptedSecret: Buffer
        ;[type, raw] = readNextUint8(raw)
        assert(type === KexRSASecret.type)
        ;[encryptedSecret, raw] = readNextBuffer(raw)
        assert(raw.length === 0)
        return new KexRSASecret({ encryptedSecret })
    }
}
