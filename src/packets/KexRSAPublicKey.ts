import assert from "node:assert"
import { PacketNameToType } from "../constants.js"
import type Packet from "../packet.js"
import { readNextBuffer, readNextUint8, serializeBuffer, serializeUint8 } from "../utils/Buffer.js"

export interface KexRSAPublicKeyData {
    hostKey: Buffer
    transientKey: Buffer
}

export default class KexRSAPublicKey implements Packet {
    static type = PacketNameToType.SSH_MSG_KEXDH_INIT
    readonly data: KexRSAPublicKeyData

    constructor(data: KexRSAPublicKeyData) {
        assert(data.hostKey.length > 0 && data.transientKey.length > 0)
        this.data = {
            hostKey: Buffer.from(data.hostKey),
            transientKey: Buffer.from(data.transientKey),
        }
    }

    serialize(): Buffer {
        return Buffer.concat([
            serializeUint8(KexRSAPublicKey.type),
            serializeBuffer(this.data.hostKey),
            serializeBuffer(this.data.transientKey),
        ])
    }

    static parse(raw: Buffer): KexRSAPublicKey {
        let type: number
        let hostKey: Buffer
        let transientKey: Buffer
        ;[type, raw] = readNextUint8(raw)
        assert(type === KexRSAPublicKey.type)
        ;[hostKey, raw] = readNextBuffer(raw)
        ;[transientKey, raw] = readNextBuffer(raw)
        assert(raw.length === 0)
        return new KexRSAPublicKey({ hostKey, transientKey })
    }
}
