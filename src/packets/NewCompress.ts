import assert from "node:assert"

import { PacketNameToType } from "../constants.js"
import type Packet from "../packet.js"
import { readNextUint8 } from "../utils/Buffer.js"

export type NewCompressData = Record<never, never>

export default class NewCompress implements Packet {
    static type = PacketNameToType.SSH_MSG_NEWCOMPRESS

    readonly data: NewCompressData

    constructor(data: NewCompressData = {}) {
        assert(Object.keys(data).length === 0, "SSH NEWCOMPRESS does not accept fields")
        this.data = {}
    }

    serialize(): Buffer {
        return Buffer.from([NewCompress.type])
    }

    static parse(raw: Buffer): NewCompress {
        let packetType: number
        ;[packetType, raw] = readNextUint8(raw)
        assert(packetType === NewCompress.type)
        assert(raw.length === 0, "Unexpected data after SSH NEWCOMPRESS")
        return new NewCompress()
    }
}
