import assert from "assert"
import { PacketNameToType } from "../constants.js"
import Packet from "../packet.js"
import { readNextUint8 } from "../utils/Buffer.js"

export type NewKeysData = Record<never, never>
export default class NewKeys implements Packet {
    static type = PacketNameToType.SSH_MSG_NEWKEYS

    data: NewKeysData
    constructor(data: NewKeysData) {
        this.data = data
    }

    serialize(): Buffer {
        return Buffer.from([NewKeys.type])
    }

    static parse(raw: Buffer): NewKeys {
        let packetType: number
        ;[packetType, raw] = readNextUint8(raw)
        assert(packetType === NewKeys.type)

        assert(raw.length === 0)

        return new NewKeys({})
    }
}
