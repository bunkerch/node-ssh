import assert from "assert";
import { SSHPacketType } from "../constants.js";
import Packet from "../packet.js";
import { readNextUint8 } from "../utils/Buffer.js";

export interface NewKeysData {}
export default class NewKeys implements Packet {
    static type = SSHPacketType.SSH_MSG_NEWKEYS

    data: NewKeysData
    constructor(data: NewKeysData) {
        this.data = data
    }

    serialize(): Buffer {
        const buffers = []

        buffers.push(Buffer.from([NewKeys.type]))

        return Buffer.concat(buffers)
    }
    
    static parse(raw: Buffer): NewKeys {
        let packetType: number
        [packetType, raw] = readNextUint8(raw)
        assert(packetType === NewKeys.type)

        assert(raw.length === 0)
        
        return new NewKeys({})
    }
}