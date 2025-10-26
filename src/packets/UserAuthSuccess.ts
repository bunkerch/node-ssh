import assert from "assert"
import { PacketNameToType } from "../constants.js"
import Packet from "../packet.js"
import { readNextUint8, serializeUint8 } from "../utils/Buffer.js"

export type UserAuthSuccessData = Record<never, never>
export default class UserAuthSuccess implements Packet {
    static type = PacketNameToType.SSH_MSG_USERAUTH_SUCCESS

    data: UserAuthSuccessData
    constructor(data: UserAuthSuccessData) {
        this.data = data
    }

    serialize(): Buffer {
        return serializeUint8(UserAuthSuccess.type)
    }

    static parse(raw: Buffer): UserAuthSuccess {
        let packetType: number
        ;[packetType, raw] = readNextUint8(raw)
        assert(packetType === UserAuthSuccess.type)

        assert(raw.length === 0)

        return new UserAuthSuccess({})
    }
}
