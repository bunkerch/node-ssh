import assert from "assert"
import { SSHPacketType } from "../constants.js"
import Packet from "../packet.js"
import { readNextUint8, serializeUint8 } from "../utils/Buffer.js"

export interface UserAuthSuccessData {}
export default class UserAuthSuccess implements Packet {
    static type = SSHPacketType.SSH_MSG_USERAUTH_SUCCESS

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
