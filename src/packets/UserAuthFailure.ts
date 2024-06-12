import assert from "assert"
import { SSHPacketType } from "../constants.js"
import Packet from "../packet.js"
import { readNextBinaryBoolean, readNextUint8, serializeUint8 } from "../utils/Buffer.js"
import { readNextNameList, serializeNameList } from "../utils/NameList.js"
import { serializeBinaryBoolean } from "../utils/BinaryBoolean.js"

export interface UserAuthFailureData {
    auth_methods: string[]
    partial_success: boolean
}
export default class UserAuthFailure implements Packet {
    static type = SSHPacketType.SSH_MSG_USERAUTH_FAILURE

    data: UserAuthFailureData
    constructor(data: UserAuthFailureData) {
        this.data = data
    }

    serialize(): Buffer {
        const buffers = []

        buffers.push(serializeUint8(UserAuthFailure.type))

        buffers.push(serializeNameList(this.data.auth_methods))
        buffers.push(serializeBinaryBoolean(this.data.partial_success))

        return Buffer.concat(buffers)
    }

    static parse(raw: Buffer): UserAuthFailure {
        let packetType: number
        ;[packetType, raw] = readNextUint8(raw)
        assert(packetType === UserAuthFailure.type)

        let auth_methods: string[]
        ;[auth_methods, raw] = readNextNameList(raw)

        let partial_success: boolean
        ;[partial_success, raw] = readNextBinaryBoolean(raw)

        assert(raw.length === 0)

        return new UserAuthFailure({
            auth_methods: auth_methods,
            partial_success: partial_success,
        })
    }
}
