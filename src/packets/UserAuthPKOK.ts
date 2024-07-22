import assert from "assert"
import { SSHPacketType } from "../constants.js"
import Packet from "../packet.js"
import { readNextBuffer, readNextUint8, serializeBuffer, serializeUint8 } from "../utils/Buffer.js"
import PublicKey from "../utils/PublicKey.js"

export interface UserAuthPKOKData {
    publicKey: PublicKey
}
export default class UserAuthPKOK implements Packet {
    static type = SSHPacketType.SSH_MSG_USERAUTH_PK_OK

    data: UserAuthPKOKData
    constructor(data: UserAuthPKOKData) {
        this.data = data
    }

    serialize(): Buffer {
        const buffers = []

        buffers.push(serializeUint8(UserAuthPKOK.type))

        buffers.push(serializeBuffer(Buffer.from(this.data.publicKey.data.alg, "utf-8")))
        buffers.push(serializeBuffer(this.data.publicKey.serialize()))

        return Buffer.concat(buffers)
    }

    static parse(raw: Buffer): UserAuthPKOK {
        let packetType: number
        ;[packetType, raw] = readNextUint8(raw)
        assert(packetType === UserAuthPKOK.type)

        let alg: Buffer
        ;[alg, raw] = readNextBuffer(raw)

        let data: Buffer
        ;[data, raw] = readNextBuffer(raw)

        assert(raw.length === 0)

        const publicKey = PublicKey.parse(data)
        assert(alg.toString("utf-8") === publicKey.data.alg)

        return new UserAuthPKOK({
            publicKey: publicKey,
        })
    }
}
