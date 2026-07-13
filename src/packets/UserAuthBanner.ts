import assert from "node:assert"
import { PacketNameToType } from "../constants.js"
import Packet from "../packet.js"
import { readNextBuffer, readNextUint8, serializeBuffer, serializeUint8 } from "../utils/Buffer.js"

export interface UserAuthBannerData {
    message: string
    languageTag: string
}

export default class UserAuthBanner implements Packet {
    static type = PacketNameToType.SSH_MSG_USERAUTH_BANNER

    constructor(public data: UserAuthBannerData) {}

    serialize(): Buffer {
        return Buffer.concat([
            serializeUint8(UserAuthBanner.type),
            serializeBuffer(Buffer.from(this.data.message, "utf8")),
            serializeBuffer(Buffer.from(this.data.languageTag, "ascii")),
        ])
    }

    static parse(raw: Buffer): UserAuthBanner {
        let packetType: number
        ;[packetType, raw] = readNextUint8(raw)
        assert(packetType === UserAuthBanner.type)
        let message: Buffer
        ;[message, raw] = readNextBuffer(raw)
        let languageTag: Buffer
        ;[languageTag, raw] = readNextBuffer(raw)
        assert(raw.length === 0)
        return new UserAuthBanner({
            message: message.toString("utf8"),
            languageTag: languageTag.toString("ascii"),
        })
    }
}
