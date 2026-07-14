import assert from "node:assert"
import { PacketNameToType } from "../constants.js"
import Packet from "../packet.js"
import { readNextBuffer, readNextUint8, serializeBuffer, serializeUint8 } from "../utils/Buffer.js"
import {
    decodeSSHLanguageTag,
    decodeSSHUTF8,
    encodeSSHLanguageTag,
    encodeSSHUTF8,
} from "../utils/SSHText.js"

export interface UserAuthBannerData {
    message: string
    languageTag: string
}

export default class UserAuthBanner implements Packet {
    static type = PacketNameToType.SSH_MSG_USERAUTH_BANNER

    data: UserAuthBannerData

    constructor(data: UserAuthBannerData) {
        this.data = { message: data.message, languageTag: data.languageTag }
    }

    serialize(): Buffer {
        return Buffer.concat([
            serializeUint8(UserAuthBanner.type),
            serializeBuffer(encodeSSHUTF8(this.data.message, "SSH authentication banner")),
            serializeBuffer(encodeSSHLanguageTag(this.data.languageTag)),
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
            message: decodeSSHUTF8(message, "SSH authentication banner"),
            languageTag: decodeSSHLanguageTag(languageTag),
        })
    }
}
