import assert from "node:assert"
import { PacketNameToType } from "../constants.js"
import Packet from "../packet.js"
import { readNextBuffer, readNextUint8, serializeBuffer, serializeUint8 } from "../utils/Buffer.js"

export interface UserAuthPasswordChangeRequestData {
    prompt: string
    languageTag: string
}

export default class UserAuthPasswordChangeRequest implements Packet {
    static type = PacketNameToType.SSH_MSG_USERAUTH_PK_OK

    constructor(public data: UserAuthPasswordChangeRequestData) {}

    serialize(): Buffer {
        return Buffer.concat([
            serializeUint8(UserAuthPasswordChangeRequest.type),
            serializeBuffer(Buffer.from(this.data.prompt, "utf8")),
            serializeBuffer(Buffer.from(this.data.languageTag, "ascii")),
        ])
    }

    static parse(raw: Buffer): UserAuthPasswordChangeRequest {
        let packetType: number
        ;[packetType, raw] = readNextUint8(raw)
        assert(packetType === UserAuthPasswordChangeRequest.type)
        let prompt: Buffer
        ;[prompt, raw] = readNextBuffer(raw)
        let languageTag: Buffer
        ;[languageTag, raw] = readNextBuffer(raw)
        assert(raw.length === 0)
        return new UserAuthPasswordChangeRequest({
            prompt: prompt.toString("utf8"),
            languageTag: languageTag.toString("ascii"),
        })
    }
}
