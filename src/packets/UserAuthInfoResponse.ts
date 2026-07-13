import assert from "node:assert"
import { PacketNameToType } from "../constants.js"
import Packet from "../packet.js"
import {
    readNextBuffer,
    readNextUint8,
    readNextUint32,
    serializeBuffer,
    serializeUint8,
    serializeUint32,
} from "../utils/Buffer.js"

export interface UserAuthInfoResponseData {
    responses: string[]
}

export default class UserAuthInfoResponse implements Packet {
    static type = PacketNameToType.SSH_MSG_USERAUTH_INFO_RESPONSE

    constructor(public data: UserAuthInfoResponseData) {
        assert(data.responses.length <= 0xffffffff, "Too many keyboard-interactive responses")
    }

    serialize(): Buffer {
        return Buffer.concat([
            serializeUint8(UserAuthInfoResponse.type),
            serializeUint32(this.data.responses.length),
            ...this.data.responses.map((response) =>
                serializeBuffer(Buffer.from(response, "utf8")),
            ),
        ])
    }

    static parse(raw: Buffer): UserAuthInfoResponse {
        let packetType: number
        ;[packetType, raw] = readNextUint8(raw)
        assert(packetType === UserAuthInfoResponse.type)
        let responseCount: number
        ;[responseCount, raw] = readNextUint32(raw)
        const responses: string[] = []
        for (let index = 0; index < responseCount; index++) {
            let response: Buffer
            ;[response, raw] = readNextBuffer(raw)
            responses.push(response.toString("utf8"))
        }
        assert(raw.length === 0)
        return new UserAuthInfoResponse({ responses })
    }
}
