import assert from "node:assert"
import { PacketNameToType } from "../constants.js"
import Packet from "../packet.js"
import {
    readNextBinaryBoolean,
    readNextBuffer,
    readNextUint8,
    readNextUint32,
    serializeBuffer,
    serializeUint8,
    serializeUint32,
} from "../utils/Buffer.js"
import { serializeBinaryBoolean } from "../utils/BinaryBoolean.js"

export interface UserAuthPrompt {
    prompt: string
    echo: boolean
}

export interface UserAuthInfoRequestData {
    name: string
    instruction: string
    languageTag: string
    prompts: UserAuthPrompt[]
}

export default class UserAuthInfoRequest implements Packet {
    static type = PacketNameToType.SSH_MSG_USERAUTH_PK_OK

    constructor(public data: UserAuthInfoRequestData) {
        assert(data.prompts.length <= 0xffffffff, "Too many keyboard-interactive prompts")
        for (const prompt of data.prompts) {
            assert(prompt.prompt.length > 0, "Keyboard-interactive prompts must not be empty")
        }
    }

    serialize(): Buffer {
        return Buffer.concat([
            serializeUint8(UserAuthInfoRequest.type),
            serializeBuffer(Buffer.from(this.data.name, "utf8")),
            serializeBuffer(Buffer.from(this.data.instruction, "utf8")),
            serializeBuffer(Buffer.from(this.data.languageTag, "ascii")),
            serializeUint32(this.data.prompts.length),
            ...this.data.prompts.flatMap(({ prompt, echo }) => [
                serializeBuffer(Buffer.from(prompt, "utf8")),
                serializeBinaryBoolean(echo),
            ]),
        ])
    }

    static parse(raw: Buffer): UserAuthInfoRequest {
        let packetType: number
        ;[packetType, raw] = readNextUint8(raw)
        assert(packetType === UserAuthInfoRequest.type)
        let name: Buffer
        ;[name, raw] = readNextBuffer(raw)
        let instruction: Buffer
        ;[instruction, raw] = readNextBuffer(raw)
        let languageTag: Buffer
        ;[languageTag, raw] = readNextBuffer(raw)
        let promptCount: number
        ;[promptCount, raw] = readNextUint32(raw)
        const prompts: UserAuthPrompt[] = []
        for (let index = 0; index < promptCount; index++) {
            let prompt: Buffer
            ;[prompt, raw] = readNextBuffer(raw)
            let echo: boolean
            ;[echo, raw] = readNextBinaryBoolean(raw)
            prompts.push({ prompt: prompt.toString("utf8"), echo })
        }
        assert(raw.length === 0)
        return new UserAuthInfoRequest({
            name: name.toString("utf8"),
            instruction: instruction.toString("utf8"),
            languageTag: languageTag.toString("ascii"),
            prompts,
        })
    }
}
