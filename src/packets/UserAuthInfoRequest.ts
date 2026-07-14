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
import {
    decodeSSHLanguageTag,
    decodeSSHUTF8,
    encodeSSHLanguageTag,
    encodeSSHUTF8,
} from "../utils/SSHText.js"

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
            serializeBuffer(encodeSSHUTF8(this.data.name, "SSH interactive name")),
            serializeBuffer(encodeSSHUTF8(this.data.instruction, "SSH interactive instruction")),
            serializeBuffer(encodeSSHLanguageTag(this.data.languageTag)),
            serializeUint32(this.data.prompts.length),
            ...this.data.prompts.flatMap(({ prompt, echo }) => [
                serializeBuffer(encodeSSHUTF8(prompt, "SSH interactive prompt")),
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
            prompts.push({ prompt: decodeSSHUTF8(prompt, "SSH interactive prompt"), echo })
        }
        assert(raw.length === 0)
        return new UserAuthInfoRequest({
            name: decodeSSHUTF8(name, "SSH interactive name"),
            instruction: decodeSSHUTF8(instruction, "SSH interactive instruction"),
            languageTag: decodeSSHLanguageTag(languageTag),
            prompts,
        })
    }
}
