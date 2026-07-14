import assert from "node:assert"
import { PacketNameToType } from "../constants.js"
import Packet from "../packet.js"
import {
    readNextBuffer,
    readNextUint32,
    readNextUint8,
    serializeBuffer,
    serializeUint32,
    serializeUint8,
} from "../utils/Buffer.js"
import { decodeSSHName, encodeSSHName, validateSSHName } from "../utils/SSHName.js"

export interface SSHExtension {
    readonly name: string
    readonly value: Buffer
}

export const AUTHENTICATION_EXT_INFO_EXTENSION = "ext-info-in-auth@openssh.com"

export interface ExtInfoData {
    readonly extensions: readonly SSHExtension[]
}

export function copySSHExtensions(
    extensions: readonly SSHExtension[],
): readonly Readonly<SSHExtension>[] {
    return Object.freeze(
        extensions.map((extension) =>
            Object.freeze({ name: extension.name, value: Buffer.from(extension.value) }),
        ),
    )
}

export default class ExtInfo implements Packet {
    static type = PacketNameToType.SSH_MSG_EXT_INFO

    data: ExtInfoData

    constructor(data: ExtInfoData) {
        const names = new Set<string>()
        for (const extension of data.extensions) {
            validateSSHName(extension.name, "SSH extension name")
            assert(!names.has(extension.name), `Duplicate SSH extension: ${extension.name}`)
            names.add(extension.name)
        }
        this.data = Object.freeze({ extensions: copySSHExtensions(data.extensions) })
    }

    serialize(): Buffer {
        return Buffer.concat([
            serializeUint8(ExtInfo.type),
            serializeUint32(this.data.extensions.length),
            ...this.data.extensions.flatMap((extension) => [
                serializeBuffer(encodeSSHName(extension.name, "SSH extension name")),
                serializeBuffer(extension.value),
            ]),
        ])
    }

    static parse(raw: Buffer): ExtInfo {
        let packetType: number
        ;[packetType, raw] = readNextUint8(raw)
        assert(packetType === ExtInfo.type)

        let count: number
        ;[count, raw] = readNextUint32(raw)
        const extensions: SSHExtension[] = []
        for (let index = 0; index < count; index++) {
            let name: Buffer
            let value: Buffer
            ;[name, raw] = readNextBuffer(raw)
            ;[value, raw] = readNextBuffer(raw)
            extensions.push({ name: decodeSSHName(name, "SSH extension name"), value })
        }
        assert(raw.length === 0, "Unexpected data after SSH extension information")
        return new ExtInfo({ extensions })
    }
}
