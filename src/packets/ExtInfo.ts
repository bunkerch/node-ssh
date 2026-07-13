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

export interface SSHExtension {
    name: string
    value: Buffer
}

export interface ExtInfoData {
    extensions: SSHExtension[]
}

export default class ExtInfo implements Packet {
    static type = PacketNameToType.SSH_MSG_EXT_INFO

    data: ExtInfoData

    constructor(data: ExtInfoData) {
        const names = new Set<string>()
        for (const extension of data.extensions) {
            assert(extension.name.length > 0, "SSH extension name must not be empty")
            assert(!names.has(extension.name), `Duplicate SSH extension: ${extension.name}`)
            names.add(extension.name)
        }
        this.data = data
    }

    serialize(): Buffer {
        return Buffer.concat([
            serializeUint8(ExtInfo.type),
            serializeUint32(this.data.extensions.length),
            ...this.data.extensions.flatMap((extension) => [
                serializeBuffer(Buffer.from(extension.name, "utf8")),
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
            extensions.push({ name: name.toString("utf8"), value })
        }
        assert(raw.length === 0, "Unexpected data after SSH extension information")
        return new ExtInfo({ extensions })
    }
}
