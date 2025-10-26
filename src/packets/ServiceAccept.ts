import assert from "assert"
import { PacketNameToType } from "../constants.js"
import Packet from "../packet.js"
import { readNextBuffer, readNextUint8, serializeBuffer } from "../utils/Buffer.js"

export interface ServiceAcceptData {
    service_name: string
}
export default class ServiceAccept implements Packet {
    static type = PacketNameToType.SSH_MSG_SERVICE_ACCEPT

    data: ServiceAcceptData
    constructor(data: ServiceAcceptData) {
        this.data = data
    }

    serialize(): Buffer {
        const buffers = []

        buffers.push(Buffer.from([ServiceAccept.type]))

        buffers.push(serializeBuffer(Buffer.from(this.data.service_name, "utf-8")))

        return Buffer.concat(buffers)
    }

    static parse(raw: Buffer): ServiceAccept {
        let packetType: number
        ;[packetType, raw] = readNextUint8(raw)
        assert(packetType === ServiceAccept.type)

        let service_name: Buffer
        ;[service_name, raw] = readNextBuffer(raw)

        assert(raw.length === 0)

        return new ServiceAccept({
            service_name: service_name.toString("utf-8"),
        })
    }
}
