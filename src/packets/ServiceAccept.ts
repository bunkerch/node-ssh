import assert from "assert"
import { PacketNameToType } from "../constants.js"
import Packet from "../packet.js"
import { readNextBuffer, readNextUint8, serializeBuffer } from "../utils/Buffer.js"
import { decodeSSHName, encodeSSHName } from "../utils/SSHName.js"

export interface ServiceAcceptData {
    service_name: string
}
export default class ServiceAccept implements Packet {
    static type = PacketNameToType.SSH_MSG_SERVICE_ACCEPT

    data: ServiceAcceptData
    constructor(data: ServiceAcceptData) {
        this.data = { service_name: data.service_name }
    }

    serialize(): Buffer {
        const buffers = []

        buffers.push(Buffer.from([ServiceAccept.type]))

        buffers.push(serializeBuffer(encodeSSHName(this.data.service_name, "SSH service name")))

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
            service_name: decodeSSHName(service_name, "SSH service name"),
        })
    }
}
