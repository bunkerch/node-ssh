import assert from "assert"
import { PacketNameToType } from "../constants.js"
import Packet from "../packet.js"
import { readNextBuffer, readNextUint8, serializeBuffer } from "../utils/Buffer.js"

export interface ServiceRequestData {
    service_name: string
}
export default class ServiceRequest implements Packet {
    static type = PacketNameToType.SSH_MSG_SERVICE_REQUEST

    data: ServiceRequestData
    constructor(data: ServiceRequestData) {
        this.data = data
    }

    serialize(): Buffer {
        const buffers = []

        buffers.push(Buffer.from([ServiceRequest.type]))

        buffers.push(serializeBuffer(Buffer.from(this.data.service_name, "utf-8")))

        return Buffer.concat(buffers)
    }

    static parse(raw: Buffer): ServiceRequest {
        let packetType: number
        ;[packetType, raw] = readNextUint8(raw)
        assert(packetType === ServiceRequest.type)

        let service_name: Buffer
        ;[service_name, raw] = readNextBuffer(raw)

        assert(raw.length === 0)

        return new ServiceRequest({
            service_name: service_name.toString("utf-8"),
        })
    }
}
