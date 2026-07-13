import Client from "../Client.js"
import { serializeBuffer, serializeUint32 } from "../utils/Buffer.js"
import ClientChannel from "./ClientChannel.js"

export interface TCPIPConnectionDetails {
    destinationHost: string
    destinationPort: number
    sourceHost: string
    sourcePort: number
}

export default class ClientTCPIPChannel extends ClientChannel {
    readonly details: Readonly<TCPIPConnectionDetails>

    constructor(client: Client, details: TCPIPConnectionDetails) {
        super(client, "direct-tcpip")
        this.details = Object.freeze({
            ...details,
            destinationPort: this.port(details.destinationPort, "destination port"),
            sourcePort: this.port(details.sourcePort, "source port"),
        })
    }

    override getOpenPacket() {
        return super.getOpenPacket(
            Buffer.concat([
                serializeBuffer(Buffer.from(this.details.destinationHost, "utf8")),
                serializeUint32(this.details.destinationPort),
                serializeBuffer(Buffer.from(this.details.sourceHost, "utf8")),
                serializeUint32(this.details.sourcePort),
            ]),
        )
    }

    private port(value: number, name: string): number {
        if (!Number.isInteger(value) || value < 0 || value > 65_535) {
            throw new RangeError(`SSH ${name} must be between 0 and 65535`)
        }
        return value
    }
}
