import assert from "node:assert"
import Client from "../Client.js"
import ChannelOpen from "../packets/ChannelOpen.js"
import { readNextBuffer, readNextUint32 } from "../utils/Buffer.js"
import ClientChannel from "./ClientChannel.js"
import type { TCPIPConnectionDetails } from "./ClientTCPIPChannel.js"

export default class ClientForwardedTCPIPChannel extends ClientChannel {
    readonly details: Readonly<TCPIPConnectionDetails>

    constructor(client: Client, packet: ChannelOpen) {
        assert(packet.data.channel_type === "forwarded-tcpip")
        super(client, "forwarded-tcpip")
        this.details = Object.freeze(ClientForwardedTCPIPChannel.parseDetails(packet.data.args))
        this.acceptOpen(packet)
    }

    static parseDetails(raw: Buffer): TCPIPConnectionDetails {
        const [destinationHost, afterDestinationHost] = readNextBuffer(raw)
        const [destinationPort, afterDestinationPort] = readNextUint32(afterDestinationHost)
        const [sourceHost, afterSourceHost] = readNextBuffer(afterDestinationPort)
        const [sourcePort, remaining] = readNextUint32(afterSourceHost)
        assert(remaining.length === 0)
        assert(destinationPort <= 65_535, "forwarded-tcpip destination port exceeds 65535")
        assert(sourcePort <= 65_535, "forwarded-tcpip source port exceeds 65535")
        return {
            destinationHost: destinationHost.toString("utf8"),
            destinationPort,
            sourceHost: sourceHost.toString("utf8"),
            sourcePort,
        }
    }
}
