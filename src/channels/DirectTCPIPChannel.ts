import assert from "node:assert"
import Channel, {
    DEFAULT_SERVER_CHANNEL_PACKET_SIZE,
    DEFAULT_SERVER_CHANNEL_WINDOW_SIZE,
} from "../Channel.js"
import Client from "../Client.js"
import ServerClient from "../ServerClient.js"
import { readNextBuffer, readNextUint32 } from "../utils/Buffer.js"
import { decodeSSHUTF8 } from "../utils/SSHText.js"
import type { TCPIPConnectionDetails } from "./ClientTCPIPChannel.js"
import ChannelStream from "./ChannelStream.js"

export class DirectTCPIPStream extends ChannelStream {}

export default class DirectTCPIPChannel extends Channel {
    static channel_type = "direct-tcpip"

    readonly details: Readonly<TCPIPConnectionDetails>
    readonly stream: DirectTCPIPStream

    constructor(client: Client | ServerClient, channelType: string, clientArgs = Buffer.alloc(0)) {
        if (client instanceof Client) {
            throw new Error("A client must not accept a server-initiated direct-tcpip channel")
        }
        super(client, channelType, clientArgs)
        this.local_initial_window_size = DEFAULT_SERVER_CHANNEL_WINDOW_SIZE
        this.local_maximum_packet_size = DEFAULT_SERVER_CHANNEL_PACKET_SIZE
        this.details = Object.freeze(this.parseDetails(clientArgs))
        this.stream = new DirectTCPIPStream(this)
    }

    protected handleData(data: Buffer): boolean {
        return this.stream.receive(data)
    }

    protected handleEOF(): void {
        this.stream.receiveEOF()
    }

    protected handleClose(): void {
        this.stream.closeFromRemote()
    }

    private parseDetails(raw: Buffer): TCPIPConnectionDetails {
        const [destinationHost, afterDestinationHost] = readNextBuffer(raw)
        const [destinationPort, afterDestinationPort] = readNextUint32(afterDestinationHost)
        const [sourceHost, afterSourceHost] = readNextBuffer(afterDestinationPort)
        const [sourcePort, remaining] = readNextUint32(afterSourceHost)
        assert(remaining.length === 0)
        assert(destinationPort <= 65_535, "direct-tcpip destination port exceeds 65535")
        assert(sourcePort <= 65_535, "direct-tcpip source port exceeds 65535")
        return {
            destinationHost: decodeSSHUTF8(destinationHost, "direct-tcpip destination address"),
            destinationPort,
            sourceHost: decodeSSHUTF8(sourceHost, "direct-tcpip originator address"),
            sourcePort,
        }
    }
}
