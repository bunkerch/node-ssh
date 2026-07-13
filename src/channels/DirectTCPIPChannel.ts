import assert from "node:assert"
import { Duplex } from "node:stream"
import Channel, {
    DEFAULT_SERVER_CHANNEL_PACKET_SIZE,
    DEFAULT_SERVER_CHANNEL_WINDOW_SIZE,
} from "../Channel.js"
import Client from "../Client.js"
import ServerClient from "../ServerClient.js"
import { readNextBuffer, readNextUint32 } from "../utils/Buffer.js"
import type { TCPIPConnectionDetails } from "./ClientTCPIPChannel.js"

type WriteCallback = (error?: Error | null) => void

export class DirectTCPIPStream extends Duplex {
    constructor(private readonly channel: DirectTCPIPChannel) {
        super({ allowHalfOpen: true, emitClose: true })
    }

    _read(): void {
        this.channel.resumeInput()
    }

    _write(data: Buffer | string, encoding: BufferEncoding, callback: WriteCallback): void {
        this.channel.sendData(Buffer.isBuffer(data) ? data : Buffer.from(data, encoding), callback)
    }

    _final(callback: WriteCallback): void {
        this.channel.close()
        callback()
    }

    receive(data: Buffer): boolean {
        return this.push(data)
    }

    receiveEOF(): void {
        this.push(null)
    }

    closeFromRemote(): void {
        this.receiveEOF()
        this.destroy()
    }
}

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
            destinationHost: destinationHost.toString("utf8"),
            destinationPort,
            sourceHost: sourceHost.toString("utf8"),
            sourcePort,
        }
    }
}
