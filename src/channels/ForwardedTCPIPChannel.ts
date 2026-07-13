import { Duplex } from "node:stream"
import Channel, {
    DEFAULT_SERVER_CHANNEL_PACKET_SIZE,
    DEFAULT_SERVER_CHANNEL_WINDOW_SIZE,
} from "../Channel.js"
import ServerClient from "../ServerClient.js"
import { serializeBuffer, serializeUint32 } from "../utils/Buffer.js"
import type { TCPIPConnectionDetails } from "./ClientTCPIPChannel.js"

type WriteCallback = (error?: Error | null) => void

export class ForwardedTCPIPStream extends Duplex {
    constructor(private readonly channel: ForwardedTCPIPChannel) {
        super({ allowHalfOpen: true, emitClose: true })
    }

    _read(): void {
        this.channel.resumeInput()
    }

    _write(data: Buffer | string, encoding: BufferEncoding, callback: WriteCallback): void {
        this.channel.sendData(Buffer.isBuffer(data) ? data : Buffer.from(data, encoding), callback)
    }

    _final(callback: WriteCallback): void {
        this.channel.sendEOF()
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

export default class ForwardedTCPIPChannel extends Channel {
    static channel_type = "forwarded-tcpip"

    readonly details: Readonly<TCPIPConnectionDetails>
    readonly stream: ForwardedTCPIPStream

    constructor(client: ServerClient, details: TCPIPConnectionDetails) {
        const args = Buffer.concat([
            serializeBuffer(Buffer.from(details.destinationHost, "utf8")),
            serializeUint32(details.destinationPort),
            serializeBuffer(Buffer.from(details.sourceHost, "utf8")),
            serializeUint32(details.sourcePort),
        ])
        super(client, ForwardedTCPIPChannel.channel_type, args)
        this.local_initial_window_size = DEFAULT_SERVER_CHANNEL_WINDOW_SIZE
        this.local_maximum_packet_size = DEFAULT_SERVER_CHANNEL_PACKET_SIZE
        this.local_window_size = this.local_initial_window_size
        this.details = Object.freeze({ ...details })
        this.stream = new ForwardedTCPIPStream(this)
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
}
