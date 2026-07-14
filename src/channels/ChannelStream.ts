import { Duplex } from "node:stream"
import Channel from "../Channel.js"

type WriteCallback = (error?: Error | null) => void

export default class ChannelStream extends Duplex {
    constructor(private readonly channel: Channel) {
        super({ allowHalfOpen: true, emitClose: true })
    }

    _read(): void {
        this.channel.resumeInput()
    }

    _write(data: Buffer | string, encoding: BufferEncoding, callback: WriteCallback): void {
        void this.channel
            .sendData(Buffer.isBuffer(data) ? data : Buffer.from(data, encoding))
            .then(() => callback(), callback)
    }

    _final(callback: WriteCallback): void {
        this.channel.sendEOF()
        callback()
    }

    _destroy(error: Error | null, callback: WriteCallback): void {
        if (this.channel.isOpen && this.channel.client.isConnected) {
            this.channel.terminate()
        }
        callback(error)
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
