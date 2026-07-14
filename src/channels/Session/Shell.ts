import { Duplex, Writable } from "node:stream"
import { SSHExtendedDataTypes } from "../../constants.js"
import { serializeBinaryBoolean } from "../../utils/BinaryBoolean.js"
import { serializeBuffer, serializeUint32 } from "../../utils/Buffer.js"
import { normalizeSSHSignal } from "../../utils/Signal.js"
import SessionChannel from "../SessionChannel.js"

type WriteCallback = (error?: Error | null) => void

class ServerStderr extends Writable {
    constructor(private readonly channel: SessionChannel) {
        super()
    }

    _write(data: Buffer | string, encoding: BufferEncoding, callback: WriteCallback): void {
        const buffer = Buffer.isBuffer(data) ? data : Buffer.from(data, encoding)
        this.channel.sendExtendedData(
            SSHExtendedDataTypes.SSH_EXTENDED_DATA_STDERR,
            buffer,
            callback,
        )
    }
}

export default class Shell extends Duplex {
    readonly channel: SessionChannel
    readonly stdin: this
    readonly stdout: this
    readonly stderr: Writable

    constructor(channel: SessionChannel) {
        super({ allowHalfOpen: true, emitClose: true })
        this.channel = channel
        this.stdin = this
        this.stdout = this
        this.stderr = new ServerStderr(channel)
    }

    _read(): void {
        this.channel.resumeInput()
    }

    _write(data: Buffer | string, encoding: BufferEncoding, callback: WriteCallback): void {
        const buffer = Buffer.isBuffer(data) ? data : Buffer.from(data, encoding)
        this.channel.sendData(buffer, callback)
    }

    _final(callback: WriteCallback): void {
        this.channel.close()
        callback()
    }

    _destroy(error: Error | null, callback: WriteCallback): void {
        if (!this.stderr.destroyed) this.stderr.destroy()
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

    eof(): this {
        this.channel.sendEOF()
        return this
    }

    /** Ask an OpenSSH peer to stop writing to this session without closing the channel. */
    sendEndOfWrite(force = false): boolean {
        return this.channel.sendEndOfWrite(force)
    }

    close(): this {
        this.channel.close()
        return this
    }

    setXonXoff(clientCanDo: boolean): this {
        this.channel.sendRequest("xon-xoff", serializeBinaryBoolean(clientCanDo))
        return this
    }

    exit(status: number): this
    exit(signal: string, coreDumped?: boolean, message?: string): this
    exit(statusOrSignal: number | string, coreDumped = false, message = ""): this {
        if (typeof statusOrSignal === "number") {
            if (
                !Number.isSafeInteger(statusOrSignal) ||
                statusOrSignal < 0 ||
                statusOrSignal > 0xffff_ffff
            ) {
                throw new RangeError("SSH exit status must be a uint32")
            }
            this.channel.sendRequest("exit-status", serializeUint32(statusOrSignal))
            return this
        }

        const signal = normalizeSSHSignal(statusOrSignal)
        this.channel.sendRequest(
            "exit-signal",
            Buffer.concat([
                serializeBuffer(Buffer.from(signal, "ascii")),
                serializeBinaryBoolean(coreDumped),
                serializeBuffer(Buffer.from(message, "utf8")),
                serializeBuffer(Buffer.alloc(0)),
            ]),
        )
        return this
    }
}
