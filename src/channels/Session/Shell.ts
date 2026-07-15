import { Duplex, Writable } from "node:stream"
import { SSHExtendedDataTypes } from "../../constants.js"
import { serializeBinaryBoolean } from "../../utils/BinaryBoolean.js"
import { serializeBuffer, serializeUint32 } from "../../utils/Buffer.js"
import { normalizeSSHSignal } from "../../utils/Signal.js"
import { encodeSSHLanguageTag, encodeSSHUTF8 } from "../../utils/SSHText.js"
import SessionChannel from "../SessionChannel.js"

type WriteCallback = (error?: Error | null) => void

class ServerStderr extends Writable {
    constructor(private readonly channel: SessionChannel) {
        super()
    }

    _write(data: Buffer | string, encoding: BufferEncoding, callback: WriteCallback): void {
        const buffer = Buffer.isBuffer(data) ? data : Buffer.from(data, encoding)
        void this.channel
            .sendExtendedData(SSHExtendedDataTypes.SSH_EXTENDED_DATA_STDERR, buffer)
            .then(() => callback(), callback)
    }
}

export default class Shell extends Duplex {
    readonly channel: SessionChannel
    readonly stdin: this
    readonly stdout: this
    readonly stderr: Writable
    private exitResultSent = false

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
        void this.writeStdout(data, encoding).then(() => callback(), callback)
    }

    /** Send standard output and resolve after every resulting channel-data packet is written. */
    writeStdout(data: Buffer | string, encoding: BufferEncoding = "utf8"): Promise<void> {
        return this.channel.sendData(Buffer.isBuffer(data) ? data : Buffer.from(data, encoding))
    }

    /** Send standard error and resolve after every resulting extended-data packet is written. */
    writeStderr(data: Buffer | string, encoding: BufferEncoding = "utf8"): Promise<void> {
        return this.channel.sendExtendedData(
            SSHExtendedDataTypes.SSH_EXTENDED_DATA_STDERR,
            Buffer.isBuffer(data) ? data : Buffer.from(data, encoding),
        )
    }

    _final(callback: WriteCallback): void {
        this.channel.sendEOF()
        callback()
    }

    _destroy(error: Error | null, callback: WriteCallback): void {
        if (this.channel.isOpen && this.channel.client.isConnected) {
            this.channel.terminate()
        }
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
    exit(signal: string, coreDumped?: boolean, message?: string, languageTag?: string): this
    exit(
        statusOrSignal: number | string,
        coreDumped = false,
        message = "",
        languageTag = "",
    ): this {
        if (this.exitResultSent) {
            throw new Error("SSH session exit result has already been sent")
        }
        if (typeof statusOrSignal === "number") {
            if (
                !Number.isSafeInteger(statusOrSignal) ||
                statusOrSignal < 0 ||
                statusOrSignal > 0xffff_ffff
            ) {
                throw new RangeError("SSH exit status must be a uint32")
            }
            this.channel.sendRequest("exit-status", serializeUint32(statusOrSignal))
            this.exitResultSent = true
            return this
        }

        const signal = normalizeSSHSignal(statusOrSignal)
        const encodedMessage = encodeSSHUTF8(message, "SSH exit-signal message")
        const encodedLanguageTag = encodeSSHLanguageTag(languageTag, "SSH exit-signal language tag")
        this.channel.sendRequest(
            "exit-signal",
            Buffer.concat([
                serializeBuffer(Buffer.from(signal, "ascii")),
                serializeBinaryBoolean(coreDumped),
                serializeBuffer(encodedMessage),
                serializeBuffer(encodedLanguageTag),
            ]),
        )
        this.exitResultSent = true
        return this
    }
}
