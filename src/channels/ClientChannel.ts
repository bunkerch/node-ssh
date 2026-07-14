import { Duplex, Readable } from "node:stream"
import Client from "../Client.js"
import ChannelClose from "../packets/ChannelClose.js"
import ChannelData from "../packets/ChannelData.js"
import ChannelEOF from "../packets/ChannelEOF.js"
import ChannelFailure from "../packets/ChannelFailure.js"
import ChannelOpen from "../packets/ChannelOpen.js"
import ChannelOpenConfirmation from "../packets/ChannelOpenConfirmation.js"
import ChannelOpenFailure, { ChannelOpenError } from "../packets/ChannelOpenFailure.js"
import ChannelRequest from "../packets/ChannelRequest.js"
import ChannelSuccess from "../packets/ChannelSuccess.js"
import ChannelWindowAdjust from "../packets/ChannelWindowAdjust.js"
import { MAXIMUM_CHANNEL_WINDOW_SIZE, SSHExtendedDataTypes } from "../constants.js"
import {
    readNextBinaryBoolean,
    readNextBuffer,
    readNextUint32,
    serializeBuffer,
} from "../utils/Buffer.js"
import { Hooker } from "../utils/Hooker.js"
import { normalizeSSHSignal } from "../utils/Signal.js"

export const DEFAULT_CHANNEL_WINDOW_SIZE = 2 ** 21
export const DEFAULT_CHANNEL_PACKET_SIZE = 2 ** 15
const CHANNEL_WINDOW_THRESHOLD = DEFAULT_CHANNEL_WINDOW_SIZE / 2

type WriteCallback = (error?: Error | null) => void

interface PendingWrite {
    data: Buffer
    offset: number
    callback: WriteCallback
    atomic: boolean
}

interface PendingRequest {
    type: string
    resolve: () => void
    reject: (error: Error) => void
}

export type ClientChannelRequestContext = Readonly<{
    type: string
    args: Buffer
    wantReply: boolean
}>
export interface ClientChannelRequestController {
    success: boolean
}
// eslint-disable-next-line @typescript-eslint/consistent-type-definitions
export type ClientChannelHooker = {
    endOfWrite: []
    request: [context: ClientChannelRequestContext, controller: ClientChannelRequestController]
}

export class ClientChannelStderr extends Readable {
    constructor(private readonly onDemand: () => void) {
        super({ highWaterMark: DEFAULT_CHANNEL_WINDOW_SIZE })
    }

    _read(): void {
        this.onDemand()
    }

    receive(data: Buffer): boolean {
        return this.push(data)
    }

    endFromRemote(): void {
        this.push(null)
    }
}

export default class ClientChannel extends Duplex {
    readonly hooker = new Hooker<ClientChannelHooker>()
    readonly client: Client
    readonly type: string
    readonly localId: number
    readonly localInitialWindowSize: number
    readonly localMaximumPacketSize: number
    readonly stderr: ClientChannelStderr

    remoteId?: number
    remoteWindowSize = 0
    remoteMaximumPacketSize = 0
    localWindowSize: number

    exitCode?: number | null
    exitSignal?: string
    exitCoreDumped?: boolean
    exitErrorMessage?: string
    exitLanguageTag?: string

    private openResolve!: () => void
    private openReject!: (error: Error) => void
    private readonly openPromise: Promise<void>
    private pendingWrite?: PendingWrite
    private readonly pendingRequests: PendingRequest[] = []
    private stdoutBlocked = false
    private stderrBlocked = false
    private sentEOF = false
    private receivedEOF = false
    private sentEndOfWrite = false
    private receivedEndOfWrite = false
    private sentClose = false
    private receivedClose = false
    private transportClosed = false

    constructor(
        client: Client,
        type: string,
        options: {
            initialWindowSize?: number
            maximumPacketSize?: number
        } = {},
    ) {
        super({
            allowHalfOpen: true,
            emitClose: true,
            highWaterMark: options.initialWindowSize ?? DEFAULT_CHANNEL_WINDOW_SIZE,
        })
        this.client = client
        this.type = type
        this.localId = client.localChannelIndex++
        this.localInitialWindowSize = options.initialWindowSize ?? DEFAULT_CHANNEL_WINDOW_SIZE
        this.localMaximumPacketSize = options.maximumPacketSize ?? DEFAULT_CHANNEL_PACKET_SIZE
        this.localWindowSize = this.localInitialWindowSize
        this.stderr = new ClientChannelStderr(() => {
            this.stderrBlocked = false
            this.adjustWindowIfNeeded()
        })
        this.openPromise = new Promise<void>((resolve, reject) => {
            this.openResolve = resolve
            this.openReject = reject
        })
    }

    get isOpen(): boolean {
        return this.remoteId !== undefined && !this.sentClose && !this.receivedClose
    }

    get isFullyClosed(): boolean {
        return this.sentClose && this.receivedClose
    }

    get hasSentEndOfWrite(): boolean {
        return this.sentEndOfWrite
    }

    get hasReceivedEndOfWrite(): boolean {
        return this.receivedEndOfWrite
    }

    getOpenPacket(args: Buffer = Buffer.alloc(0)): ChannelOpen {
        return new ChannelOpen({
            channel_type: this.type,
            sender_channel_id: this.localId,
            initial_window_size: this.localInitialWindowSize,
            maximum_packet_size: this.localMaximumPacketSize,
            args,
        })
    }

    getOpenConfirmationPacket(): ChannelOpenConfirmation {
        if (this.remoteId === undefined) {
            throw new Error(`SSH channel ${this.localId} has no remote channel identifier`)
        }
        return new ChannelOpenConfirmation({
            recipient_channel_id: this.remoteId,
            sender_channel_id: this.localId,
            initial_window_size: this.localInitialWindowSize,
            maximum_packet_size: this.localMaximumPacketSize,
            args: Buffer.alloc(0),
        })
    }

    waitUntilOpen(): Promise<void> {
        return this.openPromise
    }

    abort(error: Error | null = null): void {
        this.transportClosed = true
        if (this.remoteId === undefined) {
            this.openReject(error ?? new Error(`SSH channel ${this.localId} closed before opening`))
        }
        this.destroy(error ?? undefined)
    }

    confirmOpen(packet: ChannelOpenConfirmation): void {
        if (this.remoteId !== undefined) {
            throw new Error(`SSH channel ${this.localId} was confirmed more than once`)
        }
        this.remoteId = packet.data.sender_channel_id
        this.remoteWindowSize = packet.data.initial_window_size
        this.remoteMaximumPacketSize = packet.data.maximum_packet_size
        this.openResolve()
    }

    acceptOpen(packet: ChannelOpen): void {
        if (this.remoteId !== undefined) {
            throw new Error(`SSH channel ${this.localId} was opened more than once`)
        }
        this.remoteId = packet.data.sender_channel_id
        this.remoteWindowSize = packet.data.initial_window_size
        this.remoteMaximumPacketSize = packet.data.maximum_packet_size
        this.openResolve()
    }

    failOpen(packet: ChannelOpenFailure): void {
        this.openReject(
            new ChannelOpenError(
                packet.data.reason_code,
                packet.data.recipient_channel_id,
                packet.data.description || `SSH channel ${this.localId} could not be opened`,
            ),
        )
    }

    request(type: string, args: Buffer = Buffer.alloc(0), wantReply = true): Promise<void> {
        if (!this.isOpen || this.remoteId === undefined) {
            return Promise.reject(new Error(`SSH channel ${this.localId} is not open`))
        }
        if (!/^[\x21-\x7e]+$/u.test(type)) {
            return Promise.reject(
                new TypeError("SSH channel request type must be non-empty printable ASCII"),
            )
        }
        if (!Buffer.isBuffer(args)) {
            return Promise.reject(new TypeError("SSH channel request arguments must be a buffer"))
        }

        const response = wantReply
            ? new Promise<void>((resolve, reject) => {
                  this.pendingRequests.push({ type, resolve, reject })
              })
            : Promise.resolve()

        try {
            this.client.sendPacket(
                new ChannelRequest({
                    recipient_channel_id: this.remoteId,
                    request_type: type,
                    want_reply: wantReply,
                    args: Buffer.from(args),
                }),
            )
        } catch (error) {
            if (wantReply) this.pendingRequests.pop()
            return Promise.reject(error)
        }

        return response
    }

    receiveRequestSuccess(): void {
        const request = this.pendingRequests.shift()
        if (!request) throw new Error(`Unexpected success response for SSH channel ${this.localId}`)
        request.resolve()
    }

    receiveRequestFailure(): void {
        const request = this.pendingRequests.shift()
        if (!request) throw new Error(`Unexpected failure response for SSH channel ${this.localId}`)
        request.reject(new Error(`SSH channel ${this.localId} request failed (${request.type})`))
    }

    receiveWindowAdjust(bytesToAdd: number): void {
        if (bytesToAdd > MAXIMUM_CHANNEL_WINDOW_SIZE - this.remoteWindowSize) {
            throw new Error(`SSH channel ${this.localId} window adjustment exceeds uint32`)
        }
        this.remoteWindowSize += bytesToAdd
        this.flushPendingWrite()
    }

    receiveData(data: Buffer): void {
        this.consumeLocalWindow(data)
        this.stdoutBlocked = !this.push(data)
        this.adjustWindowIfNeeded()
    }

    receiveExtendedData(dataType: number, data: Buffer): void {
        this.consumeLocalWindow(data)
        if (dataType === SSHExtendedDataTypes.SSH_EXTENDED_DATA_STDERR) {
            this.stderrBlocked = !this.stderr.receive(data)
        }
        this.adjustWindowIfNeeded()
    }

    receiveEOF(): void {
        if (this.receivedEOF) return
        this.receivedEOF = true
        this.push(null)
        this.stderr.endFromRemote()
    }

    receiveClose(): void {
        if (this.receivedClose) return
        this.receivedClose = true
        this.receiveEOF()
        if (!this.sentClose) this.sendClose()
        this.destroy()
    }

    async receiveRequest(packet: ChannelRequest): Promise<void> {
        if (packet.data.request_type === "eow@openssh.com") {
            if (packet.data.want_reply || packet.data.args.length !== 0) {
                throw new Error("Invalid end-of-write channel request")
            }
            if (this.type !== "session") {
                throw new Error("End-of-write is only valid on session channels")
            }
            if (this.receivedEndOfWrite) return
            this.receivedEndOfWrite = true
            await this.hooker.triggerHook("endOfWrite")
            this.emit("endOfWrite")
            if (!this.writableEnded) this.end()
            return
        }

        if (packet.data.request_type === "exit-status") {
            this.validateExitRequest(packet)
            const [exitCode, remaining] = readNextUint32(packet.data.args)
            if (remaining.length !== 0) throw new Error("Invalid exit-status channel request")
            this.exitCode = exitCode
            this.emit("exit", exitCode)
            this.replyToRequest(packet, true)
            return
        }

        if (packet.data.request_type === "exit-signal") {
            this.validateExitRequest(packet)
            const [signal, afterSignal] = readNextBuffer(packet.data.args)
            const [coreDumped, afterCoreDumped] = readNextBinaryBoolean(afterSignal)
            const [errorMessage, afterErrorMessage] = readNextBuffer(afterCoreDumped)
            const [languageTag, remaining] = readNextBuffer(afterErrorMessage)
            if (remaining.length !== 0) throw new Error("Invalid exit-signal channel request")

            const signalName = signal.toString("ascii")
            if (signal.some((byte) => byte > 0x7f)) {
                throw new Error("Invalid exit-signal signal name")
            }
            const normalizedSignal = normalizeSSHSignal(signalName)
            if (normalizedSignal !== signalName) {
                throw new Error('SSH exit-signal names must omit the "SIG" prefix')
            }
            const decodedErrorMessage = new TextDecoder("utf-8", { fatal: true }).decode(
                errorMessage,
            )
            const decodedLanguageTag = languageTag.toString("ascii")
            if (
                languageTag.some((byte) => byte > 0x7f) ||
                (decodedLanguageTag.length > 0 &&
                    !/^[A-Za-z]{1,8}(?:-[A-Za-z0-9]{1,8})*$/u.test(decodedLanguageTag))
            ) {
                throw new Error("Invalid exit-signal language tag")
            }

            this.exitCode = null
            this.exitSignal = `SIG${normalizedSignal}`
            this.exitCoreDumped = coreDumped
            this.exitErrorMessage = decodedErrorMessage
            this.exitLanguageTag = decodedLanguageTag
            this.emit(
                "exit",
                null,
                this.exitSignal,
                coreDumped,
                this.exitErrorMessage,
                decodedLanguageTag,
            )
            this.replyToRequest(packet, true)
            return
        }

        const context: ClientChannelRequestContext = Object.freeze({
            type: packet.data.request_type,
            args: Buffer.from(packet.data.args),
            wantReply: packet.data.want_reply,
        })
        const controller: ClientChannelRequestController = { success: false }
        await this.hooker.triggerHook("request", context, controller)
        this.replyToRequest(packet, controller.success)
    }

    private validateExitRequest(packet: ChannelRequest): void {
        if (this.type !== "session") throw new Error("Exit requests are only valid on sessions")
        if (packet.data.want_reply) throw new Error("SSH exit requests must not request a reply")
        if (this.exitCode !== undefined || this.exitSignal !== undefined) {
            throw new Error("SSH session received more than one exit result")
        }
    }

    eof(): this {
        if (!this.sentEOF && this.remoteId !== undefined && !this.sentClose) {
            this.sentEOF = true
            this.client.sendPacket(new ChannelEOF({ recipient_channel_id: this.remoteId }))
        }
        return this
    }

    /** Ask the peer to stop sending channel data while keeping this channel open. */
    sendEndOfWrite(force = false): boolean {
        if (this.sentEndOfWrite || !this.isOpen || this.type !== "session") return false
        const software = this.client.serverProtocolVersion?.protocol_software ?? ""
        if (!force && !software.startsWith("OpenSSH_")) return false
        this.sentEndOfWrite = true
        void this.request("eow@openssh.com", Buffer.alloc(0), false)
        return true
    }

    close(): this {
        this.eof()
        this.sendClose()
        return this
    }

    _read(): void {
        this.stdoutBlocked = false
        this.adjustWindowIfNeeded()
    }

    _write(data: Buffer | string, encoding: BufferEncoding, callback: WriteCallback): void {
        if (!this.isOpen) {
            callback(new Error(`SSH channel ${this.localId} is not open for writing`))
            return
        }
        if (this.pendingWrite) {
            callback(new Error(`SSH channel ${this.localId} already has a pending write`))
            return
        }

        this.writeChannelData(Buffer.isBuffer(data) ? data : Buffer.from(data, encoding), callback)
    }

    _final(callback: WriteCallback): void {
        this.eof()
        callback()
    }

    _destroy(error: Error | null, callback: (error?: Error | null) => void): void {
        if (!this.transportClosed && !this.sentClose && this.remoteId !== undefined) {
            this.sendClose()
        }
        if (this.pendingWrite) {
            const pending = this.pendingWrite
            this.pendingWrite = undefined
            pending.callback(error ?? new Error(`SSH channel ${this.localId} closed during write`))
        }
        while (this.pendingRequests.length > 0) {
            this.pendingRequests
                .shift()!
                .reject(error ?? new Error(`SSH channel ${this.localId} closed during request`))
        }
        callback(error)
    }

    protected serializeString(value: string): Buffer {
        return serializeBuffer(Buffer.from(value, "utf8"))
    }

    protected writeChannelData(data: Buffer, callback: WriteCallback, atomic = false): void {
        if (!this.isOpen) {
            callback(new Error(`SSH channel ${this.localId} is not open for writing`))
            return
        }
        if (this.pendingWrite) {
            callback(new Error(`SSH channel ${this.localId} already has a pending write`))
            return
        }
        if (
            atomic &&
            (data.length > this.remoteMaximumPacketSize ||
                data.length > DEFAULT_CHANNEL_PACKET_SIZE)
        ) {
            callback(new Error(`SSH channel ${this.localId} atomic packet exceeds peer limits`))
            return
        }
        this.pendingWrite = { data: Buffer.from(data), offset: 0, callback, atomic }
        this.flushPendingWrite()
    }

    private replyToRequest(packet: ChannelRequest, success: boolean): void {
        if (!packet.data.want_reply || !this.isOpen || this.remoteId === undefined) return
        this.client.sendPacket(
            success
                ? new ChannelSuccess({ recipient_channel_id: this.remoteId })
                : new ChannelFailure({ recipient_channel_id: this.remoteId }),
        )
    }

    protected consumeLocalWindow(data: Buffer): void {
        if (this.receivedEOF) {
            throw new Error(`SSH channel ${this.localId} received data after EOF`)
        }
        if (data.length > this.localMaximumPacketSize) {
            throw new Error(`SSH channel ${this.localId} received an oversized data packet`)
        }
        if (data.length > this.localWindowSize) {
            throw new Error(`SSH channel ${this.localId} received data beyond its window`)
        }
        this.localWindowSize -= data.length
    }

    protected adjustWindowIfNeeded(): void {
        if (
            this.remoteId === undefined ||
            this.sentClose ||
            this.stdoutBlocked ||
            this.stderrBlocked ||
            this.localWindowSize > CHANNEL_WINDOW_THRESHOLD
        ) {
            return
        }

        const bytesToAdd = this.localInitialWindowSize - this.localWindowSize
        if (bytesToAdd === 0) return
        this.localWindowSize += bytesToAdd
        this.client.sendPacket(
            new ChannelWindowAdjust({
                recipient_channel_id: this.remoteId,
                bytes_to_add: bytesToAdd,
            }),
        )
    }

    private flushPendingWrite(): void {
        const pending = this.pendingWrite
        if (!pending || this.remoteId === undefined) return

        if (pending.atomic && this.remoteWindowSize < pending.data.length) return

        while (
            pending.offset < pending.data.length &&
            this.remoteWindowSize > 0 &&
            this.remoteMaximumPacketSize > 0
        ) {
            const length = pending.atomic
                ? pending.data.length
                : Math.min(
                      pending.data.length - pending.offset,
                      this.remoteWindowSize,
                      this.remoteMaximumPacketSize,
                      DEFAULT_CHANNEL_PACKET_SIZE,
                  )
            const data = pending.data.subarray(pending.offset, pending.offset + length)
            this.client.sendPacket(
                new ChannelData({
                    recipient_channel_id: this.remoteId,
                    data,
                }),
            )
            pending.offset += length
            this.remoteWindowSize -= length
        }

        if (pending.offset === pending.data.length) {
            this.pendingWrite = undefined
            pending.callback()
        }
    }

    private sendClose(): void {
        if (this.sentClose || this.remoteId === undefined) return
        this.sentClose = true
        this.client.sendPacket(new ChannelClose({ recipient_channel_id: this.remoteId }))
    }
}
