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
import { readNextBinaryBoolean, readNextBuffer, readNextUint32 } from "../utils/Buffer.js"
import { Hooker } from "../utils/Hooker.js"
import { normalizeSSHSignal } from "../utils/Signal.js"
import { decodeSSHLanguageTag, decodeSSHUTF8 } from "../utils/SSHText.js"
import { ProtocolError } from "../packets/Disconnect.js"
import { waitForReply } from "../ReplyTimeout.js"
import {
    registerUnimplementedRejection,
    unimplementedPacketError,
} from "../utils/UnimplementedRegistry.js"
import allocateChannelIdentifier from "../utils/ChannelIdentifier.js"
import { deferApplicationTraffic } from "../utils/RekeyQueue.js"
import { validateSSHName } from "../utils/SSHName.js"

export const DEFAULT_CHANNEL_WINDOW_SIZE = 2 ** 21
export const DEFAULT_CHANNEL_PACKET_SIZE = 2 ** 15
const CHANNEL_WINDOW_THRESHOLD = DEFAULT_CHANNEL_WINDOW_SIZE / 2

type WriteCallback = (error?: Error | null) => void

interface PendingWrite {
    data: Buffer
    offset: number
    resolve: () => void
    reject: (error: Error) => void
    atomic: boolean
}

interface PendingRequest {
    type: string
    resolve: () => void
    reject: (error: Error) => void
    unregisterUnimplemented?: () => void
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
    private openSettled = false
    private readonly pendingWrites: PendingWrite[] = []
    private readonly pendingRequests: PendingRequest[] = []
    private stdoutBlocked = false
    private stderrBlocked = false
    private sentEOF = false
    private eofPacketSent = false
    private receivedEOF = false
    private sentEndOfWrite = false
    private receivedEndOfWrite = false
    private sentClose = false
    private receivedClose = false
    private transportClosed = false
    private transportCloseError?: Error
    private readonly resumeWritesAfterRekey = () => this.flushPendingWrites()

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
        this.localId = allocateChannelIdentifier(client)
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
        return (
            this.remoteId !== undefined &&
            !this.sentClose &&
            !this.receivedClose &&
            !this.transportClosed
        )
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
        this.transportCloseError = error ?? undefined
        if (!this.openSettled) {
            this.openSettled = true
            this.openReject(error ?? new Error(`SSH channel ${this.localId} closed before opening`))
        }
        this.destroy()
    }

    confirmOpen(packet: ChannelOpenConfirmation): void {
        if (this.openSettled) {
            throw new ProtocolError(`SSH channel ${this.localId} open was settled twice`)
        }
        this.openSettled = true
        this.remoteId = packet.data.sender_channel_id
        this.remoteWindowSize = packet.data.initial_window_size
        this.remoteMaximumPacketSize = packet.data.maximum_packet_size
        this.openResolve()
    }

    acceptOpen(packet: ChannelOpen): void {
        if (this.openSettled) {
            throw new ProtocolError(`SSH channel ${this.localId} open was settled twice`)
        }
        this.openSettled = true
        this.remoteId = packet.data.sender_channel_id
        this.remoteWindowSize = packet.data.initial_window_size
        this.remoteMaximumPacketSize = packet.data.maximum_packet_size
        this.openResolve()
    }

    failOpen(packet: ChannelOpenFailure): void {
        if (this.openSettled) {
            throw new ProtocolError(`SSH channel ${this.localId} open was settled twice`)
        }
        this.openSettled = true
        this.openReject(
            new ChannelOpenError(
                packet.data.reason_code,
                packet.data.description || `SSH channel ${this.localId} could not be opened`,
                packet.data.language_tag,
            ),
        )
    }

    request(type: string, args: Buffer = Buffer.alloc(0), wantReply = true): Promise<void> {
        if (!this.isOpen || this.remoteId === undefined) {
            return Promise.reject(new Error(`SSH channel ${this.localId} is not open`))
        }
        try {
            validateSSHName(type, "SSH channel request name")
        } catch (error) {
            return Promise.reject(error)
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
            const sequenceNumber = this.client.sendPacket(
                new ChannelRequest({
                    recipient_channel_id: this.remoteId,
                    request_type: type,
                    want_reply: wantReply,
                    args: Buffer.from(args),
                }),
            )
            if (wantReply) {
                const pending = this.pendingRequests.at(-1)!
                pending.unregisterUnimplemented = registerUnimplementedRejection(
                    this.client,
                    sequenceNumber,
                    () => {
                        const index = this.pendingRequests.indexOf(pending)
                        if (index === -1) return
                        this.pendingRequests.splice(index, 1)
                        pending.reject(
                            unimplementedPacketError(
                                sequenceNumber,
                                `channel ${this.localId} request ${type}`,
                            ),
                        )
                    },
                )
            }
        } catch (error) {
            if (wantReply) this.pendingRequests.pop()
            return Promise.reject(error)
        }

        return wantReply
            ? waitForReply(this.client, response, `channel ${this.localId} request ${type} reply`)
            : response
    }

    receiveRequestSuccess(): void {
        const request = this.pendingRequests.shift()
        if (!request) {
            throw new ProtocolError(`Unexpected success response for SSH channel ${this.localId}`)
        }
        request.unregisterUnimplemented?.()
        request.resolve()
    }

    receiveRequestFailure(): void {
        const request = this.pendingRequests.shift()
        if (!request) {
            throw new ProtocolError(`Unexpected failure response for SSH channel ${this.localId}`)
        }
        request.unregisterUnimplemented?.()
        request.reject(new Error(`SSH channel ${this.localId} request failed (${request.type})`))
    }

    receiveWindowAdjust(bytesToAdd: number): void {
        if (this.client.noFlowControl) return
        if (bytesToAdd > MAXIMUM_CHANNEL_WINDOW_SIZE - this.remoteWindowSize) {
            throw new ProtocolError(`SSH channel ${this.localId} window adjustment exceeds uint32`)
        }
        this.remoteWindowSize += bytesToAdd
        this.flushPendingWrites()
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
                throw new ProtocolError("Invalid end-of-write channel request")
            }
            if (this.type !== "session") {
                throw new ProtocolError("End-of-write is only valid on session channels")
            }
            if (this.receivedEndOfWrite) return
            this.receivedEndOfWrite = true
            await this.hooker.triggerHook("endOfWrite")
            if (!this.isOpen) return
            this.emit("endOfWrite")
            if (!this.writableEnded) this.end()
            return
        }

        if (packet.data.request_type === "exit-status") {
            this.validateExitRequest(packet)
            const [exitCode, remaining] = readNextUint32(packet.data.args)
            if (remaining.length !== 0) {
                throw new ProtocolError("Invalid exit-status channel request")
            }
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
            if (remaining.length !== 0) {
                throw new ProtocolError("Invalid exit-signal channel request")
            }

            const signalName = signal.toString("ascii")
            if (signal.some((byte) => byte > 0x7f)) {
                throw new ProtocolError("Invalid exit-signal signal name")
            }
            const normalizedSignal = normalizeSSHSignal(signalName)
            if (normalizedSignal !== signalName) {
                throw new ProtocolError('SSH exit-signal names must omit the "SIG" prefix')
            }
            const decodedErrorMessage = decodeSSHUTF8(errorMessage, "SSH exit-signal message")
            const decodedLanguageTag = decodeSSHLanguageTag(
                languageTag,
                "SSH exit-signal language tag",
            )

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
        const policyCompleted = await this.hooker.triggerHookChecked("request", context, controller)
        this.replyToRequest(packet, policyCompleted && controller.success)
    }

    private validateExitRequest(packet: ChannelRequest): void {
        if (this.type !== "session") {
            throw new ProtocolError("Exit requests are only valid on sessions")
        }
        if (packet.data.want_reply) {
            throw new ProtocolError("SSH exit requests must not request a reply")
        }
        if (this.exitCode !== undefined || this.exitSignal !== undefined) {
            throw new ProtocolError("SSH session received more than one exit result")
        }
    }

    eof(): this {
        if (
            !this.transportClosed &&
            !this.sentEOF &&
            this.remoteId !== undefined &&
            !this.sentClose
        ) {
            this.sentEOF = true
            this.sendEOFIfReady()
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
        void this.sendData(data, encoding).then(() => callback(), callback)
    }

    _final(callback: WriteCallback): void {
        this.eof()
        callback()
    }

    _destroy(error: Error | null, callback: (error?: Error | null) => void): void {
        if (!this.transportClosed && !this.sentClose && this.remoteId !== undefined) {
            this.sendClose()
        }
        const closeError = error ?? this.transportCloseError
        const writeError =
            closeError ?? new Error(`SSH channel ${this.localId} closed during write`)
        while (this.pendingWrites.length > 0) this.pendingWrites.shift()!.reject(writeError)
        while (this.pendingRequests.length > 0) {
            const request = this.pendingRequests.shift()!
            request.unregisterUnimplemented?.()
            request.reject(
                closeError ?? new Error(`SSH channel ${this.localId} closed during request`),
            )
        }
        callback(error)
    }

    /** Send channel data and resolve after SSH flow control permits every resulting packet. */
    sendData(data: Buffer | string, encoding: BufferEncoding = "utf8"): Promise<void> {
        return this.queueData(Buffer.isBuffer(data) ? data : Buffer.from(data, encoding), false)
    }

    protected sendAtomicData(data: Buffer): Promise<void> {
        return this.queueData(data, true)
    }

    private queueData(data: Buffer, atomic: boolean): Promise<void> {
        if (!this.isOpen) {
            return Promise.reject(new Error(`SSH channel ${this.localId} is not open for writing`))
        }
        if (this.sentEOF) {
            return Promise.reject(
                new Error(`SSH channel ${this.localId} is closed for writing after EOF`),
            )
        }
        if (
            atomic &&
            (data.length > this.remoteMaximumPacketSize ||
                data.length > DEFAULT_CHANNEL_PACKET_SIZE)
        ) {
            return Promise.reject(
                new Error(`SSH channel ${this.localId} atomic packet exceeds peer limits`),
            )
        }
        return new Promise<void>((resolve, reject) => {
            this.pendingWrites.push({ data: Buffer.from(data), offset: 0, resolve, reject, atomic })
            this.flushPendingWrites()
        })
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
            throw new ProtocolError(`SSH channel ${this.localId} received data after EOF`)
        }
        if (data.length > this.localMaximumPacketSize) {
            throw new ProtocolError(`SSH channel ${this.localId} received an oversized data packet`)
        }
        if (this.client.noFlowControl) return
        if (data.length > this.localWindowSize) {
            throw new ProtocolError(`SSH channel ${this.localId} received data beyond its window`)
        }
        this.localWindowSize -= data.length
    }

    protected adjustWindowIfNeeded(): void {
        if (this.client.noFlowControl) return
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

    private flushPendingWrites(): void {
        if (this.remoteId === undefined) return
        if (deferApplicationTraffic(this.client, this.resumeWritesAfterRekey)) return
        try {
            while (this.pendingWrites.length > 0) {
                const pending = this.pendingWrites[0]!
                if (
                    !this.client.noFlowControl &&
                    pending.atomic &&
                    this.remoteWindowSize < pending.data.length
                ) {
                    return
                }
                while (
                    pending.offset < pending.data.length &&
                    (this.client.noFlowControl || this.remoteWindowSize > 0) &&
                    this.remoteMaximumPacketSize > 0
                ) {
                    const length = pending.atomic
                        ? pending.data.length
                        : Math.min(
                              pending.data.length - pending.offset,
                              this.client.noFlowControl
                                  ? Number.MAX_SAFE_INTEGER
                                  : this.remoteWindowSize,
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
                    if (!this.client.noFlowControl) this.remoteWindowSize -= length
                }
                if (pending.offset !== pending.data.length) return
                this.pendingWrites.shift()
                pending.resolve()
            }
            this.sendEOFIfReady()
        } catch (error) {
            const writeError = error instanceof Error ? error : new Error(String(error))
            while (this.pendingWrites.length > 0) this.pendingWrites.shift()!.reject(writeError)
            throw writeError
        }
    }

    private sendClose(): void {
        if (this.transportClosed || this.sentClose || this.remoteId === undefined) return
        const writeError = new Error(`SSH channel ${this.localId} closed during write`)
        while (this.pendingWrites.length > 0) this.pendingWrites.shift()!.reject(writeError)
        this.sendEOFIfReady()
        this.sentClose = true
        try {
            this.client.sendPacket(new ChannelClose({ recipient_channel_id: this.remoteId }))
        } finally {
            const requestError = new Error(`SSH channel ${this.localId} closed during request`)
            while (this.pendingRequests.length > 0) {
                const request = this.pendingRequests.shift()!
                request.unregisterUnimplemented?.()
                request.reject(requestError)
            }
        }
    }

    private sendEOFIfReady(): void {
        if (
            !this.sentEOF ||
            this.eofPacketSent ||
            this.pendingWrites.length > 0 ||
            this.transportClosed ||
            this.sentClose ||
            this.remoteId === undefined
        ) {
            return
        }
        this.client.sendPacket(new ChannelEOF({ recipient_channel_id: this.remoteId }))
        this.eofPacketSent = true
    }
}
