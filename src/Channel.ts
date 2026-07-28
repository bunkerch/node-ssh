import assert from "node:assert"
import type Client from "./Client.js"
import type ServerClient from "./ServerClient.js"
import ChannelClose from "./packets/ChannelClose.js"
import ChannelData from "./packets/ChannelData.js"
import ChannelEOF from "./packets/ChannelEOF.js"
import ChannelExtendedData from "./packets/ChannelExtendedData.js"
import ChannelFailure from "./packets/ChannelFailure.js"
import ChannelSuccess from "./packets/ChannelSuccess.js"
import ChannelOpen from "./packets/ChannelOpen.js"
import ChannelOpenConfirmation from "./packets/ChannelOpenConfirmation.js"
import ChannelOpenFailure, { ChannelOpenError } from "./packets/ChannelOpenFailure.js"
import ChannelRequest from "./packets/ChannelRequest.js"
import ChannelWindowAdjust from "./packets/ChannelWindowAdjust.js"
import { MAXIMUM_CHANNEL_WINDOW_SIZE } from "./constants.js"
import { ServerHookerChannelRequestController } from "./Server.js"
import { ProtocolError } from "./packets/Disconnect.js"
import { waitForReply } from "./ReplyTimeout.js"
import allocateChannelIdentifier from "./utils/ChannelIdentifier.js"
import { deferApplicationTraffic } from "./utils/RekeyQueue.js"
import { validateSSHName } from "./utils/SSHName.js"
import {
    registerUnimplementedRejection,
    unimplementedPacketError,
} from "./utils/UnimplementedRegistry.js"

export const DEFAULT_SERVER_CHANNEL_WINDOW_SIZE = 2 ** 21
export const DEFAULT_SERVER_CHANNEL_PACKET_SIZE = 2 ** 15

interface PendingChannelWrite {
    data: Buffer
    offset: number
    extendedDataType?: number
    resolve: () => void
    reject: (error: Error) => void
    atomic: boolean
}
interface PendingChannelRequest {
    type: string
    resolve: () => void
    reject: (error: Error) => void
    unregisterUnimplemented?: () => void
}

export default class Channel {
    client: Client | ServerClient

    channel_type: string
    localId: number
    remoteId: number | undefined

    local_initial_window_size = 0
    remote_initial_window_size = 0
    local_maximum_packet_size = 0
    remote_maximum_packet_size = 0
    local_window_size = 0
    remote_window_size = 0

    #serverArgs: Buffer | undefined
    readonly #clientArgs: Buffer

    private readonly pendingWrites: PendingChannelWrite[] = []
    private readonly pendingRequests: PendingChannelRequest[] = []
    private inputBlocked = false
    private sentEOF = false
    private eofPacketSent = false
    private receivedEOF = false
    private sentEndOfWrite = false
    private receivedEndOfWrite = false
    private outboundStopped = false
    private sentClose = false
    private receivedClose = false
    private aborted = false
    private openSettled = false
    private openResolve!: () => void
    private openReject!: (error: Error) => void
    private readonly openPromise: Promise<void>
    private readonly resumeWritesAfterRekey = () => this.flushPendingWrites()

    constructor(
        client: Client | ServerClient,
        channel_type: string,
        clientArgs: Buffer = Buffer.alloc(0),
    ) {
        if (!Buffer.isBuffer(clientArgs)) {
            throw new TypeError("SSH channel open arguments must be a buffer")
        }
        this.client = client
        this.channel_type = channel_type
        this.localId = allocateChannelIdentifier(client)
        this.#clientArgs = Buffer.from(clientArgs)
        this.openPromise = new Promise<void>((resolve, reject) => {
            this.openResolve = resolve
            this.openReject = reject
        })
    }

    /** Owned channel-open arguments. Each access returns a defensive copy. */
    get clientArgs(): Buffer {
        return Buffer.from(this.#clientArgs)
    }

    /** Owned channel-open confirmation arguments, once configured. */
    get serverArgs(): Buffer | undefined {
        return this.#serverArgs === undefined ? undefined : Buffer.from(this.#serverArgs)
    }

    set serverArgs(value: Buffer | undefined) {
        if (value !== undefined && !Buffer.isBuffer(value)) {
            throw new TypeError("SSH channel open confirmation arguments must be a buffer")
        }
        this.#serverArgs = value === undefined ? undefined : Buffer.from(value)
    }

    get isOpen(): boolean {
        return (
            this.remoteId !== undefined && !this.sentClose && !this.receivedClose && !this.aborted
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

    debug(...msg: unknown[]): void {
        this.client.debug(`[Channel:${this.channel_type}#${this.localId}]`, ...msg)
    }

    configureRemote(open: ChannelOpen): void {
        if (this.openSettled)
            throw new ProtocolError(`SSH channel ${this.localId} was opened more than once`)
        this.remoteId = open.data.sender_channel_id
        this.remote_initial_window_size = open.data.initial_window_size
        this.remote_window_size = open.data.initial_window_size
        this.remote_maximum_packet_size = open.data.maximum_packet_size
        this.local_window_size = this.local_initial_window_size
        this.openSettled = true
        this.openResolve()
    }

    confirmOpen(confirmation: ChannelOpenConfirmation): void {
        if (this.openSettled)
            throw new ProtocolError(`SSH channel ${this.localId} was opened more than once`)
        this.remoteId = confirmation.data.sender_channel_id
        this.remote_initial_window_size = confirmation.data.initial_window_size
        this.remote_window_size = confirmation.data.initial_window_size
        this.remote_maximum_packet_size = confirmation.data.maximum_packet_size
        this.local_window_size = this.local_initial_window_size
        this.openSettled = true
        this.openResolve()
    }

    failOpen(failure: ChannelOpenFailure): void {
        if (this.openSettled) {
            throw new ProtocolError(`SSH channel ${this.localId} open was settled twice`)
        }
        this.openSettled = true
        this.openReject(
            new ChannelOpenError(
                failure.data.reason_code,
                failure.data.description || `SSH channel ${this.localId} could not be opened`,
                failure.data.language_tag,
            ),
        )
    }

    waitUntilOpen(): Promise<void> {
        return this.openPromise
    }

    getChannelOpenPacket(): ChannelOpen {
        return new ChannelOpen({
            channel_type: this.channel_type,
            initial_window_size: this.local_initial_window_size,
            maximum_packet_size: this.local_maximum_packet_size,
            sender_channel_id: this.localId,
            args: this.#clientArgs,
        })
    }

    getChannelOpenConfirmationPacket(): ChannelOpenConfirmation {
        assert(
            this.remoteId !== undefined,
            "ChannelOpenConfirmation packet was demanded, but remoteId was not set.",
        )
        assert(
            this.#serverArgs !== undefined,
            "ChannelOpenConfirmation packet was demanded, but serverArgs was not set.",
        )

        return new ChannelOpenConfirmation({
            recipient_channel_id: this.remoteId,
            sender_channel_id: this.localId,
            initial_window_size: this.local_initial_window_size,
            maximum_packet_size: this.local_maximum_packet_size,
            args: this.#serverArgs,
        })
    }

    getServerArgsBuffer(): Buffer {
        return Buffer.alloc(0)
    }

    async preHandleChannelRequest(request: ChannelRequest): Promise<boolean> {
        if (!("server" in this.client)) return false

        const controller: ServerHookerChannelRequestController = { deny: false }
        const serverClient = this.client as ServerClient
        const policyCompleted = await serverClient.server.hooker.triggerHookChecked(
            "channelRequest",
            this,
            controller,
            serverClient,
            request,
        )
        if (!this.isOpen) return true
        if (!policyCompleted || controller.deny) {
            await Channel.prototype.handleChannelRequest.call(this, request)
            return true
        }
        if (!controller.handled) return false
        if (request.data.want_reply && this.isOpen && this.remoteId !== undefined) {
            this.client.sendPacket(
                controller.success
                    ? new ChannelSuccess({ recipient_channel_id: this.remoteId })
                    : new ChannelFailure({ recipient_channel_id: this.remoteId }),
            )
        }
        return true
    }

    async handleChannelRequest(request: ChannelRequest): Promise<void> {
        assert(
            this.remoteId !== undefined,
            "handleChannelRequest was demanded, but remoteId was not set.",
        )
        if (request.data.want_reply && this.isOpen) {
            this.client.sendPacket(new ChannelFailure({ recipient_channel_id: this.remoteId }))
        }
    }

    sendData(data: Buffer): Promise<void> {
        return this.queueData(data, undefined, false)
    }

    protected sendAtomicData(data: Buffer): Promise<void> {
        return this.queueData(data, undefined, true)
    }

    sendExtendedData(dataType: number, data: Buffer): Promise<void> {
        return this.queueData(data, dataType, false)
    }

    /**
     * Send a channel notification which cannot receive a protocol reply.
     *
     * Use request() for a request whose success or failure must be awaited.
     */
    sendRequest(type: string, args: Buffer = Buffer.alloc(0)): void {
        this.sendRequestPacket(type, args, false)
    }

    private sendRequestPacket(type: string, args: Buffer, wantReply: boolean): number {
        if (!this.isOpen || this.remoteId === undefined) {
            throw new Error(`SSH channel ${this.localId} is not open`)
        }
        validateSSHName(type, "SSH channel request name")
        if (!Buffer.isBuffer(args)) {
            throw new TypeError("SSH channel request arguments must be a buffer")
        }
        return this.client.sendPacket(
            new ChannelRequest({
                recipient_channel_id: this.remoteId,
                request_type: type,
                want_reply: wantReply,
                args,
            }),
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
            const sequenceNumber = this.sendRequestPacket(type, Buffer.from(args), wantReply)
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
        if (bytesToAdd > MAXIMUM_CHANNEL_WINDOW_SIZE - this.remote_window_size) {
            throw new ProtocolError(`SSH channel ${this.localId} window adjustment exceeds uint32`)
        }
        this.remote_window_size += bytesToAdd
        this.flushPendingWrites()
    }

    receiveData(data: Buffer): void {
        this.consumeLocalWindow(data)
        this.inputBlocked ||= !this.handleData(data)
        this.adjustWindowIfNeeded()
    }

    receiveExtendedData(dataType: number, data: Buffer): void {
        this.consumeLocalWindow(data)
        this.inputBlocked ||= !this.handleExtendedData(dataType, data)
        this.adjustWindowIfNeeded()
    }

    receiveEOF(): void {
        if (this.receivedEOF) return
        this.receivedEOF = true
        this.handleEOF()
    }

    receiveClose(): void {
        if (this.receivedClose) return
        this.receivedClose = true
        this.receiveEOF()
        if (!this.sentClose) this.sendClose()
        this.failPendingWrites(new Error(`SSH channel ${this.localId} closed during write`))
        this.failPendingRequests(new Error(`SSH channel ${this.localId} closed during request`))
        this.handleClose()
    }

    resumeInput(): void {
        this.inputBlocked = false
        this.adjustWindowIfNeeded()
    }

    sendEOF(): void {
        if (this.aborted || this.sentEOF || this.remoteId === undefined || this.sentClose) return
        this.sentEOF = true
        this.sendEOFIfReady()
    }

    /** Ask the peer to stop sending channel data while keeping this channel open. */
    sendEndOfWrite(force = false): boolean {
        if (this.sentEndOfWrite || !this.isOpen || this.channel_type !== "session") return false
        const peer = this.client as Partial<ServerClient>
        const software = peer.clientProtocolVersion?.protocol_software ?? ""
        if (!force && !software.startsWith("OpenSSH_")) return false
        this.sendRequest("eow@openssh.com")
        this.sentEndOfWrite = true
        return true
    }

    receiveEndOfWrite(): void {
        if (this.receivedEndOfWrite) return
        this.receivedEndOfWrite = true
        this.outboundStopped = true
        this.failPendingWrites(new Error(`SSH channel ${this.localId} received end-of-write`))
        this.sendEOF()
    }

    close(): void {
        this.sendEOF()
        this.sendClose()
    }

    terminate(): void {
        this.sendClose()
    }

    abort(error = new Error(`SSH channel ${this.localId} connection closed`)): void {
        this.aborted = true
        if (!this.openSettled) {
            this.openSettled = true
            this.openReject(error)
        }
        this.failPendingWrites(error)
        this.failPendingRequests(error)
        this.handleClose()
    }

    protected handleData(data: Buffer): boolean {
        void data
        return true
    }

    protected handleExtendedData(dataType: number, data: Buffer): boolean {
        void dataType
        void data
        return true
    }

    protected handleEOF(): void {
        // Channel types can end their readable application stream here.
    }

    protected handleClose(): void {
        // Channel types can dispose application resources here.
    }

    private queueData(
        data: Buffer,
        extendedDataType: number | undefined,
        atomic: boolean,
    ): Promise<void> {
        if (!this.isOpen) {
            return Promise.reject(new Error(`SSH channel ${this.localId} is not open for writing`))
        }
        if (this.outboundStopped) {
            return Promise.reject(new Error(`SSH channel ${this.localId} received end-of-write`))
        }
        if (this.sentEOF) {
            return Promise.reject(
                new Error(`SSH channel ${this.localId} is closed for writing after EOF`),
            )
        }
        if (data.length === 0) return Promise.resolve()
        if (
            atomic &&
            (data.length > this.remote_maximum_packet_size ||
                data.length > DEFAULT_SERVER_CHANNEL_PACKET_SIZE)
        ) {
            return Promise.reject(
                new Error(`SSH channel ${this.localId} atomic packet exceeds peer limits`),
            )
        }
        return new Promise<void>((resolve, reject) => {
            this.pendingWrites.push({
                data: Buffer.from(data),
                offset: 0,
                extendedDataType,
                resolve,
                reject,
                atomic,
            })
            this.flushPendingWrites()
        })
    }

    private flushPendingWrites(): void {
        if (this.remoteId === undefined || this.sentClose) return
        if (deferApplicationTraffic(this.client, this.resumeWritesAfterRekey)) return
        try {
            while (
                this.pendingWrites.length > 0 &&
                (this.client.noFlowControl || this.remote_window_size > 0) &&
                this.remote_maximum_packet_size > 0
            ) {
                const pending = this.pendingWrites[0]
                if (
                    !this.client.noFlowControl &&
                    pending.atomic &&
                    this.remote_window_size < pending.data.length
                ) {
                    return
                }
                const length = pending.atomic
                    ? pending.data.length
                    : Math.min(
                          pending.data.length - pending.offset,
                          this.client.noFlowControl
                              ? Number.MAX_SAFE_INTEGER
                              : this.remote_window_size,
                          this.remote_maximum_packet_size,
                          DEFAULT_SERVER_CHANNEL_PACKET_SIZE,
                      )
                const data = pending.data.subarray(pending.offset, pending.offset + length)
                if (pending.extendedDataType === undefined) {
                    this.client.sendPacket(
                        new ChannelData({ recipient_channel_id: this.remoteId, data }),
                    )
                } else {
                    this.client.sendPacket(
                        new ChannelExtendedData({
                            recipient_channel_id: this.remoteId,
                            data_type_code: pending.extendedDataType,
                            data,
                        }),
                    )
                }
                pending.offset += length
                if (!this.client.noFlowControl) this.remote_window_size -= length
                if (pending.offset === pending.data.length) {
                    this.pendingWrites.shift()
                    pending.resolve()
                }
            }
            this.sendEOFIfReady()
        } catch (error) {
            const writeError = error instanceof Error ? error : new Error(String(error))
            this.failPendingWrites(writeError)
            throw writeError
        }
    }

    private consumeLocalWindow(data: Buffer): void {
        if (this.receivedEOF) {
            throw new ProtocolError(`SSH channel ${this.localId} received data after EOF`)
        }
        if (data.length > this.local_maximum_packet_size) {
            throw new ProtocolError(`SSH channel ${this.localId} received an oversized data packet`)
        }
        if (this.client.noFlowControl) return
        if (data.length > this.local_window_size) {
            throw new ProtocolError(`SSH channel ${this.localId} received data beyond its window`)
        }
        this.local_window_size -= data.length
    }

    private adjustWindowIfNeeded(): void {
        if (this.client.noFlowControl) return
        if (
            this.remoteId === undefined ||
            this.sentClose ||
            this.inputBlocked ||
            this.local_window_size > this.local_initial_window_size / 2
        ) {
            return
        }
        const bytesToAdd = this.local_initial_window_size - this.local_window_size
        if (bytesToAdd === 0) return
        this.local_window_size += bytesToAdd
        this.client.sendPacket(
            new ChannelWindowAdjust({
                recipient_channel_id: this.remoteId,
                bytes_to_add: bytesToAdd,
            }),
        )
    }

    private sendClose(): void {
        if (this.aborted || this.sentClose || this.remoteId === undefined) return
        this.failPendingWrites(new Error(`SSH channel ${this.localId} closed during write`))
        this.sendEOFIfReady()
        this.sentClose = true
        try {
            this.client.sendPacket(new ChannelClose({ recipient_channel_id: this.remoteId }))
        } finally {
            this.failPendingRequests(new Error(`SSH channel ${this.localId} closed during request`))
        }
    }

    private sendEOFIfReady(): void {
        if (
            !this.sentEOF ||
            this.eofPacketSent ||
            this.pendingWrites.length > 0 ||
            this.aborted ||
            this.sentClose ||
            this.remoteId === undefined
        ) {
            return
        }
        this.client.sendPacket(new ChannelEOF({ recipient_channel_id: this.remoteId }))
        this.eofPacketSent = true
    }

    private failPendingWrites(error: Error): void {
        while (this.pendingWrites.length > 0) this.pendingWrites.shift()!.reject(error)
    }

    private failPendingRequests(error: Error): void {
        while (this.pendingRequests.length > 0) {
            const request = this.pendingRequests.shift()!
            request.unregisterUnimplemented?.()
            request.reject(error)
        }
    }
}
