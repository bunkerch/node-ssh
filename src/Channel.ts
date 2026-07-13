import assert from "node:assert"
import type Client from "./Client.js"
import type ServerClient from "./ServerClient.js"
import ChannelClose from "./packets/ChannelClose.js"
import ChannelData from "./packets/ChannelData.js"
import ChannelEOF from "./packets/ChannelEOF.js"
import ChannelExtendedData from "./packets/ChannelExtendedData.js"
import ChannelFailure from "./packets/ChannelFailure.js"
import ChannelOpen from "./packets/ChannelOpen.js"
import ChannelOpenConfirmation from "./packets/ChannelOpenConfirmation.js"
import ChannelRequest from "./packets/ChannelRequest.js"
import ChannelWindowAdjust from "./packets/ChannelWindowAdjust.js"
import { MAXIMUM_CHANNEL_WINDOW_SIZE } from "./constants.js"
import { ServerHookerChannelRequestController } from "./Server.js"

export const DEFAULT_SERVER_CHANNEL_WINDOW_SIZE = 2 ** 21
export const DEFAULT_SERVER_CHANNEL_PACKET_SIZE = 2 ** 15

type WriteCallback = (error?: Error | null) => void

interface PendingChannelWrite {
    data: Buffer
    offset: number
    extendedDataType?: number
    callback: WriteCallback
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

    serverArgs: Buffer | undefined
    clientArgs: Buffer

    private readonly pendingWrites: PendingChannelWrite[] = []
    private inputBlocked = false
    private sentEOF = false
    private receivedEOF = false
    private sentClose = false
    private receivedClose = false

    constructor(
        client: Client | ServerClient,
        channel_type: string,
        clientArgs: Buffer = Buffer.alloc(0),
    ) {
        this.client = client
        this.channel_type = channel_type
        this.localId = client.localChannelIndex++
        this.clientArgs = clientArgs
    }

    get isOpen(): boolean {
        return this.remoteId !== undefined && !this.sentClose && !this.receivedClose
    }

    get isFullyClosed(): boolean {
        return this.sentClose && this.receivedClose
    }

    debug(...msg: unknown[]): void {
        this.client.debug(`[Channel:${this.channel_type}#${this.localId}]`, ...msg)
    }

    configureRemote(open: ChannelOpen): void {
        this.remoteId = open.data.sender_channel_id
        this.remote_initial_window_size = open.data.initial_window_size
        this.remote_window_size = open.data.initial_window_size
        this.remote_maximum_packet_size = open.data.maximum_packet_size
        this.local_window_size = this.local_initial_window_size
    }

    getChannelOpenPacket(): ChannelOpen {
        return new ChannelOpen({
            channel_type: this.channel_type,
            initial_window_size: this.local_initial_window_size,
            maximum_packet_size: this.local_maximum_packet_size,
            sender_channel_id: this.localId,
            args: this.clientArgs,
        })
    }

    getChannelOpenConfirmationPacket(): ChannelOpenConfirmation {
        assert(
            this.remoteId !== undefined,
            "ChannelOpenConfirmation packet was demanded, but remoteId was not set.",
        )
        assert(
            this.serverArgs !== undefined,
            "ChannelOpenConfirmation packet was demanded, but serverArgs was not set.",
        )

        return new ChannelOpenConfirmation({
            recipient_channel_id: this.remoteId,
            sender_channel_id: this.localId,
            initial_window_size: this.local_initial_window_size,
            maximum_packet_size: this.local_maximum_packet_size,
            args: this.serverArgs,
        })
    }

    getServerArgsBuffer(): Buffer {
        return Buffer.alloc(0)
    }

    async preHandleChannelRequest(request: ChannelRequest): Promise<boolean> {
        if (!("server" in this.client)) return false

        const controller: ServerHookerChannelRequestController = { deny: false }
        const serverClient = this.client as ServerClient
        await serverClient.server.hooker.triggerHook(
            "channelRequest",
            this,
            controller,
            serverClient,
        )
        if (controller.deny) await Channel.prototype.handleChannelRequest.call(this, request)
        return controller.deny
    }

    async handleChannelRequest(request: ChannelRequest): Promise<void> {
        assert(
            this.remoteId !== undefined,
            "handleChannelRequest was demanded, but remoteId was not set.",
        )
        if (request.data.want_reply) {
            this.client.sendPacket(new ChannelFailure({ recipient_channel_id: this.remoteId }))
        }
    }

    sendData(data: Buffer, callback: WriteCallback): void {
        this.queueData(data, undefined, callback)
    }

    sendExtendedData(dataType: number, data: Buffer, callback: WriteCallback): void {
        this.queueData(data, dataType, callback)
    }

    sendRequest(type: string, args: Buffer = Buffer.alloc(0), wantReply = false): void {
        if (!this.isOpen || this.remoteId === undefined) {
            throw new Error(`SSH channel ${this.localId} is not open`)
        }
        this.client.sendPacket(
            new ChannelRequest({
                recipient_channel_id: this.remoteId,
                request_type: type,
                want_reply: wantReply,
                args,
            }),
        )
    }

    receiveWindowAdjust(bytesToAdd: number): void {
        if (bytesToAdd > MAXIMUM_CHANNEL_WINDOW_SIZE - this.remote_window_size) {
            throw new Error(`SSH channel ${this.localId} window adjustment exceeds uint32`)
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
        this.handleClose()
    }

    resumeInput(): void {
        this.inputBlocked = false
        this.adjustWindowIfNeeded()
    }

    sendEOF(): void {
        if (this.sentEOF || this.remoteId === undefined || this.sentClose) return
        this.sentEOF = true
        this.client.sendPacket(new ChannelEOF({ recipient_channel_id: this.remoteId }))
    }

    close(): void {
        this.sendEOF()
        this.sendClose()
    }

    terminate(): void {
        this.sendClose()
    }

    abort(error = new Error(`SSH channel ${this.localId} connection closed`)): void {
        this.failPendingWrites(error)
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
        callback: WriteCallback,
    ): void {
        if (!this.isOpen) {
            callback(new Error(`SSH channel ${this.localId} is not open for writing`))
            return
        }
        if (data.length === 0) {
            callback()
            return
        }
        this.pendingWrites.push({ data, offset: 0, extendedDataType, callback })
        this.flushPendingWrites()
    }

    private flushPendingWrites(): void {
        if (this.remoteId === undefined || this.sentClose) return

        while (
            this.pendingWrites.length > 0 &&
            this.remote_window_size > 0 &&
            this.remote_maximum_packet_size > 0
        ) {
            const pending = this.pendingWrites[0]
            const length = Math.min(
                pending.data.length - pending.offset,
                this.remote_window_size,
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
            this.remote_window_size -= length
            if (pending.offset === pending.data.length) {
                this.pendingWrites.shift()
                pending.callback()
            }
        }
    }

    private consumeLocalWindow(data: Buffer): void {
        if (this.receivedEOF) {
            throw new Error(`SSH channel ${this.localId} received data after EOF`)
        }
        if (data.length > this.local_maximum_packet_size) {
            throw new Error(`SSH channel ${this.localId} received an oversized data packet`)
        }
        if (data.length > this.local_window_size) {
            throw new Error(`SSH channel ${this.localId} received data beyond its window`)
        }
        this.local_window_size -= data.length
    }

    private adjustWindowIfNeeded(): void {
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
        if (this.sentClose || this.remoteId === undefined) return
        this.sentClose = true
        this.client.sendPacket(new ChannelClose({ recipient_channel_id: this.remoteId }))
    }

    private failPendingWrites(error: Error): void {
        while (this.pendingWrites.length > 0) this.pendingWrites.shift()!.callback(error)
    }
}
