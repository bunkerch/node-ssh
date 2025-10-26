import assert from "assert"
import Client from "./Client.js"
import ChannelOpen from "./packets/ChannelOpen.js"
import ServerClient from "./ServerClient.js"
import ChannelOpenConfirmation from "./packets/ChannelOpenConfirmation.js"
import ChannelRequest from "./packets/ChannelRequest.js"
import ChannelFailure from "./packets/ChannelFailure.js"
import { ServerHookerChannelRequestController } from "./Server.js"
import ChannelEOF from "./packets/ChannelEOF.js"
import ChannelClose from "./packets/ChannelClose.js"

export type BaseChannelEvents = {
    asd: ["meow"]
}
export default class Channel {
    client: Client | ServerClient

    channel_type: string
    localId: number
    remoteId: number | undefined

    local_initial_window_size: number = 0
    remote_initial_window_size: number = 0
    local_maximum_packet_size: number = 0
    remote_maximum_packet_size: number = 0

    serverArgs: Buffer | undefined
    clientArgs: Buffer

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

    debug(...msg: any[]) {
        return this.client.debug(`[Channel:${this.channel_type}#${this.localId}]`, ...msg)
    }

    getChannelOpenPacket() {
        return new ChannelOpen({
            channel_type: this.channel_type,
            initial_window_size: this.local_initial_window_size,
            maximum_packet_size: this.local_maximum_packet_size,
            sender_channel_id: this.localId,
            args: this.clientArgs,
        })
    }

    getChannelOpenConfirmationPacket() {
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

    getServerArgsBuffer() {
        return Buffer.alloc(0)
    }

    async preHandleChannelRequest(request: ChannelRequest): Promise<boolean> {
        if (this.client instanceof ServerClient) {
            const controller: ServerHookerChannelRequestController = {
                deny: false,
            }

            await this.client.server.hooker.triggerHook(
                "channelRequest",
                this,
                controller,
                this.client,
            )

            if (controller.deny) {
                // call this without any extend
                // this will deny the request.
                await Channel.prototype.handleChannelRequest.call(this, request)
            }

            return controller.deny
        }
        // TODO: Implement deny for Client

        return false
    }

    async handleChannelRequest(request: ChannelRequest): Promise<void> {
        assert(
            this.remoteId !== undefined,
            "handleChannelRequest was demanded, but remoteId was not set.",
        )

        if (!request.data.want_reply) return

        this.client.sendPacket(
            new ChannelFailure({
                recipient_channel_id: this.remoteId,
            }),
        )
    }

    sendEOF() {
        assert(this.remoteId !== undefined, "sendEOF was demanded, but remoteId was not set.")

        this.client.sendPacket(
            new ChannelEOF({
                recipient_channel_id: this.remoteId,
            }),
        )
    }

    close() {
        this.sendEOF()
        this.terminate()
    }

    terminate() {
        assert(this.remoteId !== undefined, "terminate was demanded, but remoteId was not set.")

        this.client.sendPacket(
            new ChannelClose({
                recipient_channel_id: this.remoteId,
            }),
        )
    }
}
