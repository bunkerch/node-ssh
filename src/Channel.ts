import assert from "assert"
import Client from "./Client.js"
import ChannelOpen from "./packets/ChannelOpen.js"
import { ChannelOpenError, ChannelOpenFailureReasonCodes } from "./packets/ChannelOpenFailure.js"
import ServerClient from "./ServerClient.js"
import ChannelOpenConfirmation from "./packets/ChannelOpenConfirmation.js"

export default class Channel {
    static channel_types = new Map<string, typeof Channel>()

    client: Client | ServerClient

    channel_type: string
    localId: number
    remoteId: number | undefined

    local_initial_window_size: number = 0
    remote_initial_window_size: number = 0
    local_maximum_packet_size: number = 0
    remote_maximum_packet_size: number = 0

    constructor(client: Client | ServerClient, channel_type: string) {
        this.client = client
        this.channel_type = channel_type
        this.localId = client.localChannelIndex++
    }

    getChannelOpenPacket() {
        return new ChannelOpen({
            channel_type: this.channel_type,
            initial_window_size: this.local_initial_window_size,
            maximum_packet_size: this.local_maximum_packet_size,
            sender_channel_id: this.localId,
            args: Buffer.alloc(0),
        })
    }

    getChannelOpenConfirmationPacket() {
        assert(
            this.remoteId !== undefined,
            "ChannelOpenConfirmation packet was demanded, but remoteId was not set.",
        )
        return new ChannelOpenConfirmation({
            recipient_channel_id: this.localId,
            sender_channel_id: this.remoteId!,
            initial_window_size: this.local_initial_window_size,
            maximum_packet_size: this.local_maximum_packet_size,
            args: Buffer.alloc(0),
        })
    }

    static fromChannelOpenPacket(packet: ChannelOpen, client: Client | ServerClient) {
        const constructor = Channel.channel_types.get(packet.data.channel_type)
        if (!constructor) {
            throw new ChannelOpenError(
                ChannelOpenFailureReasonCodes.SSH_OPEN_UNKNOWN_CHANNEL_TYPE,
                client.localChannelIndex++,
                `Unknown channel type: ${JSON.stringify(packet.data.channel_type)}`,
            )
        }

        const channel = new constructor(client, packet.data.channel_type)
        channel.remoteId = packet.data.sender_channel_id
        channel.remote_initial_window_size = packet.data.initial_window_size
        channel.remote_maximum_packet_size = packet.data.maximum_packet_size

        assert(
            channel.remote_initial_window_size != 0,
            new ChannelOpenError(
                ChannelOpenFailureReasonCodes.SSH_OPEN_CONNECT_FAILED,
                channel.localId,
                `Misconfigured remote initial window size`,
            ),
        )
        assert(
            channel.local_initial_window_size != 0,
            new ChannelOpenError(
                ChannelOpenFailureReasonCodes.SSH_OPEN_CONNECT_FAILED,
                channel.localId,
                `Misconfigured local initial window size`,
            ),
        )
        assert(
            channel.remote_maximum_packet_size != 0,
            new ChannelOpenError(
                ChannelOpenFailureReasonCodes.SSH_OPEN_CONNECT_FAILED,
                channel.localId,
                `Misconfigured remote maximum packet size`,
            ),
        )
        assert(
            channel.local_maximum_packet_size != 0,
            new ChannelOpenError(
                ChannelOpenFailureReasonCodes.SSH_OPEN_CONNECT_FAILED,
                channel.localId,
                `Misconfigured local maximum packet size`,
            ),
        )

        return channel
    }
}
