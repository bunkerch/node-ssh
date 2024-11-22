import assert from "assert"
import Channel from "./Channel.js"
import SessionChannel from "./channels/SessionChannel.js"
import Client from "./Client.js"
import ChannelOpen from "./packets/ChannelOpen.js"
import { ChannelOpenError, ChannelOpenFailureReasonCodes } from "./packets/ChannelOpenFailure.js"
import ServerClient from "./ServerClient.js"

export const channels = new Map<string, typeof Channel>([
    [SessionChannel.channel_type, SessionChannel],
])

export function channelFromChannelOpenPacket(packet: ChannelOpen, client: Client | ServerClient) {
    const constructor = channels.get(packet.data.channel_type)
    if (!constructor) {
        throw new ChannelOpenError(
            ChannelOpenFailureReasonCodes.SSH_OPEN_UNKNOWN_CHANNEL_TYPE,
            client.localChannelIndex++,
            `Unknown channel type: ${JSON.stringify(packet.data.channel_type)}`,
        )
    }

    const channel = new constructor(client, packet.data.channel_type, packet.data.args)
    channel.remoteId = packet.data.sender_channel_id
    channel.remote_initial_window_size = packet.data.initial_window_size
    channel.remote_maximum_packet_size = packet.data.maximum_packet_size
    channel.serverArgs = channel.getServerArgsBuffer()

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
