import Channel from "./Channel.js"
import SessionChannel from "./channels/SessionChannel.js"
import Client from "./Client.js"
import ChannelOpen from "./packets/ChannelOpen.js"
import { ChannelOpenError, ChannelOpenFailureReasonCodes } from "./packets/ChannelOpenFailure.js"
import ServerClient from "./ServerClient.js"
import DirectTCPIPChannel from "./channels/DirectTCPIPChannel.js"
import DirectStreamLocalChannel from "./channels/DirectStreamLocalChannel.js"

export const channels = new Map<string, typeof Channel>([
    [SessionChannel.channel_type, SessionChannel],
    [DirectTCPIPChannel.channel_type, DirectTCPIPChannel],
    [DirectStreamLocalChannel.channel_type, DirectStreamLocalChannel],
])

export function channelFromChannelOpenPacket(packet: ChannelOpen, client: Client | ServerClient) {
    const constructor = channels.get(packet.data.channel_type)
    if (!constructor) {
        throw new ChannelOpenError(
            ChannelOpenFailureReasonCodes.SSH_OPEN_UNKNOWN_CHANNEL_TYPE,
            packet.data.sender_channel_id,
            `Unknown channel type: ${JSON.stringify(packet.data.channel_type)}`,
        )
    }

    const channel = new constructor(client, packet.data.channel_type, packet.data.args)
    channel.configureRemote(packet)
    channel.serverArgs = channel.getServerArgsBuffer()

    return channel
}
