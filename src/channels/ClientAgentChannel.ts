import assert from "node:assert"
import Client from "../Client.js"
import ChannelOpen from "../packets/ChannelOpen.js"
import ClientChannel from "./ClientChannel.js"

export default class ClientAgentChannel extends ClientChannel {
    static channelType = "auth-agent@openssh.com"

    constructor(client: Client, packet: ChannelOpen) {
        assert(packet.data.channel_type === ClientAgentChannel.channelType)
        assert(packet.data.args.length === 0, "Agent channel open has trailing data")
        super(client, ClientAgentChannel.channelType)
        this.acceptOpen(packet)
    }
}
