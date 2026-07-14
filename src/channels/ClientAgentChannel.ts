import assert from "node:assert"
import Client from "../Client.js"
import ChannelOpen from "../packets/ChannelOpen.js"
import ClientChannel from "./ClientChannel.js"
import { LEGACY_AGENT_CHANNEL, RFC9987_AGENT_CHANNEL } from "../AgentForwarding.js"

export default class ClientAgentChannel extends ClientChannel {
    static channelType = LEGACY_AGENT_CHANNEL
    static channelTypes = Object.freeze([RFC9987_AGENT_CHANNEL, LEGACY_AGENT_CHANNEL])

    constructor(client: Client, packet: ChannelOpen) {
        assert(ClientAgentChannel.channelTypes.includes(packet.data.channel_type))
        assert(packet.data.args.length === 0, "Agent channel open has trailing data")
        super(client, packet.data.channel_type)
        this.acceptOpen(packet)
    }
}
