import Channel, {
    DEFAULT_SERVER_CHANNEL_PACKET_SIZE,
    DEFAULT_SERVER_CHANNEL_WINDOW_SIZE,
} from "../Channel.js"
import ServerClient from "../ServerClient.js"
import ChannelStream from "./ChannelStream.js"
import {
    agentChannelType,
    LEGACY_AGENT_CHANNEL,
    type AgentForwardingProtocol,
} from "../AgentForwarding.js"

export default class ForwardedAgentChannel extends Channel {
    static channel_type = LEGACY_AGENT_CHANNEL

    readonly stream: ChannelStream

    constructor(client: ServerClient, protocol: AgentForwardingProtocol = "legacy") {
        super(client, agentChannelType(protocol))
        this.local_initial_window_size = DEFAULT_SERVER_CHANNEL_WINDOW_SIZE
        this.local_maximum_packet_size = DEFAULT_SERVER_CHANNEL_PACKET_SIZE
        this.local_window_size = this.local_initial_window_size
        this.stream = new ChannelStream(this)
    }

    protected handleData(data: Buffer): boolean {
        return this.stream.receive(data)
    }

    protected handleEOF(): void {
        this.stream.receiveEOF()
    }

    protected handleClose(): void {
        this.stream.closeFromRemote()
    }
}
