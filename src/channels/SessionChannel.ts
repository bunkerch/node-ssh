import Channel from "../Channel.js"
import Client from "../Client.js"
import ServerClient from "../ServerClient.js"

export default class SessionChannel extends Channel {
    static channel_type = "session"

    constructor(client: Client | ServerClient, channel_type: string) {
        super(client, channel_type)

        // taken from OpenSSH
        this.local_initial_window_size = 2 ** 21
        this.local_maximum_packet_size = 2 ** 15
    }
}

Channel.channel_types.set(SessionChannel.channel_type, SessionChannel)
