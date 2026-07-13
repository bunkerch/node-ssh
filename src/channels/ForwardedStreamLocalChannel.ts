import Channel, {
    DEFAULT_SERVER_CHANNEL_PACKET_SIZE,
    DEFAULT_SERVER_CHANNEL_WINDOW_SIZE,
} from "../Channel.js"
import ServerClient from "../ServerClient.js"
import { serializeBuffer } from "../utils/Buffer.js"
import ChannelStream from "./ChannelStream.js"
import type { StreamLocalConnectionDetails } from "./ClientForwardedStreamLocalChannel.js"

export default class ForwardedStreamLocalChannel extends Channel {
    static channel_type = "forwarded-streamlocal@openssh.com"

    readonly details: Readonly<StreamLocalConnectionDetails>
    readonly stream: ChannelStream

    constructor(client: ServerClient, socketPath: string) {
        super(
            client,
            ForwardedStreamLocalChannel.channel_type,
            Buffer.concat([
                serializeBuffer(Buffer.from(socketPath, "utf8")),
                serializeBuffer(Buffer.alloc(0)),
            ]),
        )
        this.local_initial_window_size = DEFAULT_SERVER_CHANNEL_WINDOW_SIZE
        this.local_maximum_packet_size = DEFAULT_SERVER_CHANNEL_PACKET_SIZE
        this.local_window_size = this.local_initial_window_size
        this.details = Object.freeze({ socketPath })
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
