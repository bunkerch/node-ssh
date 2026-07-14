import Channel, {
    DEFAULT_SERVER_CHANNEL_PACKET_SIZE,
    DEFAULT_SERVER_CHANNEL_WINDOW_SIZE,
} from "../Channel.js"
import ServerClient from "../ServerClient.js"
import { serializeBuffer, serializeUint32 } from "../utils/Buffer.js"
import { encodeSSHUTF8 } from "../utils/SSHText.js"
import ChannelStream from "./ChannelStream.js"
import type { X11ConnectionDetails } from "./ClientX11Channel.js"

export default class ForwardedX11Channel extends Channel {
    static channel_type = "x11"

    readonly details: Readonly<X11ConnectionDetails>
    readonly stream: ChannelStream

    constructor(client: ServerClient, details: X11ConnectionDetails) {
        super(
            client,
            ForwardedX11Channel.channel_type,
            Buffer.concat([
                serializeBuffer(encodeSSHUTF8(details.originatorAddress, "X11 originator address")),
                serializeUint32(details.originatorPort),
            ]),
        )
        this.local_initial_window_size = DEFAULT_SERVER_CHANNEL_WINDOW_SIZE
        this.local_maximum_packet_size = DEFAULT_SERVER_CHANNEL_PACKET_SIZE
        this.local_window_size = this.local_initial_window_size
        this.details = Object.freeze({ ...details })
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
