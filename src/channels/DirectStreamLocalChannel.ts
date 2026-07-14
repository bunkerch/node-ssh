import assert from "node:assert"
import Channel, {
    DEFAULT_SERVER_CHANNEL_PACKET_SIZE,
    DEFAULT_SERVER_CHANNEL_WINDOW_SIZE,
} from "../Channel.js"
import Client from "../Client.js"
import ServerClient from "../ServerClient.js"
import { readNextBuffer, readNextUint32 } from "../utils/Buffer.js"
import { decodeSSHUTF8 } from "../utils/SSHText.js"
import ChannelStream from "./ChannelStream.js"
import type { StreamLocalConnectionDetails } from "./ClientForwardedStreamLocalChannel.js"

export default class DirectStreamLocalChannel extends Channel {
    static channel_type = "direct-streamlocal@openssh.com"

    readonly details: Readonly<StreamLocalConnectionDetails>
    readonly stream: ChannelStream

    constructor(client: Client | ServerClient, channelType: string, clientArgs = Buffer.alloc(0)) {
        if (client instanceof Client) {
            throw new Error(
                "A client must not accept a server-initiated direct-streamlocal channel",
            )
        }
        super(client, channelType, clientArgs)
        this.local_initial_window_size = DEFAULT_SERVER_CHANNEL_WINDOW_SIZE
        this.local_maximum_packet_size = DEFAULT_SERVER_CHANNEL_PACKET_SIZE
        this.details = Object.freeze(this.parseDetails(clientArgs))
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

    private parseDetails(raw: Buffer): StreamLocalConnectionDetails {
        const [socketPath, afterSocketPath] = readNextBuffer(raw)
        const [, afterReservedString] = readNextBuffer(afterSocketPath)
        const [, remaining] = readNextUint32(afterReservedString)
        assert(remaining.length === 0)
        return { socketPath: decodeSSHUTF8(socketPath, "direct stream-local socket path") }
    }
}
