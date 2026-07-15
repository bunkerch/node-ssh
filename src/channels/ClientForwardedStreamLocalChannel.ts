import assert from "node:assert"
import Client from "../Client.js"
import ChannelOpen from "../packets/ChannelOpen.js"
import { readNextBuffer } from "../utils/Buffer.js"
import { decodeSSHUTF8 } from "../utils/SSHText.js"
import ClientChannel from "./ClientChannel.js"

export interface StreamLocalConnectionDetails {
    socketPath: string
}

export default class ClientForwardedStreamLocalChannel extends ClientChannel {
    static channelType = "forwarded-streamlocal@openssh.com"

    readonly details: Readonly<StreamLocalConnectionDetails>

    constructor(client: Client, packet: ChannelOpen) {
        assert(packet.data.channel_type === ClientForwardedStreamLocalChannel.channelType)
        super(client, ClientForwardedStreamLocalChannel.channelType)
        this.details = Object.freeze(
            ClientForwardedStreamLocalChannel.parseDetails(packet.data.args),
        )
    }

    static parseDetails(raw: Buffer): StreamLocalConnectionDetails {
        const [socketPath, afterSocketPath] = readNextBuffer(raw)
        const [, remaining] = readNextBuffer(afterSocketPath)
        assert(remaining.length === 0)
        return { socketPath: decodeSSHUTF8(socketPath, "forwarded stream-local socket path") }
    }
}
