import assert from "node:assert"
import Client from "../Client.js"
import ChannelOpen from "../packets/ChannelOpen.js"
import { readNextBuffer, readNextUint32 } from "../utils/Buffer.js"
import { decodeSSHUTF8 } from "../utils/SSHText.js"
import ClientChannel from "./ClientChannel.js"

export interface X11ConnectionDetails {
    originatorAddress: string
    originatorPort: number
}

export default class ClientX11Channel extends ClientChannel {
    static channelType = "x11"

    readonly details: Readonly<X11ConnectionDetails>

    constructor(client: Client, packet: ChannelOpen) {
        assert(packet.data.channel_type === ClientX11Channel.channelType)
        super(client, ClientX11Channel.channelType)
        this.details = Object.freeze(ClientX11Channel.parseDetails(packet.data.args))
        this.acceptOpen(packet)
    }

    static parseDetails(raw: Buffer): X11ConnectionDetails {
        const [originatorAddress, afterAddress] = readNextBuffer(raw)
        const [originatorPort, remaining] = readNextUint32(afterAddress)
        assert(remaining.length === 0, "X11 channel open has trailing data")
        assert(originatorPort <= 65_535, "X11 originator port exceeds 65535")
        return {
            originatorAddress: decodeSSHUTF8(originatorAddress, "X11 originator address"),
            originatorPort,
        }
    }
}
