import Client from "../Client.js"
import ChannelOpen from "../packets/ChannelOpen.js"
import { serializeBuffer, serializeUint32 } from "../utils/Buffer.js"
import ClientChannel from "./ClientChannel.js"

export default class ClientDirectStreamLocalChannel extends ClientChannel {
    static channelType = "direct-streamlocal@openssh.com"

    readonly socketPath: string

    constructor(client: Client, socketPath: string) {
        super(client, ClientDirectStreamLocalChannel.channelType)
        this.socketPath = socketPath
    }

    override getOpenPacket(): ChannelOpen {
        return super.getOpenPacket(
            Buffer.concat([
                serializeBuffer(Buffer.from(this.socketPath, "utf8")),
                serializeBuffer(Buffer.alloc(0)),
                serializeUint32(0),
            ]),
        )
    }
}
