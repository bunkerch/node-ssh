import { Readable, Writable } from "stream"
import SessionChannel from "../SessionChannel.js"
import ChannelData from "../../packets/ChannelData.js"
import assert from "assert"
import ChannelExtendedData from "../../packets/ChannelExtendedData.js"

export default class Shell {
    channel: SessionChannel

    constructor(channel: SessionChannel) {
        this.channel = channel

        // TODO: on channelData and channelExtendedData
        // depending on if this is a server client or just a server.
        //this.channel.client.on("")
    }

    stdout: Writable = new Writable({
        write: (chunk, encoding, callback) => {
            // @ts-expect-error this shitty nodejs type is wrong.
            if (encoding !== "buffer") {
                chunk = Buffer.from(chunk, encoding)
            }

            assert(Buffer.isBuffer(chunk))

            this.channel.client.sendPacket(
                new ChannelData({
                    recipient_channel_id: this.channel.remoteId!,
                    data: chunk,
                }),
            )

            callback()
        },
    })
    stderr: Writable = new Writable({
        write: (chunk, encoding, callback) => {
            // @ts-expect-error this shitty nodejs type is wrong.
            if (encoding !== "buffer") {
                chunk = Buffer.from(chunk, encoding)
            }

            assert(Buffer.isBuffer(chunk))

            this.channel.client.sendPacket(
                new ChannelExtendedData({
                    recipient_channel_id: this.channel.remoteId!,
                    data_type_code: 1,
                    data: chunk,
                }),
            )

            callback()
        },
    })
    stdin: Readable = new Readable()
}
