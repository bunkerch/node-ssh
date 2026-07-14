import Channel from "../../src/Channel.js"
import Client from "../../src/Client.js"
import Packet from "../../src/packet.js"
import ChannelData from "../../src/packets/ChannelData.js"
import ChannelOpen from "../../src/packets/ChannelOpen.js"
import ChannelWindowAdjust from "../../src/packets/ChannelWindowAdjust.js"
import ChannelEOF from "../../src/packets/ChannelEOF.js"
import ChannelRequest from "../../src/packets/ChannelRequest.js"

function createChannel(remoteWindow = 5, remotePacketSize = 3) {
    const client = new Client({ hostname: "unused" })
    const sent: Packet[] = []
    client.sendPacket = (packet: Packet) => {
        sent.push(packet)
        return sent.length - 1
    }
    const channel = new Channel(client, "test")
    channel.local_initial_window_size = 8
    channel.local_maximum_packet_size = 4
    channel.configureRemote(
        new ChannelOpen({
            channel_type: "test",
            sender_channel_id: 42,
            initial_window_size: remoteWindow,
            maximum_packet_size: remotePacketSize,
            args: Buffer.alloc(0),
        }),
    )
    return { channel, sent }
}

describe("server Channel", () => {
    test("serializes queued output within the peer packet and window limits", async () => {
        const { channel, sent } = createChannel()
        const finished = new Promise<void>((resolve, reject) => {
            channel.sendData(Buffer.from("abcdefgh"), (error) =>
                error ? reject(error) : resolve(),
            )
        })

        expect(
            sent
                .filter((packet): packet is ChannelData => packet instanceof ChannelData)
                .map((packet) => packet.data.data.toString()),
        ).toEqual(["abc", "de"])

        channel.receiveWindowAdjust(3)
        await finished
        expect(
            sent
                .filter((packet): packet is ChannelData => packet instanceof ChannelData)
                .map((packet) => packet.data.data.toString()),
        ).toEqual(["abc", "de", "fgh"])
    })

    test("advertises more receive window after inbound data reaches the threshold", () => {
        const { channel, sent } = createChannel()

        channel.receiveData(Buffer.from("data"))

        const adjustment = sent.find(
            (packet): packet is ChannelWindowAdjust => packet instanceof ChannelWindowAdjust,
        )
        expect(adjustment?.data).toEqual({ recipient_channel_id: 42, bytes_to_add: 4 })
        expect(() => channel.receiveData(Buffer.alloc(5))).toThrow("oversized data packet")
    })

    test("accepts a zero peer window without emitting data or spinning", () => {
        const { channel, sent } = createChannel(0, 0)
        let completed = false

        channel.sendData(Buffer.from("queued"), () => {
            completed = true
        })

        expect(sent).toEqual([])
        expect(completed).toBe(false)
        channel.receiveClose()
        expect(completed).toBe(true)
    })

    test("stops outbound data after end-of-write without closing the channel", async () => {
        const { channel, sent } = createChannel(0, 3)
        channel.channel_type = "session"
        const queued = new Promise<Error | undefined>((resolve) => {
            channel.sendData(Buffer.from("queued"), (error) => resolve(error ?? undefined))
        })

        channel.receiveEndOfWrite()
        expect(await queued).toBeInstanceOf(Error)
        expect(channel.hasReceivedEndOfWrite).toBe(true)
        expect(channel.isOpen).toBe(true)
        expect(sent.some((packet) => packet instanceof ChannelEOF)).toBe(true)
        const later = await new Promise<Error | undefined>((resolve) => {
            channel.sendData(Buffer.from("later"), (error) => resolve(error ?? undefined))
        })
        expect(later?.message).toContain("end-of-write")

        expect(channel.sendEndOfWrite()).toBe(false)
        expect(channel.sendEndOfWrite(true)).toBe(true)
        expect(channel.sendEndOfWrite(true)).toBe(false)
        const request = sent.find(
            (packet): packet is ChannelRequest => packet instanceof ChannelRequest,
        )
        expect(request?.data).toEqual({
            recipient_channel_id: 42,
            request_type: "eow@openssh.com",
            want_reply: false,
            args: Buffer.alloc(0),
        })
    })
})
