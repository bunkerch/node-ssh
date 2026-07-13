import Client from "../../src/Client.js"
import ClientChannel from "../../src/channels/ClientChannel.js"
import ChannelClose from "../../src/packets/ChannelClose.js"
import ChannelData from "../../src/packets/ChannelData.js"
import ChannelOpenConfirmation from "../../src/packets/ChannelOpenConfirmation.js"
import ChannelRequest from "../../src/packets/ChannelRequest.js"
import ChannelWindowAdjust from "../../src/packets/ChannelWindowAdjust.js"
import Packet from "../../src/packet.js"

function createChannel(options: { initialWindowSize?: number; maximumPacketSize?: number } = {}) {
    const client = new Client({ hostname: "unused" })
    const sent: Packet[] = []
    client.sendPacket = (packet: Packet) => {
        sent.push(packet)
        return sent.length - 1
    }
    const channel = new ClientChannel(client, "session", options)
    channel.confirmOpen(
        new ChannelOpenConfirmation({
            recipient_channel_id: channel.localId,
            sender_channel_id: 42,
            initial_window_size: 5,
            maximum_packet_size: 3,
            args: Buffer.alloc(0),
        }),
    )
    return { channel, sent }
}

describe("ClientChannel", () => {
    test("splits writes by packet and window limits, then resumes after window adjustment", async () => {
        const { channel, sent } = createChannel()
        const writeFinished = new Promise<void>((resolve, reject) => {
            channel.write(Buffer.from("abcdefgh"), (error) => (error ? reject(error) : resolve()))
        })
        await new Promise<void>((resolve) => setImmediate(resolve))

        expect(
            sent
                .filter((packet): packet is ChannelData => packet instanceof ChannelData)
                .map((packet) => packet.data.data.toString()),
        ).toEqual(["abc", "de"])

        channel.receiveWindowAdjust(3)
        await writeFinished
        expect(
            sent
                .filter((packet): packet is ChannelData => packet instanceof ChannelData)
                .map((packet) => packet.data.data.toString()),
        ).toEqual(["abc", "de", "fgh"])
        channel.destroy()
    })

    test("enforces inbound packet limits and replenishes a consumed receive window", async () => {
        const { channel, sent } = createChannel({
            initialWindowSize: 8,
            maximumPacketSize: 4,
        })
        const received: Buffer[] = []
        channel.on("data", (data: Buffer) => received.push(data))

        channel.receiveData(Buffer.from("data"))
        await new Promise<void>((resolve) => setImmediate(resolve))

        expect(Buffer.concat(received).toString()).toBe("data")
        const adjustment = sent.find(
            (packet): packet is ChannelWindowAdjust => packet instanceof ChannelWindowAdjust,
        )
        expect(adjustment?.data).toEqual({ recipient_channel_id: 42, bytes_to_add: 4 })
        expect(() => channel.receiveData(Buffer.alloc(5))).toThrow("oversized data packet")
        channel.destroy()
    })

    test("matches request replies in FIFO order", async () => {
        const { channel, sent } = createChannel()
        const first = channel.request("first")
        const second = channel.request("second")
        const secondResult = second.catch((error: Error) => error)

        expect(
            sent
                .filter((packet): packet is ChannelRequest => packet instanceof ChannelRequest)
                .map((packet) => packet.data.request_type),
        ).toEqual(["first", "second"])

        channel.receiveRequestSuccess()
        channel.receiveRequestFailure()
        await expect(first).resolves.toBeUndefined()
        expect(await secondResult).toBeInstanceOf(Error)
        channel.destroy()
    })

    test("does not send CLOSE after the transport has already closed", () => {
        const { channel, sent } = createChannel()

        channel.abort()

        expect(sent.some((packet) => packet instanceof ChannelClose)).toBe(false)
    })
})
