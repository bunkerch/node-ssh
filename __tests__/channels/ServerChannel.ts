import Channel from "../../src/Channel.js"
import Client from "../../src/Client.js"
import Packet from "../../src/packet.js"
import ChannelData from "../../src/packets/ChannelData.js"
import ChannelExtendedData from "../../src/packets/ChannelExtendedData.js"
import ChannelOpen from "../../src/packets/ChannelOpen.js"
import ChannelWindowAdjust from "../../src/packets/ChannelWindowAdjust.js"
import ChannelEOF from "../../src/packets/ChannelEOF.js"
import ChannelRequest from "../../src/packets/ChannelRequest.js"
import { ProtocolError } from "../../src/packets/Disconnect.js"
import SessionChannel from "../../src/channels/SessionChannel.js"
import type ServerClient from "../../src/ServerClient.js"
import { serializeBuffer, serializeUint32 } from "../../src/utils/Buffer.js"
import Shell from "../../src/channels/Session/Shell.js"
import { rejectUnimplementedPacket } from "../../src/utils/UnimplementedRegistry.js"

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
    test("validates exit-signal text before sending the one-way result", () => {
        const sent: { type: string; args: Buffer }[] = []
        const channel = {
            sendRequest(type: string, args: Buffer): void {
                sent.push({ type, args: Buffer.from(args) })
            },
        } as unknown as SessionChannel
        const shell = new Shell(channel)

        expect(() => shell.exit("TERM", false, "\ud800")).toThrow(
            "SSH exit-signal message is not valid UTF-8 text",
        )
        expect(sent).toEqual([])

        expect(() => shell.exit("TERM", true, "terminated", "en_XX")).toThrow(
            "SSH exit-signal language tag is not valid RFC 3066",
        )
        expect(sent).toEqual([])

        shell.exit("TERM", true, "terminated", "en-US")
        expect(sent).toEqual([
            {
                type: "exit-signal",
                args: Buffer.from(
                    "000000045445524d01" + "0000000a7465726d696e61746564" + "00000005656e2d5553",
                    "hex",
                ),
            },
        ])
        expect(() => shell.exit(0)).toThrow("SSH session exit result has already been sent")
        expect(sent).toHaveLength(1)
        shell.destroy()
    })

    test("rejects malformed UTF-8 session policy text", () => {
        const peer = { localChannelIndex: 0, channels: new Map() } as unknown as ServerClient
        const channel = new SessionChannel(peer, "session")
        const malformed = Buffer.from([0xff])

        expect(() => channel.parseExecRequest(serializeBuffer(malformed))).toThrow(
            "SSH exec command is not valid UTF-8 text",
        )
        expect(() =>
            channel.parseEnvRequest(
                Buffer.concat([serializeBuffer(malformed), serializeBuffer(Buffer.from("value"))]),
            ),
        ).toThrow("SSH environment variable name is not valid UTF-8 text")
        expect(() =>
            channel.parsePtyRequest(
                Buffer.concat([
                    serializeBuffer(malformed),
                    serializeUint32(80),
                    serializeUint32(24),
                    serializeUint32(640),
                    serializeUint32(480),
                    serializeBuffer(Buffer.from([0])),
                ]),
            ),
        ).toThrow("SSH PTY terminal type is not valid UTF-8 text")
    })

    test("serializes queued output within the peer packet and window limits", async () => {
        const { channel, sent } = createChannel()
        const finished = channel.sendData(Buffer.from("abcdefgh"))

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

    test("sends queued output before EOF and rejects later writes", async () => {
        const { channel, sent } = createChannel()
        const sending = channel.sendData(Buffer.from("abcdefgh"))

        channel.sendEOF()
        expect(sent.map((packet) => packet.constructor)).toEqual([ChannelData, ChannelData])

        channel.receiveWindowAdjust(3)
        await sending
        expect(sent.map((packet) => packet.constructor)).toEqual([
            ChannelData,
            ChannelData,
            ChannelData,
            ChannelEOF,
        ])
        await expect(channel.sendData(Buffer.from("after EOF"))).rejects.toThrow(
            "closed for writing after EOF",
        )
    })

    test("awaits Promise-based shell output before later protocol messages", async () => {
        const { channel, sent } = createChannel(0, 3)
        channel.channel_type = "session"
        const shell = new Shell(channel as SessionChannel)

        const stdout = shell.writeStdout("out")
        expect(sent).toEqual([])
        channel.receiveWindowAdjust(3)
        await stdout

        const stderr = shell.writeStderr("err")
        channel.receiveWindowAdjust(3)
        await stderr
        shell.exit(0)

        expect(sent.map((packet) => packet.constructor)).toEqual([
            ChannelData,
            ChannelExtendedData,
            ChannelRequest,
        ])
        expect((sent[0] as ChannelData).data.data.toString()).toBe("out")
        expect((sent[1] as ChannelExtendedData).data.data.toString()).toBe("err")
        shell.destroy()
    })

    test("rejects every queued output when packet emission fails", async () => {
        const { channel } = createChannel(0, 3)
        const first = channel.sendData(Buffer.from("first")).catch((error: Error) => error)
        const second = channel.sendData(Buffer.from("second")).catch((error: Error) => error)
        const sendPacket = channel.client.sendPacket
        channel.client.sendPacket = () => {
            throw new Error("transport write failed")
        }

        expect(() => channel.receiveWindowAdjust(16)).toThrow("transport write failed")
        expect((await first).message).toBe("transport write failed")
        expect((await second).message).toBe("transport write failed")
        channel.client.sendPacket = sendPacket
        channel.terminate()
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

    test("accepts a zero peer window without emitting data or spinning", async () => {
        const { channel, sent } = createChannel(0, 0)
        let completed = false

        const completion = channel.sendData(Buffer.from("queued")).then(
            () => {
                completed = true
            },
            () => {
                completed = true
            },
        )

        expect(sent).toEqual([])
        expect(completed).toBe(false)
        channel.receiveClose()
        await completion
        expect(completed).toBe(true)
    })

    test("accepts a zero window adjustment and rejects uint32 overflow", () => {
        const { channel } = createChannel()
        expect(() => channel.receiveWindowAdjust(0)).not.toThrow()
        expect(() => channel.receiveWindowAdjust(0xffff_ffff)).toThrow(ProtocolError)
    })

    test("rejects malformed RFC names before allocating or sending a request", async () => {
        const { channel, sent } = createChannel()

        expect(() => channel.sendRequest("two,names")).toThrow("must not contain a comma")
        await expect(channel.request("a".repeat(65))).rejects.toThrow(
            "must be 1 to 64 printable US-ASCII characters",
        )
        await expect(channel.request("request@-example.test")).rejects.toThrow(
            "extension domain is invalid",
        )
        expect(sent).toEqual([])
    })

    test("rejects the exact request named by an unimplemented sequence", async () => {
        const { channel } = createChannel()
        const first = channel.request("first")
        const second = channel.request("second").catch((error: Error) => error)

        expect(rejectUnimplementedPacket(channel.client, 1)).toBe(true)
        expect((await second).message).toContain(
            "channel 0 request second (outbound packet sequence 1)",
        )

        channel.receiveRequestSuccess()
        await expect(first).resolves.toBeUndefined()
        expect(rejectUnimplementedPacket(channel.client, 1)).toBe(false)
    })

    test("stops outbound data after end-of-write without closing the channel", async () => {
        const { channel, sent } = createChannel(0, 3)
        channel.channel_type = "session"
        const queued = channel.sendData(Buffer.from("queued")).then(
            () => undefined,
            (error: Error) => error,
        )

        channel.receiveEndOfWrite()
        expect(await queued).toBeInstanceOf(Error)
        expect(channel.hasReceivedEndOfWrite).toBe(true)
        expect(channel.isOpen).toBe(true)
        expect(sent.some((packet) => packet instanceof ChannelEOF)).toBe(true)
        const later = await channel.sendData(Buffer.from("later")).then(
            () => undefined,
            (error: Error) => error,
        )
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
