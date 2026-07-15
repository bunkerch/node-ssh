import Client from "../../src/Client.js"
import ClientChannel from "../../src/channels/ClientChannel.js"
import ClientSessionChannel from "../../src/channels/ClientSessionChannel.js"
import ChannelClose from "../../src/packets/ChannelClose.js"
import ChannelData from "../../src/packets/ChannelData.js"
import ChannelEOF from "../../src/packets/ChannelEOF.js"
import ChannelOpenConfirmation from "../../src/packets/ChannelOpenConfirmation.js"
import ChannelRequest from "../../src/packets/ChannelRequest.js"
import ChannelWindowAdjust from "../../src/packets/ChannelWindowAdjust.js"
import Packet from "../../src/packet.js"
import { serializeBuffer } from "../../src/utils/Buffer.js"
import { ProtocolError } from "../../src/packets/Disconnect.js"
import { TerminalMode } from "../../src/TerminalModes.js"

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
    test("rejects invalid local session text before sending a request", async () => {
        const client = new Client({ hostname: "unused" })
        const sent: Packet[] = []
        client.sendPacket = (packet: Packet) => {
            sent.push(packet)
            return sent.length - 1
        }
        const channel = new ClientSessionChannel(client)
        channel.confirmOpen(
            new ChannelOpenConfirmation({
                recipient_channel_id: channel.localId,
                sender_channel_id: 42,
                initial_window_size: 32,
                maximum_packet_size: 32,
                args: Buffer.alloc(0),
            }),
        )

        await expect(channel.exec("\ud800")).rejects.toThrow(
            "SSH exec command is not valid UTF-8 text",
        )
        await expect(channel.setEnv("NAME", "\ud800")).rejects.toThrow(
            "SSH environment variable value is not valid UTF-8 text",
        )
        await expect(channel.requestPty({ term: "\ud800" })).rejects.toThrow(
            "SSH PTY terminal type is not valid UTF-8 text",
        )
        expect(sent).toEqual([])
        channel.destroy()
    })

    test("encodes named RFC terminal modes in a PTY request", async () => {
        const client = new Client({ hostname: "unused" })
        const sent: Packet[] = []
        client.sendPacket = (packet: Packet) => {
            sent.push(packet)
            return sent.length - 1
        }
        const channel = new ClientSessionChannel(client)
        channel.confirmOpen(
            new ChannelOpenConfirmation({
                recipient_channel_id: channel.localId,
                sender_channel_id: 42,
                initial_window_size: 32,
                maximum_packet_size: 32,
                args: Buffer.alloc(0),
            }),
        )

        const requested = channel.requestPty({
            modes: new Map([
                [TerminalMode.VINTR, 3],
                [TerminalMode.ECHO, 1],
            ]),
        })
        const packet = sent.at(-1)
        expect(packet).toBeInstanceOf(ChannelRequest)
        expect((packet as ChannelRequest).data.args).toEqual(
            Buffer.from(
                "000000057674313030" +
                    "000000500000001800000280000001e0" +
                    "0000000b0100000003350000000100",
                "hex",
            ),
        )
        channel.receiveRequestSuccess()
        await requested
        channel.destroy()
    })

    test("queues awaited sends across packet and window limits", async () => {
        const { channel, sent } = createChannel()
        const input = Buffer.from("abcdefgh")
        const first = channel.sendData(input)
        const second = channel.sendData("ij")
        input.fill(0)

        expect(
            sent
                .filter((packet): packet is ChannelData => packet instanceof ChannelData)
                .map((packet) => packet.data.data.toString()),
        ).toEqual(["abc", "de"])

        channel.receiveWindowAdjust(5)
        await Promise.all([first, second])
        expect(
            sent
                .filter((packet): packet is ChannelData => packet instanceof ChannelData)
                .map((packet) => packet.data.data.toString()),
        ).toEqual(["abc", "de", "fgh", "ij"])
        channel.destroy()
    })

    test("rejects every queued send when packet emission fails", async () => {
        const { channel } = createChannel()
        channel.remoteWindowSize = 0
        const first = channel.sendData("first").catch((error: Error) => error)
        const second = channel.sendData("second").catch((error: Error) => error)
        const sendPacket = channel.client.sendPacket
        channel.client.sendPacket = () => {
            throw new Error("transport write failed")
        }

        expect(() => channel.receiveWindowAdjust(16)).toThrow("transport write failed")
        expect((await first).message).toBe("transport write failed")
        expect((await second).message).toBe("transport write failed")
        channel.client.sendPacket = sendPacket
        channel.destroy()
    })

    test("accepts a zero window adjustment and rejects uint32 overflow", () => {
        const { channel } = createChannel()
        expect(() => channel.receiveWindowAdjust(0)).not.toThrow()
        expect(() => channel.receiveWindowAdjust(0xffff_ffff)).toThrow(ProtocolError)
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
        channel.close()

        expect(sent.some((packet) => packet instanceof ChannelClose)).toBe(false)
    })

    test("validates one-way RFC 4254 xon-xoff notifications", () => {
        const client = new Client({ hostname: "unused" })
        client.sendPacket = () => 0
        const channel = new ClientSessionChannel(client)
        channel.confirmOpen(
            new ChannelOpenConfirmation({
                recipient_channel_id: channel.localId,
                sender_channel_id: 42,
                initial_window_size: 5,
                maximum_packet_size: 3,
                args: Buffer.alloc(0),
            }),
        )
        const values: boolean[] = []
        channel.on("xonXoff", (value: boolean) => values.push(value))
        channel.receiveRequest(
            new ChannelRequest({
                recipient_channel_id: channel.localId,
                request_type: "xon-xoff",
                want_reply: false,
                args: Buffer.from([1]),
            }),
        )
        expect(values).toEqual([true])
        expect(() =>
            channel.receiveRequest(
                new ChannelRequest({
                    recipient_channel_id: channel.localId,
                    request_type: "xon-xoff",
                    want_reply: true,
                    args: Buffer.from([0]),
                }),
            ),
        ).toThrow("must not request a reply")
        expect(() =>
            channel.receiveRequest(
                new ChannelRequest({
                    recipient_channel_id: channel.localId,
                    request_type: "xon-xoff",
                    want_reply: false,
                    args: Buffer.from([0, 0]),
                }),
            ),
        ).toThrow("trailing data")
        channel.destroy()
    })

    test("validates and exposes an RFC 4254 exit signal exactly once", async () => {
        const client = new Client({ hostname: "unused" })
        client.sendPacket = () => 0
        const channel = new ClientSessionChannel(client)
        channel.confirmOpen(
            new ChannelOpenConfirmation({
                recipient_channel_id: channel.localId,
                sender_channel_id: 42,
                initial_window_size: 32,
                maximum_packet_size: 32,
                args: Buffer.alloc(0),
            }),
        )
        const exits: unknown[][] = []
        channel.on("exit", (...args) => exits.push(args))
        const request = new ChannelRequest({
            recipient_channel_id: channel.localId,
            request_type: "exit-signal",
            want_reply: false,
            args: Buffer.concat([
                serializeBuffer(Buffer.from("TERM", "ascii")),
                Buffer.from([1]),
                serializeBuffer(Buffer.from("terminated", "utf8")),
                serializeBuffer(Buffer.from("en-US", "ascii")),
            ]),
        })

        await channel.receiveRequest(request)
        expect(channel.exitCode).toBeNull()
        expect(channel.exitSignal).toBe("SIGTERM")
        expect(channel.exitCoreDumped).toBe(true)
        expect(channel.exitErrorMessage).toBe("terminated")
        expect(channel.exitLanguageTag).toBe("en-US")
        expect(exits).toEqual([[null, "SIGTERM", true, "terminated", "en-US"]])
        await expect(channel.receiveRequest(request)).rejects.toThrow("more than one exit result")
        channel.destroy()
    })

    test("rejects malformed or misplaced RFC 4254 exit results", async () => {
        const nonSessionClient = new Client({ hostname: "unused" })
        nonSessionClient.sendPacket = () => 0
        const channel = new ClientChannel(nonSessionClient, "direct-tcpip")
        channel.confirmOpen(
            new ChannelOpenConfirmation({
                recipient_channel_id: channel.localId,
                sender_channel_id: 42,
                initial_window_size: 32,
                maximum_packet_size: 32,
                args: Buffer.alloc(0),
            }),
        )
        const request = (
            recipientChannelId: number,
            type: string,
            args: Buffer,
            wantReply = false,
        ) =>
            new ChannelRequest({
                recipient_channel_id: recipientChannelId,
                request_type: type,
                want_reply: wantReply,
                args,
            })

        await expect(
            channel.receiveRequest(request(channel.localId, "exit-status", Buffer.alloc(4))),
        ).rejects.toThrow("only valid on sessions")

        const client = new Client({ hostname: "unused" })
        client.sendPacket = () => 0
        const session = new ClientSessionChannel(client)
        session.confirmOpen(
            new ChannelOpenConfirmation({
                recipient_channel_id: session.localId,
                sender_channel_id: 43,
                initial_window_size: 32,
                maximum_packet_size: 32,
                args: Buffer.alloc(0),
            }),
        )
        await expect(
            session.receiveRequest(request(session.localId, "exit-status", Buffer.alloc(4), true)),
        ).rejects.toThrow("must not request a reply")

        const exitSignal = (signal: Buffer, message: Buffer, language: Buffer) =>
            request(
                session.localId,
                "exit-signal",
                Buffer.concat([
                    serializeBuffer(signal),
                    Buffer.from([0]),
                    serializeBuffer(message),
                    serializeBuffer(language),
                ]),
            )
        await expect(
            session.receiveRequest(
                exitSignal(Buffer.from("SIGTERM"), Buffer.alloc(0), Buffer.alloc(0)),
            ),
        ).rejects.toThrow('omit the "SIG" prefix')
        await expect(
            session.receiveRequest(
                exitSignal(Buffer.from("TERM"), Buffer.from([0xff]), Buffer.alloc(0)),
            ),
        ).rejects.toThrow()
        await expect(
            session.receiveRequest(
                exitSignal(Buffer.from("TERM"), Buffer.alloc(0), Buffer.from("en_XX")),
            ),
        ).rejects.toThrow("language tag")
        channel.destroy()
        session.destroy()
    })

    test("handles awaited end-of-write as a one-way writable half-close", async () => {
        const client = new Client({ hostname: "unused" })
        const sent: Packet[] = []
        client.sendPacket = (packet: Packet) => {
            sent.push(packet)
            return sent.length - 1
        }
        const channel = new ClientSessionChannel(client)
        channel.confirmOpen(
            new ChannelOpenConfirmation({
                recipient_channel_id: channel.localId,
                sender_channel_id: 42,
                initial_window_size: 5,
                maximum_packet_size: 3,
                args: Buffer.alloc(0),
            }),
        )
        let release!: () => void
        const wait = new Promise<void>((resolve) => {
            release = resolve
        })
        let hooks = 0
        let events = 0
        channel.hooker.hook("endOfWrite", async () => {
            hooks++
            await wait
        })
        channel.on("endOfWrite", () => events++)
        const request = new ChannelRequest({
            recipient_channel_id: channel.localId,
            request_type: "eow@openssh.com",
            want_reply: false,
            args: Buffer.alloc(0),
        })

        const handling = channel.receiveRequest(request)
        await new Promise<void>((resolve) => setImmediate(resolve))
        expect(channel.writableEnded).toBe(false)
        release()
        await handling
        await new Promise<void>((resolve) => setImmediate(resolve))
        expect(channel.hasReceivedEndOfWrite).toBe(true)
        expect(channel.writableEnded).toBe(true)
        expect(hooks).toBe(1)
        expect(events).toBe(1)
        expect(sent.some((packet) => packet instanceof ChannelEOF)).toBe(true)

        await channel.receiveRequest(request)
        expect(hooks).toBe(1)
        expect(channel.sendEndOfWrite()).toBe(false)
        expect(channel.sendEndOfWrite(true)).toBe(true)
        expect(channel.sendEndOfWrite(true)).toBe(false)
        expect(
            sent.filter(
                (packet): packet is ChannelRequest =>
                    packet instanceof ChannelRequest &&
                    packet.data.request_type === "eow@openssh.com",
            ),
        ).toHaveLength(1)
        channel.destroy()
    })

    test("rejects malformed end-of-write requests", async () => {
        const { channel } = createChannel()
        await expect(
            channel.receiveRequest(
                new ChannelRequest({
                    recipient_channel_id: channel.localId,
                    request_type: "eow@openssh.com",
                    want_reply: true,
                    args: Buffer.alloc(0),
                }),
            ),
        ).rejects.toThrow("Invalid end-of-write")
        await expect(
            channel.receiveRequest(
                new ChannelRequest({
                    recipient_channel_id: channel.localId,
                    request_type: "eow@openssh.com",
                    want_reply: false,
                    args: Buffer.from([0]),
                }),
            ),
        ).rejects.toThrow("Invalid end-of-write")
        channel.destroy()
    })
})
