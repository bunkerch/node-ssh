import Client from "../../src/Client.js"
import ClientTunnelChannel from "../../src/channels/ClientTunnelChannel.js"
import {
    AUTOMATIC_TUNNEL_UNIT,
    decodeTunnelOpen,
    decodeTunnelPacket,
    encodeTunnelOpen,
    encodeTunnelPacket,
    TunnelAddressFamily,
    TunnelMode,
} from "../../src/channels/Tunnel.js"
import ChannelData from "../../src/packets/ChannelData.js"
import ChannelOpenConfirmation from "../../src/packets/ChannelOpenConfirmation.js"
import Packet from "../../src/packet.js"

const ipv4 = Buffer.from("450000140000000040110000c0000201c6336402", "hex")
const ipv6 = Buffer.from(
    "6000000000003b4020010db800000000000000000000000120010db8000000000000000000000002",
    "hex",
)

describe("packet tunnel channels", () => {
    test("uses the literal upstream open and point-to-point framing", () => {
        const open = Buffer.from("000000017fffffff", "hex")
        const packet = Buffer.from(
            "0000001800000002450000140000000040110000c0000201c6336402",
            "hex",
        )

        expect(encodeTunnelOpen(TunnelMode.PointToPoint, AUTOMATIC_TUNNEL_UNIT)).toEqual(open)
        expect(decodeTunnelOpen(open)).toEqual({
            mode: TunnelMode.PointToPoint,
            unit: AUTOMATIC_TUNNEL_UNIT,
        })
        expect(encodeTunnelPacket(TunnelMode.PointToPoint, ipv4, TunnelAddressFamily.IPv4)).toEqual(
            packet,
        )
        expect(decodeTunnelPacket(TunnelMode.PointToPoint, packet)).toEqual({
            packet: { family: TunnelAddressFamily.IPv4, data: ipv4 },
        })
    })

    test("preserves Ethernet frame boundaries and rejects malformed mode-specific data", () => {
        const frame = Buffer.from("00112233445566778899aabb0800", "hex")
        const encoded = Buffer.from("0000000e00112233445566778899aabb0800", "hex")

        expect(encodeTunnelPacket(TunnelMode.Ethernet, frame)).toEqual(encoded)
        expect(decodeTunnelPacket(TunnelMode.Ethernet, encoded)).toEqual({ frame })
        expect(() => decodeTunnelOpen(Buffer.from("0000000300000000", "hex"))).toThrow(
            "PointToPoint or Ethernet",
        )
        expect(() => decodeTunnelPacket(TunnelMode.PointToPoint, encoded)).toThrow()
        expect(() =>
            decodeTunnelPacket(
                TunnelMode.PointToPoint,
                Buffer.from("0000001800000003450000140000000040110000c0000201c6336402", "hex"),
            ),
        ).toThrow("address family")
        expect(() =>
            encodeTunnelPacket(TunnelMode.PointToPoint, ipv6, TunnelAddressFamily.IPv4),
        ).toThrow("Invalid IPv4")
    })

    test("waits for a complete remote window and sends one channel-data message", async () => {
        const client = new Client({ hostname: "unused" })
        const sent: Packet[] = []
        client.sendPacket = (packet: Packet) => {
            sent.push(packet)
            return sent.length - 1
        }
        const channel = new ClientTunnelChannel(client, TunnelMode.PointToPoint)
        channel.confirmOpen(
            new ChannelOpenConfirmation({
                recipient_channel_id: channel.localId,
                sender_channel_id: 41,
                initial_window_size: 10,
                maximum_packet_size: 128,
                args: Buffer.alloc(0),
            }),
        )

        const sending = channel.sendIPv4(ipv4)
        await new Promise<void>((resolve) => setImmediate(resolve))
        expect(sent.filter((packet) => packet instanceof ChannelData)).toHaveLength(0)

        channel.receiveWindowAdjust(18)
        await sending
        const dataPackets = sent.filter(
            (packet): packet is ChannelData => packet instanceof ChannelData,
        )
        expect(dataPackets).toHaveLength(1)
        expect(dataPackets[0].data.data).toEqual(
            Buffer.from("0000001800000002450000140000000040110000c0000201c6336402", "hex"),
        )
        channel.destroy()
    })
})
