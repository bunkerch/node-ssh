import ChannelClose from "../../src/packets/ChannelClose.js"
import ChannelData from "../../src/packets/ChannelData.js"
import ChannelEOF from "../../src/packets/ChannelEOF.js"
import ChannelExtendedData from "../../src/packets/ChannelExtendedData.js"
import ChannelOpen from "../../src/packets/ChannelOpen.js"
import ChannelRequest from "../../src/packets/ChannelRequest.js"
import ChannelWindowAdjust from "../../src/packets/ChannelWindowAdjust.js"

function vector(hex: string): Buffer {
    return Buffer.from(hex.replace(/\s/gu, ""), "hex")
}

describe("RFC 4254 channel packet vectors", () => {
    test("parses and serializes a direct-tcpip channel open", () => {
        const raw = vector(`
            5a
            0000000c 6469726563742d7463706970
            00000007 00200000 00008000
            00000010 736572766963652e696e7465726e616c
            00001f90
            0000000a 3139322e302e322e3130
            00003039
        `)

        const packet = ChannelOpen.parse(raw)
        expect(packet.data).toEqual({
            channel_type: "direct-tcpip",
            sender_channel_id: 7,
            initial_window_size: 2_097_152,
            maximum_packet_size: 32_768,
            args: vector(`
                00000010 736572766963652e696e7465726e616c
                00001f90
                0000000a 3139322e302e322e3130
                00003039
            `),
        })
        expect(packet.serialize()).toEqual(raw)
    })

    test("parses and serializes a PTY request with terminal modes", () => {
        const raw = vector(`
            62 00000003
            00000007 7074792d726571 01
            00000005 787465726d
            00000050 00000018 00000280 000001e0
            00000006 01 00000003 00
        `)

        const packet = ChannelRequest.parse(raw)
        expect(packet.data.recipient_channel_id).toBe(3)
        expect(packet.data.request_type).toBe("pty-req")
        expect(packet.data.want_reply).toBe(true)
        expect(packet.data.args).toEqual(
            vector(`
                00000005 787465726d
                00000050 00000018 00000280 000001e0
                00000006 01 00000003 00
            `),
        )
        expect(packet.serialize()).toEqual(raw)
    })

    test.each([
        [
            "env",
            `62 00000003 00000003 656e76 01
             00000004 4c414e47 0000000b 656e5f55532e5554462d38`,
        ],
        [
            "window-change",
            `62 00000003 0000000d 77696e646f772d6368616e6765 00
             00000064 00000028 00000320 00000258`,
        ],
        ["signal", `62 00000003 00000006 7369676e616c 00 00000004 5445524d`],
        ["subsystem", `62 00000003 00000009 73756273797374656d 01 00000004 73667470`],
    ])("round-trips the fixed %s request vector", (requestType, hex) => {
        const raw = vector(hex)
        const packet = ChannelRequest.parse(raw)
        expect(packet.data.request_type).toBe(requestType)
        expect(packet.serialize()).toEqual(raw)
    })

    test("round-trips flow-control, data, extended-data, EOF, and CLOSE vectors", () => {
        const cases: [Buffer, { parse(raw: Buffer): { serialize(): Buffer } }][] = [
            [vector("5d 00000003 00010000"), ChannelWindowAdjust],
            [vector("5e 00000003 00000003 616263"), ChannelData],
            [vector("5f 00000003 00000001 00000003 657272"), ChannelExtendedData],
            [vector("60 00000003"), ChannelEOF],
            [vector("61 00000003"), ChannelClose],
        ]

        for (const [raw, packetType] of cases) {
            expect(packetType.parse(raw).serialize()).toEqual(raw)
        }
    })
})
