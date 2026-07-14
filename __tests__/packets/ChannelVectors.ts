import ChannelClose from "../../src/packets/ChannelClose.js"
import ChannelData from "../../src/packets/ChannelData.js"
import ChannelEOF from "../../src/packets/ChannelEOF.js"
import ChannelExtendedData from "../../src/packets/ChannelExtendedData.js"
import ChannelOpen from "../../src/packets/ChannelOpen.js"
import ChannelRequest from "../../src/packets/ChannelRequest.js"
import ChannelWindowAdjust from "../../src/packets/ChannelWindowAdjust.js"
import ClientX11Channel from "../../src/channels/ClientX11Channel.js"
import SessionChannel from "../../src/channels/SessionChannel.js"

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
        ["exit-status", `62 00000003 0000000b 657869742d737461747573 00 0000002a`],
        [
            "exit-signal",
            `62 00000003 0000000b 657869742d7369676e616c 00
             00000004 5445524d 01
             0000000b 7465726d696e61746564
             00000005 656e2d5553`,
        ],
        ["xon-xoff", `62 00000003 00000008 786f6e2d786f6666 00 01`],
        ["eow@openssh.com", `62 00000003 0000000f 656f77406f70656e7373682e636f6d 00`],
        ["break", `62 00000003 00000005 627265616b 01 000002ee`],
        ["subsystem", `62 00000003 00000009 73756273797374656d 01 00000004 73667470`],
    ])("round-trips the fixed %s request vector", (requestType, hex) => {
        const raw = vector(hex)
        const packet = ChannelRequest.parse(raw)
        expect(packet.data.request_type).toBe(requestType)
        expect(packet.serialize()).toEqual(raw)
    })

    test("round-trips the fixed RFC 9987 agent forwarding messages", () => {
        const request = vector(`
            62 00000003
            0000001a 617574682d6167656e742d726571406f70656e7373682e636f6d
            01
        `)
        const open = vector(`
            5a
            00000016 617574682d6167656e74406f70656e7373682e636f6d
            00000007 00200000 00008000
        `)

        expect(ChannelRequest.parse(request).serialize()).toEqual(request)
        expect(ChannelOpen.parse(open).serialize()).toEqual(open)
    })

    test("parses and serializes fixed RFC 4254 X11 forwarding messages", () => {
        const request = vector(`
            62 00000003 00000007 7831312d726571 01
            00
            00000012 4d49542d4d414749432d434f4f4b49452d31
            00000020 3030313132323333343435353636373738383939616162626363646465656666
            00000002
        `)
        const open = vector(`
            5a 00000003 783131
            00000007 00200000 00008000
            0000000a 3139322e302e322e3130
            00003039
        `)

        const parsedRequest = ChannelRequest.parse(request)
        expect(parsedRequest.data.request_type).toBe("x11-req")
        expect(SessionChannel.parseX11Request(parsedRequest.data.args)).toEqual({
            single: false,
            protocol: "MIT-MAGIC-COOKIE-1",
            cookie: "00112233445566778899aabbccddeeff",
            screen: 2,
        })
        expect(parsedRequest.serialize()).toEqual(request)
        const parsedOpen = ChannelOpen.parse(open)
        expect(parsedOpen.data.channel_type).toBe("x11")
        expect(ClientX11Channel.parseDetails(parsedOpen.data.args)).toEqual({
            originatorAddress: "192.0.2.10",
            originatorPort: 12_345,
        })
        expect(parsedOpen.serialize()).toEqual(open)

        const nonAsciiCookie = Buffer.from(parsedRequest.data.args)
        nonAsciiCookie[nonAsciiCookie.length - 5] = 0xb0
        expect(() => SessionChannel.parseX11Request(nonAsciiCookie)).toThrow("hexadecimal")
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
