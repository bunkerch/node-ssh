import ClientForwardedTCPIPChannel from "../../src/channels/ClientForwardedTCPIPChannel.js"
import ChannelOpen from "../../src/packets/ChannelOpen.js"
import GlobalRequest from "../../src/packets/GlobalRequest.js"
import RequestFailure from "../../src/packets/RequestFailure.js"
import RequestSuccess from "../../src/packets/RequestSuccess.js"

function vector(hex: string): Buffer {
    return Buffer.from(hex.replace(/\s/gu, ""), "hex")
}

describe("RFC 4254 TCP forwarding packet vectors", () => {
    test.each([
        [
            "tcpip-forward",
            `50 0000000d 74637069702d666f7277617264 01
             00000007 302e302e302e30 00009c40`,
        ],
        [
            "cancel-tcpip-forward",
            `50 00000014 63616e63656c2d74637069702d666f7277617264 01
             00000007 302e302e302e30 00009c40`,
        ],
    ])("parses and serializes a fixed %s global request", (requestName, hex) => {
        const raw = vector(hex)
        const packet = GlobalRequest.parse(raw)

        expect(packet.data).toEqual({
            request_name: requestName,
            want_reply: true,
            args: vector("00000007 302e302e302e30 00009c40"),
        })
        expect(packet.serialize()).toEqual(raw)
    })

    test("parses an allocated port success and an empty failure", () => {
        const success = vector("51 0000c000")
        const failure = vector("52")

        expect(RequestSuccess.parse(success).data.args).toEqual(vector("0000c000"))
        expect(RequestSuccess.parse(success).serialize()).toEqual(success)
        expect(RequestFailure.parse(failure).serialize()).toEqual(failure)
    })

    test("parses and serializes a fixed forwarded-tcpip channel open", () => {
        const raw = vector(`
            5a
            0000000f 666f727761726465642d7463706970
            0000000b 00200000 00008000
            00000007 302e302e302e30 00009c40
            0000000a 3139322e302e322e3130 00003039
        `)
        const packet = ChannelOpen.parse(raw)

        expect(packet.data.channel_type).toBe("forwarded-tcpip")
        expect(ClientForwardedTCPIPChannel.parseDetails(packet.data.args)).toEqual({
            destinationHost: "0.0.0.0",
            destinationPort: 40_000,
            sourceHost: "192.0.2.10",
            sourcePort: 12_345,
        })
        expect(packet.serialize()).toEqual(raw)
    })
})
