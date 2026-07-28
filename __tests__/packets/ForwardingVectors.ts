import ClientForwardedTCPIPChannel from "../../src/channels/ClientForwardedTCPIPChannel.js"
import ChannelOpen from "../../src/packets/ChannelOpen.js"
import ChannelOpenConfirmation from "../../src/packets/ChannelOpenConfirmation.js"
import ChannelOpenFailure, {
    ChannelOpenFailureReasonCodes,
} from "../../src/packets/ChannelOpenFailure.js"
import GlobalRequest from "../../src/packets/GlobalRequest.js"
import RequestFailure from "../../src/packets/RequestFailure.js"
import RequestSuccess from "../../src/packets/RequestSuccess.js"
import ClientX11Channel from "../../src/channels/ClientX11Channel.js"
import ClientTCPIPChannel from "../../src/channels/ClientTCPIPChannel.js"
import Client from "../../src/Client.js"

function vector(hex: string): Buffer {
    return Buffer.from(hex.replace(/\s/gu, ""), "hex")
}

describe("RFC 4254 TCP forwarding packet vectors", () => {
    test("parses and serializes the fixed OpenSSH keepalive request", () => {
        const raw = vector("50 00000015 6b656570616c697665406f70656e7373682e636f6d 01")
        const packet = GlobalRequest.parse(raw)

        expect(packet.data).toEqual({
            request_name: "keepalive@openssh.com",
            want_reply: true,
            args: Buffer.alloc(0),
        })
        expect(packet.serialize()).toEqual(raw)
    })

    test("parses and serializes the fixed OpenSSH no-more-sessions request", () => {
        const raw = vector(
            "50 0000001c 6e6f2d6d6f72652d73657373696f6e73406f70656e7373682e636f6d 01",
        )
        const packet = GlobalRequest.parse(raw)

        expect(packet.data).toEqual({
            request_name: "no-more-sessions@openssh.com",
            want_reply: true,
            args: Buffer.alloc(0),
        })
        expect(packet.serialize()).toEqual(raw)
    })

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

    test("global request packets own opaque constructor payloads", () => {
        const requestArgs = vector("00000007 302e302e302e30 00009c40")
        const request = new GlobalRequest({
            request_name: "tcpip-forward",
            want_reply: true,
            args: requestArgs,
        })
        requestArgs.fill(0xff)
        expect(request.serialize()).toEqual(
            vector(
                "50 0000000d 74637069702d666f7277617264 01 " + "00000007 302e302e302e30 00009c40",
            ),
        )

        const successArgs = vector("0000c000")
        const success = new RequestSuccess({ args: successArgs })
        successArgs.fill(0xff)
        expect(success.serialize()).toEqual(vector("51 0000c000"))
    })

    test("parsed global request packets do not alias their input frames", () => {
        const requestFrame = vector(
            "50 0000000d 74637069702d666f7277617264 01 " + "00000007 302e302e302e30 00009c40",
        )
        const successFrame = vector("51 0000c000")
        const request = GlobalRequest.parse(requestFrame)
        const success = RequestSuccess.parse(successFrame)
        const requestCopy = request.serialize()
        const successCopy = success.serialize()

        requestFrame.fill(0xff)
        successFrame.fill(0xff)

        expect(request.serialize()).toEqual(requestCopy)
        expect(success.serialize()).toEqual(successCopy)
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

    test("rejects malformed UTF-8 forwarding addresses", () => {
        expect(() =>
            ClientForwardedTCPIPChannel.parseDetails(
                vector("00000001 ff 00000000 00000001 31 00000000"),
            ),
        ).toThrow("forwarded-tcpip destination address is not valid UTF-8 text")
        expect(() =>
            ClientForwardedTCPIPChannel.parseDetails(
                vector("00000001 31 00000000 00000001 ff 00000000"),
            ),
        ).toThrow("forwarded-tcpip originator address is not valid UTF-8 text")
        expect(() => ClientX11Channel.parseDetails(vector("00000001 ff 00000000"))).toThrow(
            "X11 originator address is not valid UTF-8 text",
        )
        const outbound = new ClientTCPIPChannel(
            new Client({ hostname: "unused", username: "test" }),
            {
                destinationHost: "\ud800",
                destinationPort: 22,
                sourceHost: "127.0.0.1",
                sourcePort: 0,
            },
        )
        expect(() => outbound.getOpenPacket()).toThrow(
            "direct-tcpip destination address is not valid UTF-8 text",
        )
    })

    test("round-trips fixed forwarded channel confirmation and rejection packets", () => {
        const confirmation = vector("5b 0000000b 0000002a 00200000 00008000")
        const rejection = vector("5c 0000000b 00000001 00000006 64656e696564 00000000")

        expect(ChannelOpenConfirmation.parse(confirmation).data).toEqual({
            recipient_channel_id: 11,
            sender_channel_id: 42,
            initial_window_size: 2_097_152,
            maximum_packet_size: 32_768,
            args: Buffer.alloc(0),
        })
        expect(ChannelOpenConfirmation.parse(confirmation).serialize()).toEqual(confirmation)
        expect(ChannelOpenFailure.parse(rejection).data).toEqual({
            recipient_channel_id: 11,
            reason_code: 1,
            description: "denied",
            language_tag: "",
        })
        expect(ChannelOpenFailure.parse(rejection).serialize()).toEqual(rejection)
    })

    test("channel open results snapshot metadata and own opaque reply bytes", () => {
        const confirmationArgs = Buffer.from("details")
        const confirmationInput = {
            recipient_channel_id: 11,
            sender_channel_id: 42,
            initial_window_size: 2_097_152,
            maximum_packet_size: 32_768,
            args: confirmationArgs,
        }
        const confirmation = new ChannelOpenConfirmation(confirmationInput)
        confirmationInput.recipient_channel_id = 12
        confirmationArgs.fill(0xff)
        expect(confirmation.data).toEqual({
            recipient_channel_id: 11,
            sender_channel_id: 42,
            initial_window_size: 2_097_152,
            maximum_packet_size: 32_768,
            args: Buffer.from("details"),
        })

        const failureInput = {
            recipient_channel_id: 11,
            reason_code: ChannelOpenFailureReasonCodes.SSH_OPEN_CONNECT_FAILED,
            description: "refused",
            language_tag: "en",
        }
        const failure = new ChannelOpenFailure(failureInput)
        failureInput.recipient_channel_id = 12
        failureInput.description = "changed"
        expect(failure.data).toEqual({
            recipient_channel_id: 11,
            reason_code: ChannelOpenFailureReasonCodes.SSH_OPEN_CONNECT_FAILED,
            description: "refused",
            language_tag: "en",
        })

        const frame = vector("5b 0000000b 0000002a 00200000 00008000 64657461696c73")
        const parsed = ChannelOpenConfirmation.parse(frame)
        frame.fill(0xff)
        expect(parsed.data.args).toEqual(Buffer.from("details"))
    })
})
