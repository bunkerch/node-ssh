import Client from "../../src/Client.js"
import ClientDirectStreamLocalChannel from "../../src/channels/ClientDirectStreamLocalChannel.js"
import ClientForwardedStreamLocalChannel from "../../src/channels/ClientForwardedStreamLocalChannel.js"
import ChannelOpen from "../../src/packets/ChannelOpen.js"
import GlobalRequest from "../../src/packets/GlobalRequest.js"

function vector(hex: string): Buffer {
    return Buffer.from(hex.replace(/\s/gu, ""), "hex")
}

const socketPath = "/tmp/service.sock"
const socketPathHex = "00000011 2f746d702f736572766963652e736f636b"

describe("OpenSSH stream-local forwarding vectors", () => {
    test.each([
        [
            "streamlocal-forward@openssh.com",
            `50 0000001f 73747265616d6c6f63616c2d666f7277617264406f70656e7373682e636f6d
             01 ${socketPathHex}`,
        ],
        [
            "cancel-streamlocal-forward@openssh.com",
            `50 00000026 63616e63656c2d73747265616d6c6f63616c2d666f7277617264406f70656e7373682e636f6d
             01 ${socketPathHex}`,
        ],
    ])("parses and serializes a fixed %s request", (requestName, hex) => {
        const raw = vector(hex)
        const packet = GlobalRequest.parse(raw)

        expect(packet.data).toEqual({
            request_name: requestName,
            want_reply: true,
            args: vector(socketPathHex),
        })
        expect(packet.serialize()).toEqual(raw)
    })

    test("serializes a fixed direct-streamlocal channel open", () => {
        const raw = vector(`
            5a 0000001e 6469726563742d73747265616d6c6f63616c406f70656e7373682e636f6d
            00000000 00200000 00008000
            ${socketPathHex} 00000000 00000000
        `)
        const channel = new ClientDirectStreamLocalChannel(
            new Client({ hostname: "unused" }),
            socketPath,
        )

        expect(channel.getOpenPacket().serialize()).toEqual(raw)
        expect(ChannelOpen.parse(raw).serialize()).toEqual(raw)
    })

    test("parses and serializes a fixed forwarded-streamlocal channel open", () => {
        const raw = vector(`
            5a 00000021 666f727761726465642d73747265616d6c6f63616c406f70656e7373682e636f6d
            0000000b 00200000 00008000
            ${socketPathHex} 00000000
        `)
        const packet = ChannelOpen.parse(raw)

        expect(ClientForwardedStreamLocalChannel.parseDetails(packet.data.args)).toEqual({
            socketPath,
        })
        expect(packet.serialize()).toEqual(raw)
    })

    test("rejects a malformed UTF-8 forwarded socket path", () => {
        expect(() =>
            ClientForwardedStreamLocalChannel.parseDetails(vector("00000001 ff 00000000")),
        ).toThrow("forwarded stream-local socket path is not valid UTF-8 text")
        const outbound = new ClientDirectStreamLocalChannel(
            new Client({ hostname: "unused" }),
            "\ud800",
        )
        expect(() => outbound.getOpenPacket()).toThrow(
            "direct stream-local socket path is not valid UTF-8 text",
        )
    })
})
