import ChannelOpenFailure from "../../src/packets/ChannelOpenFailure.js"
import Debug from "../../src/packets/Debug.js"
import Disconnect from "../../src/packets/Disconnect.js"
import UserAuthBanner from "../../src/packets/UserAuthBanner.js"
import UserAuthInfoRequest from "../../src/packets/UserAuthInfoRequest.js"
import UserAuthInfoResponse from "../../src/packets/UserAuthInfoResponse.js"
import UserAuthPasswordChangeRequest from "../../src/packets/UserAuthPasswordChangeRequest.js"
import UserAuthRequest from "../../src/packets/UserAuthRequest.js"
import NoneAuthMethod from "../../src/auth/none.js"
import ExtInfo from "../../src/packets/ExtInfo.js"
import ServiceRequest from "../../src/packets/ServiceRequest.js"
import ChannelRequest from "../../src/packets/ChannelRequest.js"
import Ignore from "../../src/packets/Ignore.js"
import { encodeSSHUTF8 } from "../../src/utils/SSHText.js"

function vector(hex: string): Buffer {
    return Buffer.from(hex.replace(/\s/gu, ""), "hex")
}

describe("RFC SSH text fields", () => {
    test("rejects every unpaired UTF-16 surrogate before UTF-8 serialization", () => {
        for (const value of ["\ud800", "\ud800x", "\udc00"]) {
            expect(() => encodeSSHUTF8(value, "test field")).toThrow(
                "test field is not valid UTF-8 text",
            )
        }
        expect(encodeSSHUTF8("\ud83d\ude80", "test field")).toEqual(Buffer.from("🚀"))
    })
    test("parses and serializes fixed UTF-8 debug and private disconnect frames", () => {
        const debugRaw = vector(`
            04 01
            00000006 68c3a96c6c6f
            00000005 66722d4341
        `)
        const disconnectRaw = vector(`
            01 fe000001
            00000007 70726976617465
            00000000
        `)

        const debug = Debug.parse(debugRaw)
        expect(debug.data).toEqual({
            always_display: true,
            message: "héllo",
            language_tag: "fr-CA",
        })
        expect(debug.serialize()).toEqual(debugRaw)

        const disconnect = Disconnect.parse(disconnectRaw)
        expect(disconnect.data).toEqual({
            reason_code: 0xfe00_0001,
            description: "private",
            language_tag: "",
        })
        expect(disconnect.serialize()).toEqual(disconnectRaw)
    })

    test("parses a fixed ignore frame and owns its opaque bytes", () => {
        const raw = vector("02 00000004 deadbeef")
        const ignore = Ignore.parse(raw)
        expect(ignore.data.data).toEqual(vector("deadbeef"))
        expect(ignore.serialize()).toEqual(raw)

        const input = vector("01020304")
        const outbound = new Ignore({ data: input })
        input.fill(0xff)
        expect(outbound.serialize()).toEqual(vector("02 00000004 01020304"))
    })

    test.each([
        ["debug", (raw: Buffer) => Debug.parse(raw), "04 00 00000001 ff 00000000"],
        ["disconnect", (raw: Buffer) => Disconnect.parse(raw), "01 0000000b 00000001 ff 00000000"],
        [
            "channel open failure",
            (raw: Buffer) => ChannelOpenFailure.parse(raw),
            "5c 00000007 00000001 00000001 ff 00000000",
        ],
        [
            "authentication banner",
            (raw: Buffer) => UserAuthBanner.parse(raw),
            "35 00000001 ff 00000000",
        ],
        [
            "password change",
            (raw: Buffer) => UserAuthPasswordChangeRequest.parse(raw),
            "3c 00000001 ff 00000000",
        ],
    ])("rejects malformed UTF-8 in a %s", (_name, parse, hex) => {
        expect(() => parse(vector(hex))).toThrow("not valid UTF-8")
    })

    test("rejects malformed inbound and outbound language tags", () => {
        expect(() => Debug.parse(vector("04 00 00000000 00000005 656e5f5858"))).toThrow("RFC 3066")
        expect(() =>
            new UserAuthBanner({ message: "hello", languageTag: "en_XX" }).serialize(),
        ).toThrow("RFC 3066")
        expect(() =>
            new Disconnect({
                reason_code: 11,
                description: "bad\ud800text",
                language_tag: "",
            }).serialize(),
        ).toThrow("not valid UTF-8")
        expect(
            () =>
                new Debug({
                    always_display: false,
                    message: "invalid\ud800debug",
                    language_tag: "",
                }),
        ).toThrow("not valid UTF-8")
    })

    test("validates every keyboard-interactive text field", () => {
        const valid = new UserAuthInfoRequest({
            name: "Vérification",
            instruction: "Répondez",
            languageTag: "fr",
            prompts: [{ prompt: "Code : ", echo: false }],
        })
        expect(UserAuthInfoRequest.parse(valid.serialize()).data).toEqual(valid.data)

        expect(() =>
            UserAuthInfoRequest.parse(
                vector("3c 00000000 00000000 00000000 00000001 00000001 ff 00"),
            ),
        ).toThrow("not valid UTF-8")
        expect(() => UserAuthInfoResponse.parse(vector("3d 00000001 00000001 ff"))).toThrow(
            "not valid UTF-8",
        )
    })

    test("rejects malformed inbound and outbound usernames", () => {
        expect(() =>
            UserAuthRequest.parse(
                vector(`
                    32 00000001 ff
                    0000000e 7373682d636f6e6e656374696f6e
                    00000004 6e6f6e65
                `),
            ),
        ).toThrow("SSH username")
        expect(() =>
            new UserAuthRequest({
                username: "bad\ud800user",
                service_name: "ssh-connection",
                method: new NoneAuthMethod(),
            }).serialize(),
        ).toThrow("SSH username")
    })

    test("rejects outbound disconnect reasons outside uint32", () => {
        expect(() =>
            new Disconnect({
                reason_code: 0x1_0000_0000,
                description: "outside range",
                language_tag: "",
            }).serialize(),
        ).toThrow("uint32")
    })

    test("applies RFC 4250 name validation to protocol packets", () => {
        expect(() => ServiceRequest.parse(vector("05 00000001 ff"))).toThrow("US-ASCII")
        expect(
            () => new ExtInfo({ extensions: [{ name: "bad extension", value: Buffer.alloc(0) }] }),
        ).toThrow("printable")
        expect(() =>
            new ChannelRequest({
                recipient_channel_id: 1,
                request_type: "bad,request",
                want_reply: false,
                args: Buffer.alloc(0),
            }).serialize(),
        ).toThrow("comma")
    })
})
