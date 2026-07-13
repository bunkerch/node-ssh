import UserAuthBanner from "../../src/packets/UserAuthBanner.js"
import UserAuthInfoRequest from "../../src/packets/UserAuthInfoRequest.js"
import UserAuthInfoResponse from "../../src/packets/UserAuthInfoResponse.js"
import UserAuthPasswordChangeRequest from "../../src/packets/UserAuthPasswordChangeRequest.js"
import UserAuthRequest, { UnknownAuthMethod } from "../../src/packets/UserAuthRequest.js"

const banner = Buffer.from(
    "3500000018417574686f72697a656420616363657373206f6e6c790d0a" + "00000005656e2d5553",
    "hex",
)
const passwordChange = Buffer.from("3c0000001050617373776f7264206578706972656400000000", "hex")
const infoRequest = Buffer.from(
    "3c000000054c6f67696e00000011456e7465722063726564656e7469616c73" +
        "00000000000000020000000a50617373776f72643a2000000000054f54503a2001",
    "hex",
)
const infoResponse = Buffer.from("3d000000020000000673656372657400000006313233343536", "hex")
const keyboardRequest = Buffer.from(
    "3200000005616c6963650000000e7373682d636f6e6e656374696f6e" +
        "000000146b6579626f6172642d696e74657261637469766500000000" +
        "0000000c6f74702c70617373776f7264",
    "hex",
)
const changedPasswordRequest = Buffer.from(
    "3200000005616c6963650000000e7373682d636f6e6e656374696f6e" +
        "0000000870617373776f726401000000036f6c64000000036e6577",
    "hex",
)
const unknownRequest = Buffer.from(
    "3200000005616c6963650000000e7373682d636f6e6e656374696f6e" +
        "0000000b6675747572652d61757468deadbeef",
    "hex",
)

describe("RFC 4252 and RFC 4256 authentication vectors", () => {
    test("parses and serializes a fixed user authentication banner", () => {
        const packet = UserAuthBanner.parse(banner)
        expect(packet.data).toEqual({
            message: "Authorized access only\r\n",
            languageTag: "en-US",
        })
        expect(packet.serialize()).toEqual(banner)
    })

    test("parses and serializes a fixed password-change request", () => {
        const packet = UserAuthPasswordChangeRequest.parse(passwordChange)
        expect(packet.data).toEqual({ prompt: "Password expired", languageTag: "" })
        expect(packet.serialize()).toEqual(passwordChange)
    })

    test("parses and serializes fixed keyboard-interactive request and response messages", () => {
        const request = UserAuthInfoRequest.parse(infoRequest)
        expect(request.data).toEqual({
            name: "Login",
            instruction: "Enter credentials",
            languageTag: "",
            prompts: [
                { prompt: "Password: ", echo: false },
                { prompt: "OTP: ", echo: true },
            ],
        })
        expect(request.serialize()).toEqual(infoRequest)

        const response = UserAuthInfoResponse.parse(infoResponse)
        expect(response.data.responses).toEqual(["secret", "123456"])
        expect(response.serialize()).toEqual(infoResponse)
    })

    test("parses fixed keyboard-interactive and changed-password authentication requests", () => {
        const keyboard = UserAuthRequest.parse(keyboardRequest)
        expect(keyboard.data.method.method_name).toBe("keyboard-interactive")
        expect((keyboard.data.method as { data: unknown }).data).toEqual({
            languageTag: "",
            submethods: "otp,password",
        })
        expect(keyboard.serialize()).toEqual(keyboardRequest)

        const password = UserAuthRequest.parse(changedPasswordRequest)
        expect(password.data.method.method_name).toBe("password")
        expect((password.data.method as { data: unknown }).data).toEqual({
            change_password: true,
            password: "old",
            newPassword: "new",
        })
        expect(password.serialize()).toEqual(changedPasswordRequest)
    })

    test("rejects an empty keyboard-interactive prompt", () => {
        expect(
            () =>
                new UserAuthInfoRequest({
                    name: "",
                    instruction: "",
                    languageTag: "",
                    prompts: [{ prompt: "", echo: false }],
                }),
        ).toThrow("must not be empty")
    })

    test("preserves an unknown authentication method for server-side rejection", () => {
        const packet = UserAuthRequest.parse(unknownRequest)
        expect(packet.data.method).toBeInstanceOf(UnknownAuthMethod)
        expect(packet.data.method.method_name).toBe("future-auth")
        expect((packet.data.method as UnknownAuthMethod).data).toEqual(
            Buffer.from("deadbeef", "hex"),
        )
        expect(packet.serialize()).toEqual(unknownRequest)
    })
})
