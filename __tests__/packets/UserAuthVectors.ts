import UserAuthBanner from "../../src/packets/UserAuthBanner.js"
import UserAuthInfoRequest from "../../src/packets/UserAuthInfoRequest.js"
import UserAuthInfoResponse from "../../src/packets/UserAuthInfoResponse.js"
import UserAuthPasswordChangeRequest from "../../src/packets/UserAuthPasswordChangeRequest.js"
import UserAuthRequest, { UnknownAuthMethod } from "../../src/packets/UserAuthRequest.js"
import PublicKeyAuthMethod, { HostboundPublicKeyAuthMethod } from "../../src/auth/publickey.js"
import HostbasedAuthMethod from "../../src/auth/hostbased.js"
import type Client from "../../src/Client.js"

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
const rsaSha512Request = Buffer.from(
    "3200000005616c6963650000000e7373682d636f6e6e656374696f6e" +
        "000000097075626c69636b6579010000000c7273612d736861322d353132" +
        "0000001b000000077373682d727361000000030100010000000500deadbeef" +
        "000000180000000c7273612d736861322d3531320000000401020304",
    "hex",
)
const hostbasedRequest = Buffer.from(
    "320000000672656d6f74650000000e7373682d636f6e6e656374696f6e" +
        "00000009686f737462617365640000000b7373682d6564323535313900000033" +
        "0000000b7373682d6564323535313900000020000102030405060708090a0b0c0d0e0f" +
        "101112131415161718191a1b1c1d1e1f0000000e636c69656e742e6578616d706c65" +
        "00000005616c696365000000530000000b7373682d6564323535313900000040" +
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
    "hex",
)
const hostbasedSignatureMessage = Buffer.from(
    "0000000401020304320000000672656d6f74650000000e7373682d636f6e6e656374696f6e" +
        "00000009686f737462617365640000000b7373682d6564323535313900000033" +
        "0000000b7373682d6564323535313900000020000102030405060708090a0b0c0d0e0f" +
        "101112131415161718191a1b1c1d1e1f0000000e636c69656e742e6578616d706c65" +
        "00000005616c696365",
    "hex",
)
const hostboundRequest = Buffer.from(
    "3200000005616c6963650000000e7373682d636f6e6e656374696f6e" +
        "000000237075626c69636b65792d686f7374626f756e642d763030406f70656e7373682e636f6d" +
        "010000000b7373682d65643235353139000000330000000b7373682d65643235353139" +
        "00000020000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
        "000000330000000b7373682d6564323535313900000020202122232425262728292a2b2c2d2e2f" +
        "303132333435363738393a3b3c3d3e3f000000530000000b7373682d65643235353139" +
        "00000040000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
    "hex",
)
const hostboundSignatureMessage = Buffer.from(
    "00000004010203043200000005616c6963650000000e7373682d636f6e6e656374696f6e" +
        "000000237075626c69636b65792d686f7374626f756e642d763030406f70656e7373682e636f6d" +
        "010000000b7373682d65643235353139000000330000000b7373682d65643235353139" +
        "00000020000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
        "000000330000000b7373682d6564323535313900000020202122232425262728292a2b2c2d2e2f" +
        "303132333435363738393a3b3c3d3e3f",
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

    test("parses and serializes an independently written RFC 8332 RSA SHA-512 request", () => {
        const packet = UserAuthRequest.parse(rsaSha512Request)
        const method = packet.data.method as PublicKeyAuthMethod

        expect(method.data.algorithm).toBe("rsa-sha2-512")
        expect(method.data.publicKey.data.alg).toBe("ssh-rsa")
        expect(method.data.signature?.data).toEqual({
            alg: "rsa-sha2-512",
            data: Buffer.from("01020304", "hex"),
        })
        expect(packet.serialize()).toEqual(rsaSha512Request)
    })

    test("binds a public-key signature to the exact server host key", () => {
        const packet = UserAuthRequest.parse(hostboundRequest)
        const method = packet.data.method as HostboundPublicKeyAuthMethod

        expect(method).toBeInstanceOf(HostboundPublicKeyAuthMethod)
        expect(method.data.serverHostKey).toEqual(
            Buffer.from(
                "0000000b7373682d6564323535313900000020202122232425262728292a2b2c2d2e2f" +
                    "303132333435363738393a3b3c3d3e3f",
                "hex",
            ),
        )
        expect(packet.serialize()).toEqual(hostboundRequest)
        expect(
            packet.serializeForSignature({ sessionID: Buffer.from("01020304", "hex") } as Client),
        ).toEqual(hostboundSignatureMessage)
    })

    test.each([
        ["ordinary", rsaSha512Request],
        ["host-bound", hostboundRequest],
    ])("rejects a malformed %s public-key signature algorithm", (_name, request) => {
        const malformed = Buffer.from(request)
        const algorithm = Buffer.from(request === rsaSha512Request ? "rsa-sha2-512" : "ssh-ed25519")
        const offset = malformed.indexOf(algorithm)
        expect(offset).toBeGreaterThanOrEqual(0)
        malformed[offset] = 0xff

        expect(() => UserAuthRequest.parse(malformed)).toThrow(
            "SSH public-key signature algorithm must be US-ASCII",
        )
    })

    test("does not mutate or retain public-key method constructor metadata", () => {
        const parsed = UserAuthRequest.parse(rsaSha512Request).data.method as PublicKeyAuthMethod
        const input = { ...parsed.data, signature: undefined }
        const method = new PublicKeyAuthMethod(input)
        expect(input.algorithm).toBe("rsa-sha2-512")
        input.algorithm = "ssh-rsa"

        expect(method.data.algorithm).toBe("rsa-sha2-512")
    })

    test("parses and serializes an independently written RFC 4252 hostbased request", () => {
        const packet = UserAuthRequest.parse(hostbasedRequest)
        const method = packet.data.method as HostbasedAuthMethod

        expect(packet.data.username).toBe("remote")
        expect(method.data.algorithm).toBe("ssh-ed25519")
        expect(method.data.publicKey.data.alg).toBe("ssh-ed25519")
        expect(method.data.clientHostname).toBe("client.example")
        expect(method.data.clientUsername).toBe("alice")
        expect(method.data.signature.data).toEqual({
            alg: "ssh-ed25519",
            data: Buffer.from(Array.from({ length: 64 }, (_, index) => index)),
        })
        expect(packet.serialize()).toEqual(hostbasedRequest)
        expect(
            packet.serializeForSignature({ sessionID: Buffer.from("01020304", "hex") } as Client),
        ).toEqual(hostbasedSignatureMessage)
    })

    test("rejects malformed hostbased identity fields", () => {
        const packet = UserAuthRequest.parse(hostbasedRequest)
        const method = packet.data.method as HostbasedAuthMethod
        expect(
            () => new HostbasedAuthMethod({ ...method.data, clientHostname: "not a hostname!" }),
        ).toThrow("valid ASCII FQDN")
        expect(() => new HostbasedAuthMethod({ ...method.data, clientUsername: "" })).toThrow(
            "username is invalid",
        )

        const malformedAlgorithm = Buffer.from(hostbasedRequest)
        const algorithmOffset = malformedAlgorithm.indexOf("ssh-ed25519")
        expect(algorithmOffset).toBeGreaterThanOrEqual(0)
        malformedAlgorithm[algorithmOffset] = 0xff
        expect(() => UserAuthRequest.parse(malformedAlgorithm)).toThrow(
            "SSH hostbased signature algorithm must be US-ASCII",
        )
    })

    test("does not retain hostbased constructor metadata", () => {
        const parsed = UserAuthRequest.parse(hostbasedRequest).data.method as HostbasedAuthMethod
        const input = { ...parsed.data }
        const method = new HostbasedAuthMethod(input)
        input.algorithm = "ssh-rsa"
        input.clientHostname = "other.example"

        expect(method.data.algorithm).toBe("ssh-ed25519")
        expect(method.data.clientHostname).toBe("client.example")
    })
})
