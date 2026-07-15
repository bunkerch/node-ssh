import Server, { type ServerOptions } from "../../src/Server.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

describe("server configuration normalization", () => {
    test("does not treat malformed values as omitted options", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        expect(() => new Server(null as never)).toThrow("SSH server options must be an object")
        const cases: readonly [ServerOptions, string][] = [
            [{ hostKeys: null as never }, "SSH server hostKeys option must be an array"],
            [
                { hostKeys: [hostKey], hostCertificates: null as never },
                "SSH server hostCertificates option must be an array",
            ],
            [
                { hostKeys: [hostKey], sendAllHostKeys: "false" as never },
                "SSH server sendAllHostKeys option must be a boolean",
            ],
            [
                { hostKeys: [hostKey], banner: null as never },
                "SSH authentication banner must be a string",
            ],
            [
                { hostKeys: [hostKey], bannerLanguageTag: null as never },
                "SSH authentication banner language tag must be a string",
            ],
            [
                { hostKeys: [hostKey], handshakeTimeout: null as never },
                "SSH handshake timeout must be a non-negative number",
            ],
            [
                { hostKeys: [hostKey], gssapi: null as never },
                "SSH server GSS-API mechanisms must be an array",
            ],
            [
                { hostKeys: [hostKey], protocolVersionExchange: null as never },
                "SSH server protocolVersionExchange option must be a ProtocolVersionExchange",
            ],
            [
                { hostKeys: [hostKey], ident: null as never },
                "SSH identification suffix must be a string or Buffer",
            ],
            [
                { hostKeys: [hostKey], algorithms: null as never },
                "SSH server algorithms option must be an object",
            ],
        ]

        for (const [options, message] of cases) {
            expect(() => new Server(options)).toThrow(message)
        }
    })
})
