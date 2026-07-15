import Client, { type ClientOptions } from "../../src/Client.js"

describe("client configuration normalization", () => {
    test("does not treat malformed values as omitted options", () => {
        expect(() => new Client(null as never)).toThrow("SSH client options must be an object")
        const cases: readonly [ClientOptions, string][] = [
            [
                { protocolVersionExchange: null as never },
                "SSH client protocolVersionExchange option must be a ProtocolVersionExchange",
            ],
            [{ algorithms: null as never }, "SSH client algorithms option must be an object"],
            [{ gssapi: null as never }, "SSH client GSS-API mechanisms must be an array"],
            [
                { authenticationMethodsOrder: null as never },
                "SSH authentication method order must be an array",
            ],
            [{ readyTimeout: null as never }, "SSH ready timeout must be a non-negative number"],
            [{ replyTimeout: null as never }, "SSH reply timeout must be a positive number"],
            [
                { keepaliveInterval: null as never },
                "SSH keepalive interval must be a non-negative number",
            ],
            [
                { keepaliveCountMax: null as never },
                "SSH keepalive count maximum must be a non-negative integer",
            ],
            [
                { rekeyBytes: null as never },
                "SSH rekey byte limit must be a non-negative safe integer",
            ],
            [
                { rekeyInterval: null as never },
                "SSH rekey interval must be an integer between 0 and 2147483647",
            ],
            [
                { maxPendingChannelOpens: null as never },
                "SSH maximum pending channel opens must be a non-negative safe integer",
            ],
            [
                { maxChannels: null as never },
                "SSH maximum simultaneous channels must be a non-negative safe integer",
            ],
            [{ hostbased: null as never }, "SSH hostbased option must be an object"],
            [{ hostbased: {} as never }, "SSH hostbased key must be a private key"],
            [{ sock: null as never }, "SSH sock option must be a duplex stream"],
        ]

        for (const [options, message] of cases) {
            expect(() => new Client(options)).toThrow(message)
        }
    })
})
