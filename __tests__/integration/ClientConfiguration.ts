import Client, { type ClientOptions } from "../../src/Client.js"

describe("client configuration normalization", () => {
    test("does not treat malformed values as omitted options", () => {
        expect(() => new Client(null as never)).toThrow("SSH client options must be an object")
        expect(() => new Client({} as never)).toThrow(
            "SSH username option is required and must be a string",
        )
        const cases: readonly [Partial<ClientOptions>, string][] = [
            [
                { protocolVersionExchange: null as never },
                "SSH client protocolVersionExchange option must be a ProtocolVersionExchange",
            ],
            [{ ident: null as never }, "SSH identification suffix must be a string or Buffer"],
            [
                { serverClient: true } as never,
                "SSH serverClient is not a client option; use ServerClient for accepted peers",
            ],
            [{ algorithms: null as never }, "SSH client algorithms option must be an object"],
            [{ gssapi: null as never }, "SSH client GSS-API mechanisms must be an array"],
            [
                { authenticationMethodsOrder: null as never },
                "SSH authentication method order must be an array",
            ],
            [
                { authenticationSignatureAlgorithms: null as never },
                "SSH authentication signature algorithms must be an array",
            ],
            [
                { authenticationSignatureAlgorithms: [] },
                "SSH authentication signature algorithm list must not be empty",
            ],
            [
                { authenticationSignatureAlgorithms: ["unsupported@example.test"] },
                "Unsupported SSH authentication signature algorithm",
            ],
            [
                { authenticationSignatureAlgorithms: ["ssh-ed25519", "ssh-ed25519"] },
                "Duplicate SSH authentication signature algorithm",
            ],
            [{ readyTimeout: null as never }, "SSH ready timeout must be a non-negative number"],
            [
                { timeout: null as never },
                "SSH transport inactivity timeout must be an integer between 0 and 2147483647",
            ],
            [
                { timeout: -1 },
                "SSH transport inactivity timeout must be an integer between 0 and 2147483647",
            ],
            [
                { timeout: 1.5 },
                "SSH transport inactivity timeout must be an integer between 0 and 2147483647",
            ],
            [
                { timeout: 2_147_483_648 },
                "SSH transport inactivity timeout must be an integer between 0 and 2147483647",
            ],
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
            expect(() => new Client({ username: "test", ...options })).toThrow(message)
        }
    })
})
