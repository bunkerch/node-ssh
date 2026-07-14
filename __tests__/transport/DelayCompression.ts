import {
    DELAY_COMPRESSION_EXTENSION,
    delayCompressionExtension,
    findDelayCompressionOffers,
    negotiateDelayCompression,
    normalizeDelayCompression,
    parseDelayCompressionValue,
} from "../../src/DelayCompression.js"
import ExtInfo from "../../src/packets/ExtInfo.js"
import NewCompress from "../../src/packets/NewCompress.js"

describe("RFC 8308 delay-compression negotiation", () => {
    test("parses the RFC directional name-list example and serializes exact extension bytes", () => {
        expect(
            parseDelayCompressionValue(
                Buffer.from("00000007666f6f2c626172000000076261722c62617a", "hex"),
            ),
        ).toEqual({
            clientToServer: ["foo", "bar"],
            serverToClient: ["bar", "baz"],
        })

        const extension = delayCompressionExtension({
            clientToServer: ["zlib", "none"],
            serverToClient: ["none", "zlib"],
        })
        expect(extension).toEqual({
            name: DELAY_COMPRESSION_EXTENSION,
            value: Buffer.from("000000097a6c69622c6e6f6e65000000096e6f6e652c7a6c6962", "hex"),
        })
        expect(new ExtInfo({ extensions: [extension] }).serialize()).toEqual(
            Buffer.from(
                "07000000010000001164656c61792d636f6d7072657373696f6e0000001a000000097a6c69622c6e6f6e65000000096e6f6e652c7a6c6962",
                "hex",
            ),
        )
    })

    test("uses opcode 8 for the exact NEWCOMPRESS trigger packet", () => {
        const bytes = Buffer.from([8])
        expect(NewCompress.parse(bytes).serialize()).toEqual(bytes)
        expect(() => NewCompress.parse(Buffer.from([8, 0]))).toThrow("Unexpected data")
    })

    test("normalizes an opt-in without retaining caller-owned lists", () => {
        expect(normalizeDelayCompression(undefined)).toBe(false)
        expect(normalizeDelayCompression(false)).toBe(false)
        expect(normalizeDelayCompression(true)).toEqual({
            clientToServer: ["zlib", "none"],
            serverToClient: ["zlib", "none"],
        })

        const clientToServer = ["none", "zlib"] as const
        const configured = normalizeDelayCompression({
            clientToServer,
            serverToClient: ["zlib"],
        })
        ;(clientToServer as unknown as string[])[0] = "changed"
        expect(configured).toEqual({
            clientToServer: ["none", "zlib"],
            serverToClient: ["zlib"],
        })
    })

    test("negotiates each direction using the client's preference order", () => {
        const client = {
            clientToServer: ["zlib", "none"],
            serverToClient: ["none", "zlib"],
        }
        const server = {
            clientToServer: ["none", "zlib"],
            serverToClient: ["zlib", "none"],
        }

        expect(negotiateDelayCompression(client, server)).toEqual({
            clientToServer: "zlib",
            serverToClient: "none",
        })
        expect(negotiateDelayCompression(client, undefined)).toBeUndefined()
        expect(
            findDelayCompressionOffers([
                delayCompressionExtension(server),
                { name: "other@example.com", value: Buffer.from("opaque") },
            ]),
        ).toEqual(server)
    })

    test("rejects forbidden, unsupported, empty, malformed, and non-mutual offers", () => {
        expect(() =>
            normalizeDelayCompression({ clientToServer: [], serverToClient: ["none"] }),
        ).toThrow("must not be empty")
        expect(() =>
            normalizeDelayCompression({
                clientToServer: ["zlib@openssh.com" as never],
                serverToClient: ["none"],
            }),
        ).toThrow("own delay semantics")
        expect(() =>
            normalizeDelayCompression({
                clientToServer: ["unknown@example.com" as never],
                serverToClient: ["none"],
            }),
        ).toThrow("Unsupported SSH delay-compression algorithm")
        expect(() => parseDelayCompressionValue(Buffer.from("00000000", "hex"))).toThrow(
            "Invalid SSH delay-compression extension value",
        )
        expect(() =>
            negotiateDelayCompression(
                { clientToServer: ["zlib"], serverToClient: ["none"] },
                { clientToServer: ["none"], serverToClient: ["zlib"] },
            ),
        ).toThrow("No mutual SSH delay-compression algorithm")
    })
})
