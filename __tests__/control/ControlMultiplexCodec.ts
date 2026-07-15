import {
    CONTROL_MULTIPLEX_VERSION,
    ControlMultiplexDecoder,
    ControlMultiplexForwardType,
    ControlMultiplexMessageType,
    ControlMultiplexProtocolError,
    decodeControlMultiplexRequest,
    encodeControlMultiplexHello,
    encodeControlMultiplexReply,
} from "../../src/control/ControlMultiplexCodec.js"

describe("OpenSSH control multiplex protocol", () => {
    test("encodes the protocol version hello exactly", () => {
        expect(encodeControlMultiplexHello()).toEqual(
            Buffer.from("000000080000000100000004", "hex"),
        )
        expect(CONTROL_MULTIPLEX_VERSION).toBe(4)
    })

    test("decodes fixed hello, session, forwarding, and administrative requests", () => {
        const hello = decodeControlMultiplexRequest(
            Buffer.from("000000010000000400000004696e666f0000000130", "hex"),
        )
        expect(hello).toEqual({
            type: ControlMultiplexMessageType.Hello,
            version: 4,
            extensions: new Map([["info", Buffer.from("0")]]),
        })

        const session = decodeControlMultiplexRequest(
            Buffer.from(
                "10000002010203040000000000000001000000000000000100000000ffffffff" +
                    "00000005787465726d00000007756e616d652d6100000003413d42",
                "hex",
            ),
        )
        expect(session).toEqual({
            type: ControlMultiplexMessageType.NewSession,
            requestId: 0x01020304,
            reserved: Buffer.alloc(0),
            wantTty: true,
            wantX11: false,
            wantAgent: true,
            subsystem: false,
            escapeCharacter: 0xffffffff,
            terminalType: "xterm",
            command: "uname-a",
            environment: ["A=B"],
        })

        const forward = decodeControlMultiplexRequest(
            Buffer.from(
                "100000061122334400000002000000093132372e302e302e3100000000" +
                    "0000000b6578616d706c652e636f6d00000016",
                "hex",
            ),
        )
        expect(forward).toEqual({
            type: ControlMultiplexMessageType.OpenForward,
            requestId: 0x11223344,
            forwardType: ControlMultiplexForwardType.Remote,
            listenHost: "127.0.0.1",
            listenPort: 0,
            destinationHost: "example.com",
            destinationPort: 22,
        })

        expect(decodeControlMultiplexRequest(Buffer.from("10000004aabbccdd", "hex"))).toEqual({
            type: ControlMultiplexMessageType.AliveCheck,
            requestId: 0xaabbccdd,
        })
    })

    test("frames fragmented and adjacent packets without retaining caller buffers", () => {
        const decoder = new ControlMultiplexDecoder()
        const first = Buffer.from("000000081000000401020304", "hex")
        const second = Buffer.from("0000000810000005aabbccdd", "hex")
        const combined = Buffer.concat([first, second])
        expect(decoder.push(combined.subarray(0, 7))).toEqual([])
        combined.fill(0, 0, 7)
        expect(decoder.push(Buffer.concat([first.subarray(7), second]))).toEqual([
            { type: ControlMultiplexMessageType.AliveCheck, requestId: 0x01020304 },
            { type: ControlMultiplexMessageType.Terminate, requestId: 0xaabbccdd },
        ])
    })

    test("encodes status replies exactly", () => {
        expect(encodeControlMultiplexReply(ControlMultiplexMessageType.Alive, 7, 1234)).toEqual(
            Buffer.from("0000000c8000000500000007000004d2", "hex"),
        )
        expect(
            encodeControlMultiplexReply(ControlMultiplexMessageType.Failure, 8, "denied"),
        ).toEqual(Buffer.from("0000001280000003000000080000000664656e696564", "hex"))
    })

    test("rejects malformed lengths, booleans, duplicate extensions, and trailing data", () => {
        const decoder = new ControlMultiplexDecoder()
        expect(() => decoder.push(Buffer.from("00000003", "hex"))).toThrow(
            ControlMultiplexProtocolError,
        )
        expect(() =>
            decodeControlMultiplexRequest(
                Buffer.from(
                    "10000002000000010000000000000002000000000000000000000000ffffffff" +
                        "0000000000000000",
                    "hex",
                ),
            ),
        ).toThrow("Invalid multiplex want TTY boolean")
        expect(() =>
            decodeControlMultiplexRequest(
                Buffer.from("0000000100000004000000017800000000000000017800000000", "hex"),
            ),
        ).toThrow("Duplicate multiplex extension x")
        expect(() =>
            decodeControlMultiplexRequest(Buffer.from("100000040000000100", "hex")),
        ).toThrow("Trailing multiplex request data")
    })
})
