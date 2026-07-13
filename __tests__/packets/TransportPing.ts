import Ping from "../../src/packets/Ping.js"
import Pong from "../../src/packets/Pong.js"

describe("transport ping fixed vectors", () => {
    test("parses and serializes an opaque ping payload", () => {
        const vector = Buffer.from("c00000000550494e4721", "hex")
        const packet = Ping.parse(vector)
        expect(packet.data.data).toEqual(Buffer.from("PING!", "ascii"))
        expect(packet.serialize()).toEqual(vector)
    })

    test("parses and serializes an empty pong payload", () => {
        const vector = Buffer.from("c100000000", "hex")
        const packet = Pong.parse(vector)
        expect(packet.data.data).toEqual(Buffer.alloc(0))
        expect(packet.serialize()).toEqual(vector)
    })

    test("rejects truncated, trailing, and incorrectly typed messages", () => {
        expect(() => Ping.parse(Buffer.from("c0000000040102", "hex"))).toThrow()
        expect(() => Pong.parse(Buffer.from("c10000000000", "hex"))).toThrow()
        expect(() => Ping.parse(Buffer.from("c100000000", "hex"))).toThrow()
    })

    test("copies caller-owned data before serialization", () => {
        const data = Buffer.from("mutable")
        const ping = new Ping({ data })
        data.fill(0)
        expect(ping.data.data.toString()).toBe("mutable")
    })
})
