import Unimplemented from "../../src/packets/Unimplemented.js"

describe("RFC 4253 unimplemented response vectors", () => {
    test("parses and serializes the rejected packet sequence number", () => {
        const vector = Buffer.from("0301020304", "hex")
        const packet = Unimplemented.parse(vector)
        expect(packet.data.sequence_number).toBe(0x0102_0304)
        expect(packet.serialize()).toEqual(vector)
    })

    test("rejects truncated and trailing fields", () => {
        expect(() => Unimplemented.parse(Buffer.from("03010203", "hex"))).toThrow()
        expect(() => Unimplemented.parse(Buffer.from("030102030400", "hex"))).toThrow()
    })
})
