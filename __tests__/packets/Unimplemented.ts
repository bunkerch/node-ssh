import Unimplemented from "../../src/packets/Unimplemented.js"
import NewKeys from "../../src/packets/NewKeys.js"
import RequestFailure from "../../src/packets/RequestFailure.js"
import UserAuthSuccess from "../../src/packets/UserAuthSuccess.js"

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

    test("snapshots sequence metadata and validates zero-field markers", () => {
        const input = { sequence_number: 0x0102_0304 }
        const packet = new Unimplemented(input)
        input.sequence_number = 0
        expect(packet.serialize()).toEqual(Buffer.from("0301020304", "hex"))

        expect(new NewKeys().serialize()).toEqual(Buffer.from("15", "hex"))
        expect(new RequestFailure().serialize()).toEqual(Buffer.from("52", "hex"))
        expect(new UserAuthSuccess().serialize()).toEqual(Buffer.from("34", "hex"))
        expect(() => new NewKeys({ field: true } as never)).toThrow("does not accept fields")
        expect(() => new RequestFailure({ field: true } as never)).toThrow("does not accept fields")
        expect(() => new UserAuthSuccess({ field: true } as never)).toThrow(
            "does not accept fields",
        )
    })
})
