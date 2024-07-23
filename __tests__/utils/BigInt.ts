import {
    decodeBigIntBE,
    decodeBigIntLE,
    encodeBigIntBE,
    encodeBigIntLE,
} from "../../src/utils/BigInt.js"

describe("Utils", () => {
    describe("BigInt", () => {
        describe("encode", () => {
            test("Big-Endian", () => {
                const result = encodeBigIntBE(0x1234567890abcdefn)
                expect(result.toString("hex")).toBe("1234567890abcdef")
            })

            test("Little-Endian", () => {
                const result = encodeBigIntLE(0x1234567890abcdefn)
                expect(result.toString("hex")).toBe("efcdab9078563412")
            })
        })

        describe("decode", () => {
            test("Big-Endian", () => {
                const result = Buffer.from("1234567890abcdef", "hex")
                expect(decodeBigIntBE(result)).toBe(0x1234567890abcdefn)
            })

            test("Little-Endian", () => {
                const result = Buffer.from("efcdab9078563412", "hex")
                expect(decodeBigIntLE(result)).toBe(0x1234567890abcdefn)
            })
        })
    })
})
