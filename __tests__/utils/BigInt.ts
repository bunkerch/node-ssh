import {
    decodeBigIntBE,
    decodeBigIntLE,
    encodeBigIntBE,
    encodeBigIntLE,
} from "../../src/utils/BigInt"

describe("BigInt Utils", () => {
    test("encode BigInt Big-Endian", () => {
        const result = encodeBigIntBE(0x1234567890abcdefn)
        expect(result.toString("hex")).toBe("1234567890abcdef")
    })

    test("encode BigInt Little-Endian", () => {
        const result = encodeBigIntLE(0x1234567890abcdefn)
        expect(result.toString("hex")).toBe("efcdab9078563412")
    })

    test("decode BigInt Big-Endian", () => {
        const result = encodeBigIntBE(0x1234567890abcdefn)
        expect(decodeBigIntBE(result)).toBe(0x1234567890abcdefn)
    })

    test("decode BigInt Little-Endian", () => {
        const result = encodeBigIntLE(0x1234567890abcdefn)
        expect(decodeBigIntLE(result)).toBe(0x1234567890abcdefn)
    })
})
