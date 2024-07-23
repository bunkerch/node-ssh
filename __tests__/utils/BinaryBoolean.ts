import { parseBinaryBoolean, serializeBinaryBoolean } from "../../src/utils/BinaryBoolean.js"

describe("Utils", () => {
    describe("BinaryBoolean", () => {
        test("parseable", () => {
            expect(parseBinaryBoolean(Buffer.from([0]))).toBe(false)
            expect(parseBinaryBoolean(Buffer.from([1]))).toBe(true)
        })

        it("not parseable", () => {
            expect(() => parseBinaryBoolean(Buffer.from([2]))).toThrow()
            expect(() => parseBinaryBoolean(Buffer.from([0, 1]))).toThrow()
        })

        test("serializeable", () => {
            expect(serializeBinaryBoolean(false)).toEqual(Buffer.from([0]))
            expect(serializeBinaryBoolean(true)).toEqual(Buffer.from([1]))
        })

        test("not serializeable", () => {
            // eslint-disable-next-line @typescript-eslint/ban-ts-comment
            // @ts-expect-error
            expect(() => serializeBinaryBoolean(null)).toThrow()
        })
    })
})
