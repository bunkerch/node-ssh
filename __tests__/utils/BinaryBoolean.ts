import { parseBinaryBoolean, serializeBinaryBoolean } from "../../src/utils/BinaryBoolean"

describe("BinaryBoolean Utils", () => {
    test("Should be parseable", () => {
        expect(parseBinaryBoolean(Buffer.from([0]))).toBe(false)
        expect(parseBinaryBoolean(Buffer.from([1]))).toBe(true)
    })

    test("Should not be parseable", () => {
        expect(() => parseBinaryBoolean(Buffer.from([2]))).toThrow()
        expect(() => parseBinaryBoolean(Buffer.from([0, 1]))).toThrow()
    })

    test("Should serialize", () => {
        expect(serializeBinaryBoolean(false)).toEqual(Buffer.from([0]))
        expect(serializeBinaryBoolean(true)).toEqual(Buffer.from([1]))
    })

    test("Should not serialize", () => {
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        // @ts-expect-error
        expect(() => serializeBinaryBoolean(null)).toThrow()
    })
})
