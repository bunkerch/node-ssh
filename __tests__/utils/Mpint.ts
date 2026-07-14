import { parseBufferToMpintBuffer, serializeMpintBufferToBuffer } from "../../src/utils/mpint.js"

describe("RFC 4251 mpint canonical encoding", () => {
    test.each([
        ["", ""],
        ["00", ""],
        ["000001", "01"],
        ["7f", "7f"],
        ["80", "0080"],
        ["0080", "0080"],
    ])("serializes %s as %s", (input, expected) => {
        expect(serializeMpintBufferToBuffer(Buffer.from(input, "hex"))).toEqual(
            Buffer.from(expected, "hex"),
        )
    })

    test.each(["", "01", "7f", "0080"])("accepts canonical positive mpint %s", (value) => {
        const raw = Buffer.from(value, "hex")
        expect(parseBufferToMpintBuffer(raw)).toEqual(raw)
    })

    test.each(["00", "0001", "000080", "80", "ff"])("rejects non-canonical mpint %s", (value) => {
        expect(() => parseBufferToMpintBuffer(Buffer.from(value, "hex"))).toThrow()
    })
})
