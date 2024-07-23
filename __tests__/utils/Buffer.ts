import {
    readNextBuffer,
    readNextUint8,
    readNextUint32,
    readNextBinaryBoolean,
    serializeBuffer,
    serializeUint8,
    serializeUint32,
} from "../../src/utils/Buffer.js"

describe("Utils", () => {
    describe("Buffer", () => {
        describe("readNextBuffer", () => {
            it("should read the next buffer correctly", () => {
                let raw = Buffer.from([
                    0x00, 0x00, 0x00, 0x04, 0x61, 0x62, 0x63, 0x64, 0xde, 0xad, 0xbe, 0xef,
                ])

                let data: Buffer = Buffer.alloc(0)
                ;[data, raw] = readNextBuffer(raw)

                expect(data).toStrictEqual(Buffer.from([0x61, 0x62, 0x63, 0x64]))
                expect(raw).toStrictEqual(Buffer.from([0xde, 0xad, 0xbe, 0xef]))
            })

            it("should throw if buffer length is less than 4", () => {
                const buffer = Buffer.from([0x00, 0x00, 0x00])
                expect(() => {
                    readNextBuffer(buffer)
                }).toThrow()
            })

            it("should throw if buffer size is nonsense", () => {
                const buffer = Buffer.from([0xff, 0xff, 0xff, 0xff, 0x12, 0x34, 0x56, 0x78])

                expect(() => {
                    readNextBuffer(buffer)
                }).toThrow()
            })
        })
        describe("readNextUint8", () => {
            it("should read the next Uint8 correctly", () => {
                const buffer = Buffer.from([0x01, 0x02, 0x03])
                const [data, remaining] = readNextUint8(buffer)
                expect(data).toBe(0x01)
                expect(remaining).toStrictEqual(Buffer.from([0x02, 0x03]))
            })
            it("should throw an error if buffer length is less than 1", () => {
                const buffer = Buffer.from([])
                expect(() => {
                    readNextUint8(buffer)
                }).toThrow()
            })
        })
        describe("readNextUint32", () => {
            it("should read the next Uint32 correctly", () => {
                const buffer = Buffer.from([0x00, 0x00, 0x00, 0x01, 0x02, 0x03])
                const [data, remaining] = readNextUint32(buffer)
                expect(data).toBe(0x00000001)
                expect(remaining).toStrictEqual(Buffer.from([0x02, 0x03]))
            })
            it("should throw an error if buffer length is less than 4", () => {
                const buffer = Buffer.from([0x00, 0x00, 0x00])
                expect(() => {
                    readNextUint32(buffer)
                }).toThrow()
            })
        })
        describe("readNextBinaryBoolean", () => {
            it("should read the next BinaryBoolean correctly", () => {
                const buffer = Buffer.from([0x01, 0x02])
                const [data, remaining] = readNextBinaryBoolean(buffer)
                expect(data).toBe(true)
                expect(remaining).toStrictEqual(Buffer.from([0x02]))
            })
            it("should throw an error if buffer length is less than 1", () => {
                const buffer = Buffer.from([])
                expect(() => {
                    readNextBinaryBoolean(buffer)
                }).toThrow()
            })
        })
        describe("serializeBuffer", () => {
            it("should serialize the buffer correctly", () => {
                const buffer = Buffer.from([0x61, 0x62, 0x63, 0x64])
                const serialized = serializeBuffer(buffer)
                expect(serialized).toStrictEqual(
                    Buffer.from([0x00, 0x00, 0x00, 0x04, 0x61, 0x62, 0x63, 0x64]),
                )
            })
        })
        describe("serializeUint8", () => {
            it("should serialize the Uint8 correctly", () => {
                const serialized = serializeUint8(0x01)
                expect(serialized).toStrictEqual(Buffer.from([0x01]))
            })
        })
        describe("serializeUint32", () => {
            it("should serialize the Uint32 correctly", () => {
                const serialized = serializeUint32(0x00000001)
                expect(serialized).toStrictEqual(Buffer.from([0x00, 0x00, 0x00, 0x01]))
            })
        })
    })
})
