import { BinaryPacketDecoder, BinaryPacketEncoder } from "../../src/BinaryPacket.js"
import { SSHZlibCompressor, SSHZlibDecompressor } from "../../src/algorithms/compression/zlib.js"

const payloads = [
    Buffer.from("first packet payload".repeat(4)),
    Buffer.from("first packet payload".repeat(4)),
    Buffer.from("completely different"),
]

const fixedCompressedPayloads = [
    Buffer.from("789c4acb2c2a2e5128484cce4e05519539f989296914880104", "hex"),
    Buffer.from("10b5c50002", "hex"),
    Buffer.from("28393fb72027b52435a7522125332d2db52835af0420", "hex"),
]

describe("RFC 4253 zlib compression", () => {
    test("matches independently generated stateful partial-flush vectors", () => {
        const compressor = new SSHZlibCompressor()
        const decompressor = new SSHZlibDecompressor(35_000)

        for (let index = 0; index < payloads.length; index++) {
            expect(compressor.compress(payloads[index])).toEqual(fixedCompressedPayloads[index])
            expect(decompressor.decompress(fixedCompressedPayloads[index])).toEqual(payloads[index])
        }
    })

    test("compresses only packet payloads and preserves state across packet boundaries", () => {
        const encoder = new BinaryPacketEncoder({ randomBytes: (size) => Buffer.alloc(size, 0xa5) })
        encoder.setCompression(new SSHZlibCompressor())
        const encoded = payloads.map((payload) => encoder.encode(payload).data)

        for (let index = 0; index < encoded.length; index++) {
            const packetLength = encoded[index].readUInt32BE(0)
            const paddingLength = encoded[index][4]
            expect(encoded[index].subarray(5, 4 + packetLength - paddingLength)).toEqual(
                fixedCompressedPayloads[index],
            )
        }

        const decoder = new BinaryPacketDecoder()
        decoder.setCompression(new SSHZlibDecompressor(35_000))
        decoder.push(Buffer.concat(encoded))
        for (const payload of payloads) expect(decoder.read()?.payload).toEqual(payload)
        expect(decoder.read()).toBeUndefined()
    })

    test("rejects malformed and excessively expanded streams", () => {
        expect(() => new SSHZlibDecompressor(35_000).decompress(Buffer.from("not-zlib"))).toThrow(
            "decompression failed",
        )

        const compressed = new SSHZlibCompressor().compress(Buffer.alloc(1_000, 0x41))
        expect(() => new SSHZlibDecompressor(100).decompress(compressed)).toThrow(
            "exceeds maximum 100",
        )
    })
})
