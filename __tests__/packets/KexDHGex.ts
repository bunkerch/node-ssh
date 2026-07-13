import Packet from "../../src/packet.js"
import KexDHGexGroup from "../../src/packets/KexDHGexGroup.js"
import KexDHGexInit from "../../src/packets/KexDHGexInit.js"
import KexDHGexReply from "../../src/packets/KexDHGexReply.js"
import KexDHGexRequest from "../../src/packets/KexDHGexRequest.js"
import KexDHGexRequestOld from "../../src/packets/KexDHGexRequestOld.js"

describe("RFC 4419 group-exchange packets", () => {
    test("parses and serializes the fixed request frame", () => {
        const wire = Buffer.from("220000080000000c0000002000", "hex")
        const packet = Packet.parse(wire) as KexDHGexRequest
        expect(packet).toBeInstanceOf(KexDHGexRequest)
        expect(packet.data).toEqual({ min: 2048, preferred: 3072, max: 8192 })
        expect(packet.serialize()).toEqual(wire)
    })

    test("parses and serializes the fixed legacy request frame in its KEX namespace", () => {
        const wire = Buffer.from("1e00000c00", "hex")
        const packet = KexDHGexRequestOld.parse(wire)
        expect(packet.data).toEqual({ preferred: 3072 })
        expect(packet.serialize()).toEqual(wire)
    })

    test("parses and serializes the fixed group frame in its KEX-specific namespace", () => {
        const wire = Buffer.from("1f00000001170000000102", "hex")
        const packet = KexDHGexGroup.parse(wire)
        expect(packet.data).toEqual({ p: Buffer.from([23]), g: Buffer.from([2]) })
        expect(packet.serialize()).toEqual(wire)
    })

    test("parses and serializes the fixed init frame", () => {
        const wire = Buffer.from("20000000030080ff", "hex")
        const packet = Packet.parse(wire) as KexDHGexInit
        expect(packet).toBeInstanceOf(KexDHGexInit)
        expect(packet.data.e).toEqual(Buffer.from("0080ff", "hex"))
        expect(packet.serialize()).toEqual(wire)
    })

    test("parses and serializes the fixed reply frame", () => {
        const wire = Buffer.from("21000000030102030000000212340000000405060708", "hex")
        const packet = Packet.parse(wire) as KexDHGexReply
        expect(packet).toBeInstanceOf(KexDHGexReply)
        expect(packet.data).toEqual({
            K_S: Buffer.from("010203", "hex"),
            f: Buffer.from("1234", "hex"),
            H_sig: Buffer.from("05060708", "hex"),
        })
        expect(packet.serialize()).toEqual(wire)
    })

    test("rejects truncated and trailing fields", () => {
        expect(() => Packet.parse(Buffer.from("220000080000000c00", "hex"))).toThrow()
        expect(() => KexDHGexGroup.parse(Buffer.from("1f0000000117000000010200", "hex"))).toThrow()
        expect(() => Packet.parse(Buffer.from("2000000002ff", "hex"))).toThrow()
        expect(() =>
            Packet.parse(Buffer.from("2100000001010000000102000000010300", "hex")),
        ).toThrow()
    })
})
