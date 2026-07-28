import IdentificationParser, {
    MAX_PREAMBLE_LINE_LENGTH,
    MAX_PREAMBLE_LINES,
} from "../../src/IdentificationParser.js"

describe("IdentificationParser", () => {
    test("handles every fragmentation boundary and preserves following binary data", () => {
        const identification = Buffer.from("SSH-2.0-test_server comment\r\n")
        const binary = Buffer.from([0x00, 0xff, 0x14, 0x00, 0x0a])
        const wire = Buffer.concat([identification, binary])

        for (let split = 0; split <= wire.length; split++) {
            const parser = new IdentificationParser({ allowPreamble: true })
            const first = parser.push(wire.subarray(0, split))
            const result = first.version ? first : parser.push(wire.subarray(split))
            const bytesNotYetFed = first.version ? wire.subarray(split) : Buffer.alloc(0)

            expect(result.version?.protocol_software).toBe("test_server")
            expect(result.identification).toEqual(identification)
            expect(Buffer.concat([result.remainder, bytesNotYetFed])).toEqual(binary)
        }
    })

    test("returns server preamble lines as soon as they are complete", () => {
        const parser = new IdentificationParser({ allowPreamble: true })

        expect(parser.push(Buffer.from("maintenance soon\r\npartial"))).toEqual({
            preamble: [Buffer.from("maintenance soon\r\n")],
            remainder: Buffer.alloc(0),
        })
        const result = parser.push(Buffer.from(" line\nSSH-2.0-server\r\npacket"))

        expect(result.preamble).toEqual([Buffer.from("partial line\n")])
        expect(result.version?.protocol_software).toBe("server")
        expect(result.remainder).toEqual(Buffer.from("packet"))
    })

    test("owns fragmented input and returned identification bytes", () => {
        const parser = new IdentificationParser({ allowPreamble: true })
        const first = Buffer.from("maintenance")
        parser.push(first)
        first.fill(0x78)

        const final = Buffer.from(" window\r\nSSH-2.0-owned\r\npacket")
        const result = parser.push(final)
        final.fill(0x79)

        expect(result.preamble).toEqual([Buffer.from("maintenance window\r\n")])
        expect(result.identification).toEqual(Buffer.from("SSH-2.0-owned\r\n"))
        expect(result.remainder).toEqual(Buffer.from("packet"))
    })

    test("parses a bounded preamble fragmented one byte at a time", () => {
        const parser = new IdentificationParser({ allowPreamble: true })
        const line = Buffer.concat([
            Buffer.alloc(MAX_PREAMBLE_LINE_LENGTH - 2, 0x61),
            Buffer.from("\r\n"),
        ])
        const wire = Buffer.concat([
            ...Array.from({ length: 64 }, () => line),
            Buffer.from("SSH-2.0-fragmented_server\r\n"),
        ])
        let preambleLines = 0
        let result

        for (const byte of wire) {
            result = parser.push(Buffer.from([byte]))
            preambleLines += result.preamble.length
        }

        expect(preambleLines).toBe(64)
        expect(result?.identification).toEqual(Buffer.from("SSH-2.0-fragmented_server\r\n"))
        expect(result?.remainder).toEqual(Buffer.alloc(0))
    }, 1_000)

    test("rejects preamble lines from an SSH client", () => {
        const parser = new IdentificationParser({ allowPreamble: false })

        expect(() => parser.push(Buffer.from("not permitted\r\nSSH-2.0-client\r\n"))).toThrow(
            "clients must not send lines",
        )
    })

    test("rejects an invalid line beginning with SSH-", () => {
        const parser = new IdentificationParser({ allowPreamble: true })

        expect(() => parser.push(Buffer.from("SSH-3.0-future\r\n"))).toThrow(
            "Invalid SSH identification",
        )
    })

    test("rejects a preamble with CR not immediately followed by LF", () => {
        const parser = new IdentificationParser({ allowPreamble: true })

        expect(() => parser.push(Buffer.from("bad\rline\n"))).toThrow("CR must be followed by LF")
    })

    test("bounds incomplete and excessive preambles", () => {
        const longLineParser = new IdentificationParser({ allowPreamble: true })
        expect(() => longLineParser.push(Buffer.alloc(MAX_PREAMBLE_LINE_LENGTH, 0x61))).toThrow(
            "exceeds",
        )

        const manyLinesParser = new IdentificationParser({ allowPreamble: true })
        const lines = Buffer.from("x\n".repeat(MAX_PREAMBLE_LINES + 1))
        expect(() => manyLinesParser.push(lines)).toThrow("1024 lines")
    })

    test("rejects data after completing identification parsing", () => {
        const parser = new IdentificationParser({ allowPreamble: true })
        parser.push(Buffer.from("SSH-2.0-server\r\n"))

        expect(() => parser.push(Buffer.alloc(0))).toThrow("already been parsed")
    })
})
