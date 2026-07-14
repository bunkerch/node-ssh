import ProtocolVersionExchange, {
    MAX_IDENTIFICATION_LENGTH,
} from "../../src/ProtocolVersionExchange.js"

describe("ProtocolVersionExchange", () => {
    test("parses and serializes an RFC 4253 identification", () => {
        const version = ProtocolVersionExchange.parse("SSH-2.0-OpenSSH_9.9 test server\r\n")

        expect(version.protocol_version).toBe("2.0")
        expect(version.protocol_software).toBe("OpenSSH_9.9")
        expect(version.comments).toBe("test server")
        expect(version.toString()).toBe("SSH-2.0-OpenSSH_9.9 test server\r\n")
    })

    test("accepts the SSH 1.99 compatibility identifier with LF", () => {
        const version = ProtocolVersionExchange.parse(Buffer.from("SSH-1.99-legacy_ssh\n"))

        expect(version.protocol_version).toBe("1.99")
        expect(version.protocol_software).toBe("legacy_ssh")
    })

    test("builds a custom SSH 2.0 identification from a fixed ident suffix", () => {
        const version = ProtocolVersionExchange.fromIdent(
            Buffer.from("modernssh_1.0 compliance-suite"),
        )
        expect(version).toEqual(
            new ProtocolVersionExchange("2.0", "modernssh_1.0", "compliance-suite"),
        )
        expect(version.toString()).toBe("SSH-2.0-modernssh_1.0 compliance-suite\r\n")
    })

    test("accepts an identification exactly 255 bytes long", () => {
        const prefix = "SSH-2.0-test "
        const comments = "a".repeat(MAX_IDENTIFICATION_LENGTH - prefix.length - 2)
        const raw = `${prefix}${comments}\r\n`

        expect(Buffer.byteLength(raw)).toBe(MAX_IDENTIFICATION_LENGTH)
        expect(ProtocolVersionExchange.parse(raw).comments).toBe(comments)
    })

    test.each([
        ["unsupported protocol", "SSH-1.5-test\r\n"],
        ["missing line ending", "SSH-2.0-test"],
        ["empty comments", "SSH-2.0-test \r\n"],
        ["hyphen in software version", "SSH-2.0-not-allowed\r\n"],
        ["whitespace in software version", "SSH-2.0-not\tallowed\r\n"],
        ["non-ASCII software version", "SSH-2.0-tést\r\n"],
        ["NUL", "SSH-2.0-test bad\0comment\r\n"],
        ["embedded CR", "SSH-2.0-test bad\rcomment\r\n"],
    ])("rejects %s", (_, raw) => {
        expect(() => ProtocolVersionExchange.parse(raw)).toThrow()
    })

    test("rejects an identification longer than 255 bytes", () => {
        expect(() => ProtocolVersionExchange.parse(`SSH-2.0-test ${"a".repeat(241)}\r\n`)).toThrow(
            "255 bytes",
        )
    })

    test("rejects unpaired surrogates in every local identification entry point", () => {
        expect(() => new ProtocolVersionExchange("2.0", "test", "\ud800")).toThrow(
            "SSH identification comments is not valid UTF-8 text",
        )
        expect(() => ProtocolVersionExchange.parse("SSH-2.0-test \ud800\r\n")).toThrow(
            "SSH identification is not valid UTF-8 text",
        )
        expect(() => ProtocolVersionExchange.fromIdent("test \ud800")).toThrow(
            "SSH identification suffix is not valid UTF-8 text",
        )
    })
})
