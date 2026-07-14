import assert from "node:assert"
import PublicKey from "./PublicKey.js"
import { decodeSSHUTF8, encodeSSHUTF8 } from "./SSHText.js"

const RFC4716_KEY_LABEL = ["SSH", "2 PUBLIC KEY"].join("")
export const RFC4716_BEGIN_MARKER = `---- BEGIN ${RFC4716_KEY_LABEL} ----`
export const RFC4716_END_MARKER = `---- END ${RFC4716_KEY_LABEL} ----`

const MAX_LINE_BYTES = 72
const MAX_HEADER_TAG_BYTES = 64
const MAX_HEADER_VALUE_BYTES = 1024

function decodeRFC4716Text(data: string | Buffer): string {
    if (Buffer.isBuffer(data)) return decodeSSHUTF8(data, "RFC 4716 public key file")
    encodeSSHUTF8(data, "RFC 4716 public key file")
    return data
}

function unquoteComment(value: string): string {
    if (value.length < 2) return value
    const quotationMark = value[0]
    return (quotationMark === '"' || quotationMark === "'") && value.at(-1) === quotationMark
        ? value.slice(1, -1)
        : value
}

export function parseRFC4716PublicKey(data: string | Buffer): PublicKey {
    const text = decodeRFC4716Text(data)
    const lines = text.split(/\r\n|\r|\n/u)
    if (lines.at(-1) === "") lines.pop()

    assert(lines[0] === RFC4716_BEGIN_MARKER, "Invalid RFC 4716 begin marker")
    assert(lines.at(-1) === RFC4716_END_MARKER, "Invalid RFC 4716 end marker")
    assert(lines.length >= 3, "RFC 4716 public key file has no body")

    for (const line of lines) {
        assert(
            Buffer.byteLength(line, "utf8") <= MAX_LINE_BYTES,
            `RFC 4716 line exceeds ${MAX_LINE_BYTES} bytes`,
        )
    }

    const content = lines.slice(1, -1)
    let index = 0
    let comment: string | undefined
    while (index < content.length && content[index]!.includes(":")) {
        let header = content[index++]!
        while (header.endsWith("\\")) {
            assert(index < content.length, "RFC 4716 header has a dangling continuation")
            header = header.slice(0, -1) + content[index++]!
        }

        const separator = header.indexOf(":")
        const tag = header.slice(0, separator)
        assert(
            /^[\x21-\x39\x3b-\x7e]+$/u.test(tag),
            "RFC 4716 header tag must be printable US-ASCII",
        )
        assert(
            Buffer.byteLength(tag, "ascii") <= MAX_HEADER_TAG_BYTES,
            `RFC 4716 header tag exceeds ${MAX_HEADER_TAG_BYTES} bytes`,
        )
        assert(header[separator + 1] === " ", "Invalid RFC 4716 header field")
        const value = header.slice(separator + 2)
        assert(
            Buffer.byteLength(value, "utf8") <= MAX_HEADER_VALUE_BYTES,
            `RFC 4716 header value exceeds ${MAX_HEADER_VALUE_BYTES} bytes`,
        )
        if (tag.toLowerCase() === "comment") comment = unquoteComment(value)
    }

    const bodyLines = content.slice(index)
    assert(bodyLines.length > 0, "RFC 4716 public key file has no body")
    assert(
        bodyLines.every((line) => line.length > 0),
        "RFC 4716 public key body has a blank line",
    )
    const base64 = bodyLines.join("")
    assert(/^[A-Za-z0-9+/]+={0,2}$/u.test(base64), "Invalid RFC 4716 public key base64")
    assert(base64.length % 4 === 0, "Invalid RFC 4716 public key base64 length")
    const decoded = Buffer.from(base64, "base64")
    assert(decoded.toString("base64") === base64, "Non-canonical RFC 4716 public key base64")

    const publicKey = PublicKey.parse(decoded)
    return comment === undefined ? publicKey : new PublicKey({ ...publicKey.data, comment })
}
