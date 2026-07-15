import assert from "node:assert"
import PublicKey from "./PublicKey.js"
import { decodeSSHUTF8, encodeSSHUTF8 } from "./SSHText.js"

const RFC4716_KEY_LABEL = ["SSH", "2 PUBLIC KEY"].join("")
export const RFC4716_BEGIN_MARKER = `---- BEGIN ${RFC4716_KEY_LABEL} ----`
export const RFC4716_END_MARKER = `---- END ${RFC4716_KEY_LABEL} ----`

const MAX_LINE_BYTES = 72
const MAX_HEADER_TAG_BYTES = 64
const MAX_HEADER_VALUE_BYTES = 1024

export interface RFC4716Header {
    readonly tag: string
    readonly value: string
}

export interface RFC4716PublicKeyFile {
    readonly publicKey: PublicKey
    readonly headers: readonly Readonly<RFC4716Header>[]
}

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

function validateHeader(tag: string, value: string): void {
    assert(/^[\x21-\x39\x3b-\x7e]+$/u.test(tag), "RFC 4716 header tag must be printable US-ASCII")
    assert(
        Buffer.byteLength(tag, "ascii") <= MAX_HEADER_TAG_BYTES,
        `RFC 4716 header tag exceeds ${MAX_HEADER_TAG_BYTES} bytes`,
    )
    encodeSSHUTF8(value, "RFC 4716 header value")
    assert(!/[\0\r\n]/u.test(value), "RFC 4716 header value contains a line ending or NUL")
    assert(
        Buffer.byteLength(value, "utf8") <= MAX_HEADER_VALUE_BYTES,
        `RFC 4716 header value exceeds ${MAX_HEADER_VALUE_BYTES} bytes`,
    )
}

function foldedHeaderLines(tag: string, value: string): string[] {
    validateHeader(tag, value)
    let remaining = `${tag}: ${value}`
    const lines: string[] = []
    while (Buffer.byteLength(remaining, "utf8") > MAX_LINE_BYTES || remaining.endsWith("\\")) {
        let bytes = 0
        let index = 0
        for (const character of remaining) {
            const characterBytes = Buffer.byteLength(character, "utf8")
            if (bytes + characterBytes > MAX_LINE_BYTES - 1) break
            bytes += characterBytes
            index += character.length
        }
        assert(index > 0, "RFC 4716 header cannot be folded within the line limit")
        lines.push(`${remaining.slice(0, index)}\\`)
        remaining = remaining.slice(index)
        if (remaining.length === 0) {
            lines.push("")
            return lines
        }
    }
    lines.push(remaining)
    return lines
}

export function parseRFC4716PublicKeyFile(data: string | Buffer): RFC4716PublicKeyFile {
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
    const headers: RFC4716Header[] = []
    while (index < content.length && content[index]!.includes(":")) {
        let physicalLine = content[index++]!
        let header = ""
        while (physicalLine.endsWith("\\")) {
            assert(index < content.length, "RFC 4716 header has a dangling continuation")
            header += physicalLine.slice(0, -1)
            physicalLine = content[index++]!
        }
        header += physicalLine

        const separator = header.indexOf(":")
        const tag = header.slice(0, separator)
        assert(header[separator + 1] === " ", "Invalid RFC 4716 header field")
        const value = header.slice(separator + 2)
        validateHeader(tag, value)
        headers.push(Object.freeze({ tag, value }))
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
    return Object.freeze({
        publicKey:
            comment === undefined ? publicKey : new PublicKey({ ...publicKey.data, comment }),
        headers: Object.freeze(headers),
    })
}

export function parseRFC4716PublicKey(data: string | Buffer): PublicKey {
    return parseRFC4716PublicKeyFile(data).publicKey
}

export function serializeRFC4716PublicKey(
    publicKey: PublicKey,
    headers?: readonly RFC4716Header[],
): string {
    if (!(publicKey instanceof PublicKey)) {
        throw new TypeError("RFC 4716 serialization requires an SSH public key")
    }
    const selectedHeaders =
        headers ??
        (publicKey.data.comment === undefined
            ? []
            : [{ tag: "Comment", value: `"${publicKey.data.comment}"` }])
    if (!Array.isArray(selectedHeaders)) {
        throw new TypeError("RFC 4716 headers must be an array")
    }

    const headerLines = selectedHeaders.flatMap((header) => {
        if (
            typeof header !== "object" ||
            header === null ||
            typeof header.tag !== "string" ||
            typeof header.value !== "string"
        ) {
            throw new TypeError("RFC 4716 headers require string tag and value fields")
        }
        return foldedHeaderLines(header.tag, header.value)
    })
    const base64 = publicKey.serialize().toString("base64")
    const bodyLines: string[] = []
    for (let offset = 0; offset < base64.length; offset += MAX_LINE_BYTES) {
        bodyLines.push(base64.slice(offset, offset + MAX_LINE_BYTES))
    }
    return [RFC4716_BEGIN_MARKER, ...headerLines, ...bodyLines, RFC4716_END_MARKER, ""].join("\n")
}
