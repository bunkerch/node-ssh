import { defaultProtocolVersionExchange } from "./constants.js"
import { encodeSSHUTF8 } from "./utils/SSHText.js"

const SOFTWARE_VERSION_PATTERN = /^[!-,.-~]+$/

export const MAX_IDENTIFICATION_LENGTH = 255

export default class ProtocolVersionExchange {
    readonly protocol_version: string
    readonly protocol_software: string
    readonly comments: string | undefined
    constructor(
        protocol_version: string,
        protocol_software: string,
        comments?: string | undefined,
    ) {
        if (protocol_version !== "2.0" && protocol_version !== "1.99") {
            throw new Error(`Unsupported SSH protocol version: ${protocol_version}`)
        }
        if (!SOFTWARE_VERSION_PATTERN.test(protocol_software)) {
            throw new Error(
                "SSH software version must be printable US-ASCII without whitespace or '-'",
            )
        }
        if (comments !== undefined && (comments.length === 0 || /[\0\r\n]/u.test(comments))) {
            throw new Error(
                "SSH identification comments must not be empty or contain NUL, CR, or LF",
            )
        }
        if (comments !== undefined) encodeSSHUTF8(comments, "SSH identification comments")

        this.protocol_version = protocol_version
        this.protocol_software = protocol_software
        this.comments = comments
        Object.defineProperties(this, {
            protocol_version: { configurable: false, writable: false },
            protocol_software: { configurable: false, writable: false },
            comments: { configurable: false, writable: false },
        })

        if (Buffer.byteLength(this.toString(), "utf8") > MAX_IDENTIFICATION_LENGTH) {
            throw new Error(`SSH identification must not exceed ${MAX_IDENTIFICATION_LENGTH} bytes`)
        }
    }

    static parse(raw: string | Buffer): ProtocolVersionExchange {
        const encoded = Buffer.isBuffer(raw) ? raw : encodeSSHUTF8(raw, "SSH identification")
        if (encoded.length > MAX_IDENTIFICATION_LENGTH) {
            throw new Error(`SSH identification must not exceed ${MAX_IDENTIFICATION_LENGTH} bytes`)
        }
        if (encoded.includes(0)) {
            throw new Error("SSH identification must not contain NUL")
        }

        let body: Buffer
        if (encoded.subarray(-2).equals(Buffer.from("\r\n"))) {
            body = encoded.subarray(0, -2)
        } else if (encoded.subarray(-1).equals(Buffer.from("\n"))) {
            // RFC 4253 section 5 permits accepting LF-only identification for
            // compatibility with older SSH implementations.
            body = encoded.subarray(0, -1)
        } else {
            throw new Error("SSH identification must end with CRLF or LF")
        }

        const text = body.toString("utf8")
        if (!Buffer.from(text, "utf8").equals(body)) {
            throw new Error("SSH identification is not valid UTF-8")
        }
        const match = /^SSH-(2\.0|1\.99)-([^ ]+)(?: (.+))?$/u.exec(text)
        if (!match) {
            throw new Error("Invalid SSH identification")
        }

        const [, protocol_version, protocol_software, comments] = match

        return new ProtocolVersionExchange(protocol_version, protocol_software, comments)
    }

    /** Builds an SSH 2.0 identification from a software identifier and optional comment. */
    static fromIdent(ident: string | Buffer): ProtocolVersionExchange {
        const suffix = Buffer.isBuffer(ident)
            ? Buffer.from(ident)
            : encodeSSHUTF8(ident, "SSH identification suffix")
        return ProtocolVersionExchange.parse(
            Buffer.concat([Buffer.from("SSH-2.0-"), suffix, Buffer.from("\r\n")]),
        )
    }

    static readonly defaultValue = ProtocolVersionExchange.parse(defaultProtocolVersionExchange)

    toString(): string {
        return `SSH-${this.protocol_version}-${this.protocol_software}${this.comments ? ` ${this.comments}` : ""}\r\n`
    }
}

/** Copy a possibly subclassed configuration into the validated base representation. */
export function copyProtocolVersionExchange(
    value: ProtocolVersionExchange,
): ProtocolVersionExchange {
    return new ProtocolVersionExchange(
        value.protocol_version,
        value.protocol_software,
        value.comments,
    )
}
