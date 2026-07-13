import ProtocolVersionExchange, { MAX_IDENTIFICATION_LENGTH } from "./ProtocolVersionExchange.js"

export const MAX_PREAMBLE_LINE_LENGTH = 8192
export const MAX_PREAMBLE_LINES = 1024
const SSH_PREFIX = Buffer.from("SSH-")

export interface IdentificationParserOptions {
    allowPreamble: boolean
}

export interface IdentificationParseResult {
    preamble: Buffer[]
    version?: ProtocolVersionExchange
    identification?: Buffer
    remainder: Buffer
}

/** Incrementally parses the SSH identification exchange from a byte stream. */
export default class IdentificationParser {
    readonly allowPreamble: boolean

    private buffered = Buffer.alloc(0)
    private preambleLines = 0
    private complete = false

    constructor(options: IdentificationParserOptions) {
        this.allowPreamble = options.allowPreamble
    }

    push(chunk: Buffer): IdentificationParseResult {
        if (this.complete) {
            throw new Error("SSH identification has already been parsed")
        }

        this.buffered = Buffer.concat([this.buffered, chunk])
        const preamble: Buffer[] = []

        while (true) {
            const newline = this.buffered.indexOf(0x0a)
            if (newline === -1) {
                this.validatePendingLine()
                return { preamble, remainder: Buffer.alloc(0) }
            }

            const line = this.buffered.subarray(0, newline + 1)
            this.buffered = this.buffered.subarray(newline + 1)

            if (line.subarray(0, SSH_PREFIX.length).equals(SSH_PREFIX)) {
                if (line.length > MAX_IDENTIFICATION_LENGTH) {
                    throw new Error(
                        `SSH identification must not exceed ${MAX_IDENTIFICATION_LENGTH} bytes`,
                    )
                }

                const version = ProtocolVersionExchange.parse(line)
                const remainder = this.buffered
                this.buffered = Buffer.alloc(0)
                this.complete = true
                return { preamble, version, identification: line, remainder }
            }

            if (!this.allowPreamble) {
                throw new Error("SSH clients must not send lines before their identification")
            }
            const carriageReturn = line.indexOf(0x0d)
            if (carriageReturn !== -1 && carriageReturn !== line.length - 2) {
                throw new Error("Invalid SSH identification header: CR must be followed by LF")
            }
            if (line.length > MAX_PREAMBLE_LINE_LENGTH) {
                throw new Error(
                    `SSH preamble line must not exceed ${MAX_PREAMBLE_LINE_LENGTH} bytes`,
                )
            }
            if (++this.preambleLines > MAX_PREAMBLE_LINES) {
                throw new Error(`SSH preamble must not exceed ${MAX_PREAMBLE_LINES} lines`)
            }

            preamble.push(line)
        }
    }

    private validatePendingLine(): void {
        const carriageReturn = this.buffered.indexOf(0x0d)
        if (carriageReturn !== -1 && carriageReturn !== this.buffered.length - 1) {
            throw new Error("Invalid SSH identification header: CR must be followed by LF")
        }

        const isIdentification = this.buffered.subarray(0, SSH_PREFIX.length).equals(SSH_PREFIX)
        const maximum = isIdentification ? MAX_IDENTIFICATION_LENGTH : MAX_PREAMBLE_LINE_LENGTH
        if (this.buffered.length >= maximum) {
            throw new Error(`SSH identification header line exceeds ${maximum} bytes`)
        }
    }
}
