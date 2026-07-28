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

    private readonly currentLine = Buffer.allocUnsafe(MAX_PREAMBLE_LINE_LENGTH)
    private currentLineLength = 0
    private carriageReturn = -1
    private preambleLines = 0
    private complete = false

    constructor(options: IdentificationParserOptions) {
        this.allowPreamble = options.allowPreamble
    }

    push(chunk: Buffer): IdentificationParseResult {
        if (this.complete) {
            throw new Error("SSH identification has already been parsed")
        }

        const preamble: Buffer[] = []
        let offset = 0

        while (offset < chunk.length) {
            const newline = chunk.indexOf(0x0a, offset)
            const end = newline === -1 ? chunk.length : newline + 1
            this.append(chunk.subarray(offset, end), newline !== -1)
            offset = end
            if (newline === -1) {
                this.validatePendingLine()
                return { preamble, remainder: Buffer.alloc(0) }
            }

            const line = this.consumeLine()

            if (line.subarray(0, SSH_PREFIX.length).equals(SSH_PREFIX)) {
                if (line.length > MAX_IDENTIFICATION_LENGTH) {
                    throw new Error(
                        `SSH identification must not exceed ${MAX_IDENTIFICATION_LENGTH} bytes`,
                    )
                }

                const version = ProtocolVersionExchange.parse(line)
                const remainder = Buffer.from(chunk.subarray(offset))
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

        this.validatePendingLine()
        return { preamble, remainder: Buffer.alloc(0) }
    }

    private append(data: Buffer, completeLine: boolean): void {
        const nextLength = this.currentLineLength + data.length
        const isIdentification = this.startsWithIdentificationPrefix(data)
        const maximum = isIdentification ? MAX_IDENTIFICATION_LENGTH : MAX_PREAMBLE_LINE_LENGTH
        if (nextLength > maximum || (!completeLine && nextLength >= maximum)) {
            if (completeLine && isIdentification) {
                throw new Error(
                    `SSH identification must not exceed ${MAX_IDENTIFICATION_LENGTH} bytes`,
                )
            }
            if (completeLine) {
                throw new Error(
                    `SSH preamble line must not exceed ${MAX_PREAMBLE_LINE_LENGTH} bytes`,
                )
            }
            throw new Error(`SSH identification header line exceeds ${maximum} bytes`)
        }

        const carriageReturn = data.indexOf(0x0d)
        if (this.carriageReturn === -1 && carriageReturn !== -1) {
            this.carriageReturn = this.currentLineLength + carriageReturn
        }
        data.copy(this.currentLine, this.currentLineLength)
        this.currentLineLength = nextLength
    }

    private startsWithIdentificationPrefix(data: Buffer): boolean {
        if (this.currentLineLength + data.length < SSH_PREFIX.length) return false
        for (let index = 0; index < SSH_PREFIX.length; index++) {
            const value =
                index < this.currentLineLength
                    ? this.currentLine[index]
                    : data[index - this.currentLineLength]
            if (value !== SSH_PREFIX[index]) return false
        }
        return true
    }

    private consumeLine(): Buffer {
        const line = Buffer.from(this.currentLine.subarray(0, this.currentLineLength))
        this.currentLineLength = 0
        this.carriageReturn = -1
        return line
    }

    private validatePendingLine(): void {
        if (this.carriageReturn !== -1 && this.carriageReturn !== this.currentLineLength - 1) {
            throw new Error("Invalid SSH identification header: CR must be followed by LF")
        }
    }
}
