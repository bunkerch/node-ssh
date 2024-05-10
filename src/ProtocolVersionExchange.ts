import { defaultProtocolVersionExchange } from "./constants.js"

export default class ProtocolVersionExchange {
    protocol_version: string
    protocol_software: string
    comments: string | undefined
    constructor(
        protocol_version: string,
        protocol_software: string,
        comments?: string | undefined,
    ) {
        this.protocol_version = protocol_version
        this.protocol_software = protocol_software
        this.comments = comments
    }

    static parse(raw: string): ProtocolVersionExchange {
        const match = raw.match(/^SSH-(\d+\.\d+)-([^ \n\r]+)( (.+))?\r?\n$/)
        if (raw.length > 255 || !match) {
            throw new Error("Invalid protocol version exchange message from server")
        }
        const protocol_version = match[1]
        const protocol_software = match[2]
        const comments = match[4]

        return new ProtocolVersionExchange(protocol_version, protocol_software, comments)
    }

    static defaultValue = ProtocolVersionExchange.parse(defaultProtocolVersionExchange)

    toString(): string {
        return `SSH-${this.protocol_version}-${this.protocol_software}${this.comments ? ` ${this.comments}` : ""}\r\n`
    }
}
