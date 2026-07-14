import assert from "node:assert"
import { PacketNameToType } from "../constants.js"
import { normalizeGSSAPIOID, normalizeGSSAPIToken } from "../GSSAPI.js"
import type Packet from "../packet.js"
import {
    readNextBuffer,
    readNextUint32,
    readNextUint8,
    serializeBuffer,
    serializeUint32,
    serializeUint8,
} from "../utils/Buffer.js"
import {
    decodeSSHLanguageTag,
    decodeSSHUTF8,
    encodeSSHLanguageTag,
    encodeSSHUTF8,
} from "../utils/SSHText.js"

export class UserAuthGSSAPIResponse implements Packet {
    static type = PacketNameToType.SSH_MSG_USERAUTH_PK_OK
    readonly oid: Buffer

    constructor(oid: Buffer) {
        this.oid = normalizeGSSAPIOID(oid)
    }

    serialize(): Buffer {
        return Buffer.concat([
            serializeUint8(UserAuthGSSAPIResponse.type),
            serializeBuffer(this.oid),
        ])
    }

    static parse(raw: Buffer): UserAuthGSSAPIResponse {
        let type: number
        let oid: Buffer
        ;[type, raw] = readNextUint8(raw)
        assert(type === UserAuthGSSAPIResponse.type)
        ;[oid, raw] = readNextBuffer(raw)
        assert(raw.length === 0, "Unexpected GSS-API response data")
        return new UserAuthGSSAPIResponse(oid)
    }
}

export class UserAuthGSSAPIToken implements Packet {
    static type = PacketNameToType.SSH_MSG_USERAUTH_INFO_RESPONSE
    readonly token: Buffer

    constructor(token: Buffer) {
        this.token = normalizeGSSAPIToken(token)
    }

    serialize(): Buffer {
        return Buffer.concat([
            serializeUint8(UserAuthGSSAPIToken.type),
            serializeBuffer(this.token),
        ])
    }

    static parse(raw: Buffer): UserAuthGSSAPIToken {
        let type: number
        let token: Buffer
        ;[type, raw] = readNextUint8(raw)
        assert(type === UserAuthGSSAPIToken.type)
        ;[token, raw] = readNextBuffer(raw)
        assert(raw.length === 0, "Unexpected GSS-API token data")
        return new UserAuthGSSAPIToken(token)
    }
}

export class UserAuthGSSAPIExchangeComplete implements Packet {
    static type = PacketNameToType.SSH_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE

    serialize(): Buffer {
        return serializeUint8(UserAuthGSSAPIExchangeComplete.type)
    }

    static parse(raw: Buffer): UserAuthGSSAPIExchangeComplete {
        let type: number
        ;[type, raw] = readNextUint8(raw)
        assert(type === UserAuthGSSAPIExchangeComplete.type)
        assert(raw.length === 0, "Unexpected GSS-API exchange-complete data")
        return new UserAuthGSSAPIExchangeComplete()
    }
}

export interface UserAuthGSSAPIErrorData {
    majorStatus: number
    minorStatus: number
    message: string
    languageTag: string
}

export class UserAuthGSSAPIError implements Packet {
    static type = PacketNameToType.SSH_MSG_USERAUTH_GSSAPI_ERROR
    readonly data: Readonly<UserAuthGSSAPIErrorData>

    constructor(data: UserAuthGSSAPIErrorData) {
        assertUint32(data.majorStatus, "GSS-API major status")
        assertUint32(data.minorStatus, "GSS-API minor status")
        encodeSSHUTF8(data.message, "GSS-API error message")
        encodeSSHLanguageTag(data.languageTag)
        this.data = Object.freeze({ ...data })
    }

    serialize(): Buffer {
        return Buffer.concat([
            serializeUint8(UserAuthGSSAPIError.type),
            serializeUint32(this.data.majorStatus),
            serializeUint32(this.data.minorStatus),
            serializeBuffer(encodeSSHUTF8(this.data.message, "GSS-API error message")),
            serializeBuffer(encodeSSHLanguageTag(this.data.languageTag)),
        ])
    }

    static parse(raw: Buffer): UserAuthGSSAPIError {
        let type: number
        let majorStatus: number
        let minorStatus: number
        let message: Buffer
        let languageTag: Buffer
        ;[type, raw] = readNextUint8(raw)
        assert(type === UserAuthGSSAPIError.type)
        ;[majorStatus, raw] = readNextUint32(raw)
        ;[minorStatus, raw] = readNextUint32(raw)
        ;[message, raw] = readNextBuffer(raw)
        ;[languageTag, raw] = readNextBuffer(raw)
        assert(raw.length === 0, "Unexpected GSS-API error data")
        return new UserAuthGSSAPIError({
            majorStatus,
            minorStatus,
            message: decodeSSHUTF8(message, "GSS-API error message"),
            languageTag: decodeSSHLanguageTag(languageTag),
        })
    }
}

export class UserAuthGSSAPIErrorToken implements Packet {
    static type = PacketNameToType.SSH_MSG_USERAUTH_GSSAPI_ERRTOK
    readonly token: Buffer

    constructor(token: Buffer) {
        this.token = normalizeGSSAPIToken(token, "GSS-API error token")
    }

    serialize(): Buffer {
        return Buffer.concat([
            serializeUint8(UserAuthGSSAPIErrorToken.type),
            serializeBuffer(this.token),
        ])
    }

    static parse(raw: Buffer): UserAuthGSSAPIErrorToken {
        let type: number
        let token: Buffer
        ;[type, raw] = readNextUint8(raw)
        assert(type === UserAuthGSSAPIErrorToken.type)
        ;[token, raw] = readNextBuffer(raw)
        assert(raw.length === 0, "Unexpected GSS-API error-token data")
        return new UserAuthGSSAPIErrorToken(token)
    }
}

export class UserAuthGSSAPIMIC implements Packet {
    static type = PacketNameToType.SSH_MSG_USERAUTH_GSSAPI_MIC
    readonly mic: Buffer

    constructor(mic: Buffer) {
        this.mic = normalizeGSSAPIToken(mic, "GSS-API MIC")
    }

    serialize(): Buffer {
        return Buffer.concat([serializeUint8(UserAuthGSSAPIMIC.type), serializeBuffer(this.mic)])
    }

    static parse(raw: Buffer): UserAuthGSSAPIMIC {
        let type: number
        let mic: Buffer
        ;[type, raw] = readNextUint8(raw)
        assert(type === UserAuthGSSAPIMIC.type)
        ;[mic, raw] = readNextBuffer(raw)
        assert(raw.length === 0, "Unexpected GSS-API MIC data")
        return new UserAuthGSSAPIMIC(mic)
    }
}

function assertUint32(value: number, name: string): void {
    if (!Number.isInteger(value) || value < 0 || value > 0xffff_ffff) {
        throw new RangeError(`${name} must be a uint32`)
    }
}
