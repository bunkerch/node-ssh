import assert from "node:assert"

import { PacketNameToType } from "../constants.js"
import { normalizeGSSAPIToken } from "../GSSAPI.js"
import type Packet from "../packet.js"
import { serializeBinaryBoolean } from "../utils/BinaryBoolean.js"
import {
    readNextBinaryBoolean,
    readNextBuffer,
    readNextUint32,
    readNextUint8,
    serializeBuffer,
    serializeUint32,
    serializeUint8,
} from "../utils/Buffer.js"
import { parseBufferToMpintBuffer, serializeMpintBufferToBuffer } from "../utils/mpint.js"
import {
    decodeSSHLanguageTag,
    decodeSSHUTF8,
    encodeSSHLanguageTag,
    encodeSSHUTF8,
} from "../utils/SSHText.js"
import type { ExchangeValueEncoding } from "../algorithms/kex/key-exchange.js"

export class KexGSSAPIInit implements Packet {
    static type = PacketNameToType.SSH_MSG_KEXDH_INIT
    readonly token: Buffer
    readonly publicKey: Buffer
    readonly encoding: ExchangeValueEncoding

    constructor(token: Buffer, publicKey: Buffer, encoding: ExchangeValueEncoding) {
        this.token = normalizeGSSAPIToken(token)
        this.publicKey = normalizeExchangeValue(publicKey, encoding)
        this.encoding = encoding
    }

    serialize(): Buffer {
        return Buffer.concat([
            serializeUint8(KexGSSAPIInit.type),
            serializeBuffer(this.token),
            serializeBuffer(encodeExchangeValue(this.publicKey, this.encoding)),
        ])
    }

    static parse(raw: Buffer, encoding: ExchangeValueEncoding): KexGSSAPIInit {
        let type: number
        let token: Buffer
        let publicKey: Buffer
        ;[type, raw] = readNextUint8(raw)
        assert(type === KexGSSAPIInit.type)
        ;[token, raw] = readNextBuffer(raw)
        ;[publicKey, raw] = readNextBuffer(raw)
        assert(raw.length === 0, "Unexpected GSS-API key-exchange init data")
        if (encoding === "mpint") parseBufferToMpintBuffer(publicKey)
        return new KexGSSAPIInit(token, publicKey, encoding)
    }
}

export class KexGSSAPIContinue implements Packet {
    static type = PacketNameToType.SSH_MSG_KEXDH_REPLY
    readonly token: Buffer

    constructor(token: Buffer) {
        this.token = normalizeGSSAPIToken(token)
    }

    serialize(): Buffer {
        return Buffer.concat([serializeUint8(KexGSSAPIContinue.type), serializeBuffer(this.token)])
    }

    static parse(raw: Buffer): KexGSSAPIContinue {
        let type: number
        let token: Buffer
        ;[type, raw] = readNextUint8(raw)
        assert(type === KexGSSAPIContinue.type)
        ;[token, raw] = readNextBuffer(raw)
        assert(raw.length === 0, "Unexpected GSS-API key-exchange continuation data")
        return new KexGSSAPIContinue(token)
    }
}

export class KexGSSAPIComplete implements Packet {
    static type = PacketNameToType.SSH_MSG_KEX_DH_GEX_INIT
    readonly publicKey: Buffer
    readonly mic: Buffer
    readonly token?: Buffer
    readonly encoding: ExchangeValueEncoding

    constructor(
        publicKey: Buffer,
        mic: Buffer,
        token: Buffer | undefined,
        encoding: ExchangeValueEncoding,
    ) {
        this.publicKey = normalizeExchangeValue(publicKey, encoding)
        this.mic = normalizeGSSAPIToken(mic, "GSS-API key-exchange MIC")
        this.token =
            token === undefined
                ? undefined
                : normalizeGSSAPIToken(token, "GSS-API final context token")
        this.encoding = encoding
    }

    serialize(): Buffer {
        return Buffer.concat([
            serializeUint8(KexGSSAPIComplete.type),
            serializeBuffer(encodeExchangeValue(this.publicKey, this.encoding)),
            serializeBuffer(this.mic),
            serializeBinaryBoolean(this.token !== undefined),
            ...(this.token === undefined ? [] : [serializeBuffer(this.token)]),
        ])
    }

    static parse(raw: Buffer, encoding: ExchangeValueEncoding): KexGSSAPIComplete {
        let type: number
        let publicKey: Buffer
        let mic: Buffer
        let hasToken: boolean
        ;[type, raw] = readNextUint8(raw)
        assert(type === KexGSSAPIComplete.type)
        ;[publicKey, raw] = readNextBuffer(raw)
        ;[mic, raw] = readNextBuffer(raw)
        ;[hasToken, raw] = readNextBinaryBoolean(raw)
        let token: Buffer | undefined
        if (hasToken) [token, raw] = readNextBuffer(raw)
        assert(raw.length === 0, "Unexpected GSS-API key-exchange completion data")
        if (encoding === "mpint") parseBufferToMpintBuffer(publicKey)
        return new KexGSSAPIComplete(publicKey, mic, token, encoding)
    }
}

export class KexGSSAPIHostKey implements Packet {
    static type = PacketNameToType.SSH_MSG_KEX_DH_GEX_REPLY
    readonly hostKey: Buffer

    constructor(hostKey: Buffer) {
        if (!Buffer.isBuffer(hostKey) || hostKey.length === 0) {
            throw new TypeError("GSS-API server host key must be a non-empty buffer")
        }
        this.hostKey = Buffer.from(hostKey)
    }

    serialize(): Buffer {
        return Buffer.concat([serializeUint8(KexGSSAPIHostKey.type), serializeBuffer(this.hostKey)])
    }

    static parse(raw: Buffer): KexGSSAPIHostKey {
        let type: number
        let hostKey: Buffer
        ;[type, raw] = readNextUint8(raw)
        assert(type === KexGSSAPIHostKey.type)
        ;[hostKey, raw] = readNextBuffer(raw)
        assert(raw.length === 0, "Unexpected GSS-API host-key data")
        return new KexGSSAPIHostKey(hostKey)
    }
}

export interface KexGSSAPIErrorData {
    majorStatus: number
    minorStatus: number
    message: string
    languageTag: string
}

export class KexGSSAPIError implements Packet {
    static type = PacketNameToType.SSH_MSG_KEX_DH_GEX_REQUEST
    readonly data: Readonly<KexGSSAPIErrorData>

    constructor(data: KexGSSAPIErrorData) {
        assertUint32(data.majorStatus, "GSS-API major status")
        assertUint32(data.minorStatus, "GSS-API minor status")
        encodeSSHUTF8(data.message, "GSS-API key-exchange error message")
        encodeSSHLanguageTag(data.languageTag)
        this.data = Object.freeze({ ...data })
    }

    serialize(): Buffer {
        return Buffer.concat([
            serializeUint8(KexGSSAPIError.type),
            serializeUint32(this.data.majorStatus),
            serializeUint32(this.data.minorStatus),
            serializeBuffer(encodeSSHUTF8(this.data.message, "GSS-API key-exchange error message")),
            serializeBuffer(encodeSSHLanguageTag(this.data.languageTag)),
        ])
    }

    static parse(raw: Buffer): KexGSSAPIError {
        let type: number
        let majorStatus: number
        let minorStatus: number
        let message: Buffer
        let languageTag: Buffer
        ;[type, raw] = readNextUint8(raw)
        assert(type === KexGSSAPIError.type)
        ;[majorStatus, raw] = readNextUint32(raw)
        ;[minorStatus, raw] = readNextUint32(raw)
        ;[message, raw] = readNextBuffer(raw)
        ;[languageTag, raw] = readNextBuffer(raw)
        assert(raw.length === 0, "Unexpected GSS-API key-exchange error data")
        return new KexGSSAPIError({
            majorStatus,
            minorStatus,
            message: decodeSSHUTF8(message, "GSS-API key-exchange error message"),
            languageTag: decodeSSHLanguageTag(languageTag),
        })
    }
}

function normalizeExchangeValue(value: Buffer, encoding: ExchangeValueEncoding): Buffer {
    if (!Buffer.isBuffer(value)) throw new TypeError("GSS-API exchange value must be a buffer")
    if (encoding === "string") {
        if (value.length === 0) throw new TypeError("GSS-API exchange value must not be empty")
        return Buffer.from(value)
    }
    const canonical = serializeMpintBufferToBuffer(value)
    parseBufferToMpintBuffer(canonical)
    return canonical
}

function encodeExchangeValue(value: Buffer, encoding: ExchangeValueEncoding): Buffer {
    return encoding === "mpint" ? serializeMpintBufferToBuffer(value) : value
}

function assertUint32(value: number, name: string): void {
    if (!Number.isInteger(value) || value < 0 || value > 0xffff_ffff) {
        throw new RangeError(`${name} must be a uint32`)
    }
}
