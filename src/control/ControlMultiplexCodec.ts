import {
    readNextBuffer,
    readNextUint32,
    serializeBuffer,
    serializeUint32,
} from "../utils/Buffer.js"
import { decodeSSHUTF8 } from "../utils/SSHText.js"

export const CONTROL_MULTIPLEX_VERSION = 4
export const CONTROL_MULTIPLEX_MAX_PACKET_SIZE = 256 * 1024
export const CONTROL_MULTIPLEX_STREAM_LOCAL_PORT = 0xfffffffe

export enum ControlMultiplexMessageType {
    Hello = 0x00000001,
    NewSession = 0x10000002,
    AliveCheck = 0x10000004,
    Terminate = 0x10000005,
    OpenForward = 0x10000006,
    CloseForward = 0x10000007,
    NewStdioForward = 0x10000008,
    StopListening = 0x10000009,
    Proxy = 0x1000000f,
    ExtensionInfo = 0x20000001,
    Ok = 0x80000001,
    PermissionDenied = 0x80000002,
    Failure = 0x80000003,
    Exit = 0x80000004,
    Alive = 0x80000005,
    SessionOpened = 0x80000006,
    RemotePort = 0x80000007,
    TtyAllocationFailed = 0x80000008,
    ProxyReady = 0x8000000f,
    ExtensionInfoReply = 0x90000001,
}

export enum ControlMultiplexForwardType {
    Local = 1,
    Remote = 2,
    Dynamic = 3,
}

export interface ControlMultiplexHello {
    readonly type: ControlMultiplexMessageType.Hello
    readonly version: number
    readonly extensions: ReadonlyMap<string, Buffer>
}

export interface ControlMultiplexRequestBase {
    readonly requestId: number
}

export interface ControlMultiplexSimpleRequest extends ControlMultiplexRequestBase {
    readonly type:
        | ControlMultiplexMessageType.AliveCheck
        | ControlMultiplexMessageType.Terminate
        | ControlMultiplexMessageType.StopListening
        | ControlMultiplexMessageType.Proxy
}

export interface ControlMultiplexSessionRequest extends ControlMultiplexRequestBase {
    readonly type: ControlMultiplexMessageType.NewSession
    readonly reserved: Buffer
    readonly wantTty: boolean
    readonly wantX11: boolean
    readonly wantAgent: boolean
    readonly subsystem: boolean
    readonly escapeCharacter: number
    readonly terminalType: string
    readonly command: string
    readonly environment: readonly string[]
}

export interface ControlMultiplexStdioForwardRequest extends ControlMultiplexRequestBase {
    readonly type: ControlMultiplexMessageType.NewStdioForward
    readonly reserved: Buffer
    readonly destinationHost: string
    readonly destinationPort: number
}

export interface ControlMultiplexForwardRequest extends ControlMultiplexRequestBase {
    readonly type:
        | ControlMultiplexMessageType.OpenForward
        | ControlMultiplexMessageType.CloseForward
    readonly forwardType: ControlMultiplexForwardType
    readonly listenHost: string
    readonly listenPort: number
    readonly destinationHost: string
    readonly destinationPort: number
}

export interface ControlMultiplexExtensionInfoRequest extends ControlMultiplexRequestBase {
    readonly type: ControlMultiplexMessageType.ExtensionInfo
    readonly name: string
}

export interface ControlMultiplexUnknownRequest extends ControlMultiplexRequestBase {
    readonly type: number
    readonly body: Buffer
}

export type ControlMultiplexRequest =
    | ControlMultiplexHello
    | ControlMultiplexSimpleRequest
    | ControlMultiplexSessionRequest
    | ControlMultiplexStdioForwardRequest
    | ControlMultiplexForwardRequest
    | ControlMultiplexExtensionInfoRequest
    | ControlMultiplexUnknownRequest

function requireEmpty(raw: Buffer): void {
    if (raw.length !== 0) throw new ControlMultiplexProtocolError("Trailing multiplex request data")
}

function readString(raw: Buffer, name: string): [string, Buffer] {
    let value: Buffer
    ;[value, raw] = readNextBuffer(raw)
    return [decodeSSHUTF8(value, `multiplex ${name}`), raw]
}

function readBoolean(raw: Buffer, name: string): [boolean, Buffer] {
    let value: number
    ;[value, raw] = readNextUint32(raw)
    if (value !== 0 && value !== 1) {
        throw new ControlMultiplexProtocolError(`Invalid multiplex ${name} boolean`)
    }
    return [value === 1, raw]
}

export function decodeControlMultiplexRequest(payload: Buffer): ControlMultiplexRequest {
    if (payload.length < 4)
        throw new ControlMultiplexProtocolError("Multiplex request is too short")
    let raw: Buffer = Buffer.from(payload)
    const [type, remainingAfterType] = readNextUint32(raw)
    raw = remainingAfterType

    if (type === ControlMultiplexMessageType.Hello) {
        let version: number
        ;[version, raw] = readNextUint32(raw)
        const extensions = new Map<string, Buffer>()
        while (raw.length !== 0) {
            let name: string
            let value: Buffer
            ;[name, raw] = readString(raw, "extension name")
            ;[value, raw] = readNextBuffer(raw)
            if (extensions.has(name)) {
                throw new ControlMultiplexProtocolError(`Duplicate multiplex extension ${name}`)
            }
            extensions.set(name, Buffer.from(value))
        }
        return Object.freeze({ type, version, extensions })
    }

    const [requestId, remainingAfterRequestId] = readNextUint32(raw)
    raw = remainingAfterRequestId
    if (
        type === ControlMultiplexMessageType.AliveCheck ||
        type === ControlMultiplexMessageType.Terminate ||
        type === ControlMultiplexMessageType.StopListening ||
        type === ControlMultiplexMessageType.Proxy
    ) {
        requireEmpty(raw)
        return Object.freeze({ type, requestId })
    }
    if (type === ControlMultiplexMessageType.NewSession) {
        let reserved: Buffer
        let wantTty: boolean
        let wantX11: boolean
        let wantAgent: boolean
        let subsystem: boolean
        let escapeCharacter: number
        let terminalType: string
        let command: string
        ;[reserved, raw] = readNextBuffer(raw)
        ;[wantTty, raw] = readBoolean(raw, "want TTY")
        ;[wantX11, raw] = readBoolean(raw, "want X11")
        ;[wantAgent, raw] = readBoolean(raw, "want agent")
        ;[subsystem, raw] = readBoolean(raw, "subsystem")
        ;[escapeCharacter, raw] = readNextUint32(raw)
        ;[terminalType, raw] = readString(raw, "terminal type")
        ;[command, raw] = readString(raw, "command")
        const environment: string[] = []
        while (raw.length !== 0) {
            let value: string
            ;[value, raw] = readString(raw, "environment")
            if (environment.length >= 4096) {
                throw new ControlMultiplexProtocolError("Too many multiplex environment entries")
            }
            environment.push(value)
        }
        return Object.freeze({
            type,
            requestId,
            reserved: Buffer.from(reserved),
            wantTty,
            wantX11,
            wantAgent,
            subsystem,
            escapeCharacter,
            terminalType,
            command,
            environment: Object.freeze(environment),
        })
    }
    if (type === ControlMultiplexMessageType.NewStdioForward) {
        let reserved: Buffer
        let destinationHost: string
        let destinationPort: number
        ;[reserved, raw] = readNextBuffer(raw)
        ;[destinationHost, raw] = readString(raw, "destination host")
        ;[destinationPort, raw] = readNextUint32(raw)
        requireEmpty(raw)
        return Object.freeze({
            type,
            requestId,
            reserved: Buffer.from(reserved),
            destinationHost,
            destinationPort,
        })
    }
    if (
        type === ControlMultiplexMessageType.OpenForward ||
        type === ControlMultiplexMessageType.CloseForward
    ) {
        let forwardType: number
        let listenHost: string
        let listenPort: number
        let destinationHost: string
        let destinationPort: number
        ;[forwardType, raw] = readNextUint32(raw)
        ;[listenHost, raw] = readString(raw, "listen host")
        ;[listenPort, raw] = readNextUint32(raw)
        ;[destinationHost, raw] = readString(raw, "destination host")
        ;[destinationPort, raw] = readNextUint32(raw)
        requireEmpty(raw)
        if (
            forwardType !== ControlMultiplexForwardType.Local &&
            forwardType !== ControlMultiplexForwardType.Remote &&
            forwardType !== ControlMultiplexForwardType.Dynamic
        ) {
            throw new ControlMultiplexProtocolError("Invalid multiplex forwarding type")
        }
        return Object.freeze({
            type,
            requestId,
            forwardType,
            listenHost,
            listenPort,
            destinationHost,
            destinationPort,
        })
    }
    if (type === ControlMultiplexMessageType.ExtensionInfo) {
        let name: string
        ;[name, raw] = readString(raw, "information name")
        requireEmpty(raw)
        return Object.freeze({ type, requestId, name })
    }
    return Object.freeze({ type, requestId, body: Buffer.from(raw) })
}

export function encodeControlMultiplexPayload(payload: Buffer): Buffer {
    if (payload.length < 4 || payload.length > CONTROL_MULTIPLEX_MAX_PACKET_SIZE) {
        throw new ControlMultiplexProtocolError("Invalid multiplex packet length")
    }
    return Buffer.concat([serializeUint32(payload.length), payload])
}

export function encodeControlMultiplexHello(): Buffer {
    return encodeControlMultiplexPayload(
        Buffer.concat([
            serializeUint32(ControlMultiplexMessageType.Hello),
            serializeUint32(CONTROL_MULTIPLEX_VERSION),
        ]),
    )
}

export function encodeControlMultiplexReply(
    type: ControlMultiplexMessageType,
    requestId: number,
    value?: number | string,
): Buffer {
    const fields = [serializeUint32(type), serializeUint32(requestId)]
    if (typeof value === "number") fields.push(serializeUint32(value))
    else if (typeof value === "string") fields.push(serializeBuffer(Buffer.from(value, "utf8")))
    return encodeControlMultiplexPayload(Buffer.concat(fields))
}

export class ControlMultiplexDecoder {
    private buffered: Buffer = Buffer.alloc(0)

    push(chunk: Buffer): readonly ControlMultiplexRequest[] {
        if (!Buffer.isBuffer(chunk)) throw new TypeError("Multiplex input must be a Buffer")
        this.buffered = Buffer.concat([this.buffered, chunk])
        const requests: ControlMultiplexRequest[] = []
        while (this.buffered.length >= 4) {
            const length = this.buffered.readUInt32BE(0)
            if (length < 4 || length > CONTROL_MULTIPLEX_MAX_PACKET_SIZE) {
                throw new ControlMultiplexProtocolError("Invalid multiplex packet length")
            }
            if (this.buffered.length < length + 4) break
            const payload = this.buffered.subarray(4, length + 4)
            this.buffered = this.buffered.subarray(length + 4)
            requests.push(decodeControlMultiplexRequest(payload))
        }
        if (this.buffered.length > CONTROL_MULTIPLEX_MAX_PACKET_SIZE + 4) {
            throw new ControlMultiplexProtocolError("Multiplex packet exceeds buffering limit")
        }
        return requests
    }
}

export class ControlMultiplexProtocolError extends Error {
    override name = "ControlMultiplexProtocolError"
}
