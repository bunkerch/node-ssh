import { EventEmitter } from "node:events"
import { readNextUint32, serializeUint32 } from "../utils/Buffer.js"

export enum TunnelMode {
    PointToPoint = 1,
    Ethernet = 2,
}

export enum TunnelAddressFamily {
    IPv4 = 2,
    IPv6 = 24,
}

export const AUTOMATIC_TUNNEL_UNIT = 0x7fff_ffff

export interface TunnelIPPacket {
    readonly family: TunnelAddressFamily.IPv4 | TunnelAddressFamily.IPv6
    readonly data: Buffer
}

export interface TunnelEvents {
    packet: [packet: Readonly<TunnelIPPacket>]
    frame: [frame: Buffer]
}

export function validateTunnelMode(mode: number): asserts mode is TunnelMode {
    if (mode !== TunnelMode.PointToPoint && mode !== TunnelMode.Ethernet) {
        throw new RangeError("SSH tunnel mode must be PointToPoint or Ethernet")
    }
}

export function validateTunnelUnit(unit: number): void {
    if (!Number.isInteger(unit) || unit < 0 || unit > AUTOMATIC_TUNNEL_UNIT) {
        throw new RangeError("SSH tunnel unit must be between 0 and 0x7fffffff")
    }
}

export function encodeTunnelOpen(mode: TunnelMode, unit: number): Buffer {
    validateTunnelMode(mode)
    validateTunnelUnit(unit)
    return Buffer.concat([serializeUint32(mode), serializeUint32(unit)])
}

export function decodeTunnelOpen(raw: Buffer): { mode: TunnelMode; unit: number } {
    const [mode, afterMode] = readNextUint32(raw)
    const [unit, remaining] = readNextUint32(afterMode)
    if (remaining.length !== 0) throw new Error("SSH tunnel open has trailing data")
    validateTunnelMode(mode)
    validateTunnelUnit(unit)
    return { mode, unit }
}

export function encodeTunnelPacket(mode: TunnelMode, payload: Buffer, family?: number): Buffer {
    if (!Buffer.isBuffer(payload)) throw new TypeError("SSH tunnel payload must be a buffer")
    validateTunnelMode(mode)
    if (mode === TunnelMode.Ethernet) {
        if (family !== undefined)
            throw new TypeError("Ethernet tunnel frames have no address family")
        return Buffer.concat([serializeUint32(payload.length), payload])
    }
    if (family !== TunnelAddressFamily.IPv4 && family !== TunnelAddressFamily.IPv6) {
        throw new RangeError("SSH point-to-point packets require an IPv4 or IPv6 address family")
    }
    validateIPPacket(family, payload)
    return Buffer.concat([serializeUint32(payload.length + 4), serializeUint32(family), payload])
}

export function decodeTunnelPacket(
    mode: TunnelMode,
    raw: Buffer,
): { packet?: Readonly<TunnelIPPacket>; frame?: Buffer } {
    validateTunnelMode(mode)
    const [length, payload] = readNextUint32(raw)
    if (length !== payload.length)
        throw new Error("SSH tunnel packet length does not match its data")
    if (mode === TunnelMode.Ethernet) return { frame: Buffer.from(payload) }
    if (length < 4)
        throw new Error("SSH point-to-point tunnel packet is missing its address family")
    const [family, data] = readNextUint32(payload)
    if (family !== TunnelAddressFamily.IPv4 && family !== TunnelAddressFamily.IPv6) {
        throw new Error(`Unsupported SSH tunnel address family ${family}`)
    }
    validateIPPacket(family, data)
    return { packet: Object.freeze({ family, data: Buffer.from(data) }) }
}

function validateIPPacket(family: TunnelAddressFamily, data: Buffer): void {
    const expectedVersion = family === TunnelAddressFamily.IPv4 ? 4 : 6
    const minimumLength = family === TunnelAddressFamily.IPv4 ? 20 : 40
    if (data.length < minimumLength || data[0] >>> 4 !== expectedVersion) {
        throw new Error(`Invalid IPv${expectedVersion} tunnel packet`)
    }
}

export function emitTunnelPayload(
    events: EventEmitter<TunnelEvents>,
    mode: TunnelMode,
    data: Buffer,
): void {
    const decoded = decodeTunnelPacket(mode, data)
    if (decoded.packet) events.emit("packet", decoded.packet)
    else events.emit("frame", decoded.frame!)
}
