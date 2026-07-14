import { decodeBigIntBE } from "../../utils/BigInt.js"
import { KeyExchangeError } from "./key-exchange.js"

export function decodePositiveDHMPInt(value: Buffer, label: string): bigint {
    if (value.length === 0 || (value[0] & 0x80) !== 0) {
        throw new KeyExchangeError(`Diffie-Hellman ${label} must be a positive mpint`)
    }
    if (value.length > 1 && value[0] === 0 && (value[1] & 0x80) === 0) {
        throw new KeyExchangeError(`Diffie-Hellman ${label} is not canonically encoded`)
    }
    const decoded = decodeBigIntBE(value)
    if (decoded <= 0n) throw new KeyExchangeError(`Diffie-Hellman ${label} must be positive`)
    return decoded
}

export function unsignedDHBuffer(value: Buffer): Buffer {
    return value.length > 1 && value[0] === 0 ? value.subarray(1) : value
}

export function keyExchangeErrorMessage(error: unknown): string {
    return error instanceof Error ? error.message : String(error)
}
