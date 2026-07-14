import assert from "node:assert"
import { createHash, createHmac } from "node:crypto"

import { decodeBigIntBE, encodeBigIntBE } from "./BigInt.js"

/**
 * Runs an operation with successive deterministic nonce candidates from RFC 6979 section 3.2.
 * Returning undefined rejects a candidate, as required when a signature produces a zero scalar.
 */
export function withRFC6979Nonce<T>(
    hashName: string,
    privateScalar: bigint,
    order: bigint,
    digest: Buffer,
    operation: (nonce: bigint) => T | undefined,
): T {
    assert(order > 2n, "RFC 6979 subgroup order must be greater than two")
    assert(privateScalar > 0n && privateScalar < order, "RFC 6979 private scalar is out of range")
    const orderBits = bitLength(order)
    const orderBytes = Math.ceil(orderBits / 8)
    const outputLength = createHash(hashName).digest().length
    const privateOctets = fixedWidth(privateScalar, orderBytes)
    const digestOctets = fixedWidth(bitsToInteger(digest, orderBits) % order, orderBytes)
    let key: Buffer = Buffer.alloc(outputLength)
    let value: Buffer = Buffer.alloc(outputLength, 1)

    const hmac = (...parts: readonly Buffer[]): Buffer => {
        const mac = createHmac(hashName, key)
        for (const part of parts) mac.update(part)
        return mac.digest()
    }
    const replaceKey = (next: Buffer): void => {
        key.fill(0)
        key = next
    }
    const replaceValue = (next: Buffer): void => {
        value.fill(0)
        value = next
    }

    try {
        replaceKey(hmac(value, Buffer.from([0]), privateOctets, digestOctets))
        replaceValue(hmac(value))
        replaceKey(hmac(value, Buffer.from([1]), privateOctets, digestOctets))
        replaceValue(hmac(value))

        while (true) {
            const chunks: Buffer[] = []
            let length = 0
            while (length < orderBytes) {
                replaceValue(hmac(value))
                const chunk = Buffer.from(value)
                chunks.push(chunk)
                length += chunk.length
            }
            const candidateBytes = Buffer.concat(chunks)
            const candidate = bitsToInteger(candidateBytes, orderBits)
            candidateBytes.fill(0)
            for (const chunk of chunks) chunk.fill(0)
            if (candidate > 0n && candidate < order) {
                const result = operation(candidate)
                if (result !== undefined) return result
            }
            replaceKey(hmac(value, Buffer.from([0])))
            replaceValue(hmac(value))
        }
    } finally {
        key.fill(0)
        value.fill(0)
        privateOctets.fill(0)
        digestOctets.fill(0)
    }
}

export function modularInverse(value: bigint, modulus: bigint): bigint {
    let oldR = ((value % modulus) + modulus) % modulus
    let remainder = modulus
    let oldCoefficient = 1n
    let coefficient = 0n
    while (remainder !== 0n) {
        const quotient = oldR / remainder
        ;[oldR, remainder] = [remainder, oldR - quotient * remainder]
        ;[oldCoefficient, coefficient] = [coefficient, oldCoefficient - quotient * coefficient]
    }
    assert(oldR === 1n, "Value has no modular inverse")
    return ((oldCoefficient % modulus) + modulus) % modulus
}

function bitsToInteger(value: Buffer, bits: number): bigint {
    const excess = value.length * 8 - bits
    const integer = decodeBigIntBE(value)
    return excess > 0 ? integer >> BigInt(excess) : integer
}

function fixedWidth(value: bigint, width: number): Buffer {
    const encoded = encodeBigIntBE(value)
    assert(encoded.length <= width, "RFC 6979 integer exceeds its fixed width")
    const result = Buffer.alloc(width)
    encoded.copy(result, width - encoded.length)
    encoded.fill(0)
    return result
}

function bitLength(value: bigint): number {
    return value.toString(2).length
}
