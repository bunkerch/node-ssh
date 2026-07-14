import assert from "node:assert"
import { checkPrimeSync, createHash, randomBytes, type KeyObject } from "node:crypto"
import asn1js from "asn1js"
import { decodeBigIntBE, encodeBigIntBE } from "./BigInt.js"

export interface DSAParameters {
    p: Buffer
    q: Buffer
    g: Buffer
    y: Buffer
}

export interface DSAPrivateParameters extends DSAParameters {
    x: Buffer
}

const DSA_OID = "1.2.840.10040.4.1"

export function validateDSAParameters(parameters: DSAParameters): void {
    const p = positiveMpintValue(parameters.p, "DSA p")
    const q = positiveMpintValue(parameters.q, "DSA q")
    const g = positiveMpintValue(parameters.g, "DSA g")
    const y = positiveMpintValue(parameters.y, "DSA y")
    assert(bitLength(p) === 1024, "DSA p must be 1024 bits")
    assert(bitLength(q) === 160, "DSA q must be 160 bits")
    assert(checkPrimeSync(unsigned(parameters.p)), "DSA p must be prime")
    assert(checkPrimeSync(unsigned(parameters.q)), "DSA q must be prime")
    assert((p - 1n) % q === 0n, "DSA q must divide p - 1")
    assert(g > 1n && g < p, "DSA g is out of range")
    assert(modPow(g, q, p) === 1n, "DSA g is not in the q-order subgroup")
    assert(y > 1n && y < p, "DSA y is out of range")
    assert(modPow(y, q, p) === 1n, "DSA y is not in the q-order subgroup")
}

export function validateDSAPrivateParameters(parameters: DSAPrivateParameters): void {
    validateDSAParameters(parameters)
    const x = positiveMpintValue(parameters.x, "DSA x")
    const p = decodeBigIntBE(parameters.p)
    const q = decodeBigIntBE(parameters.q)
    const g = decodeBigIntBE(parameters.g)
    const y = decodeBigIntBE(parameters.y)
    assert(x > 0n && x < q, "DSA x is out of range")
    assert(modPow(g, x, p) === y, "DSA private and public values do not match")
}

export function signDSA(data: Buffer, parameters: DSAPrivateParameters): Buffer {
    const p = decodeBigIntBE(parameters.p)
    const q = decodeBigIntBE(parameters.q)
    const g = decodeBigIntBE(parameters.g)
    const x = decodeBigIntBE(parameters.x)
    const digest = decodeBigIntBE(createHash("sha1").update(data).digest())
    while (true) {
        const k = randomScalar(q)
        const r = modPow(g, k, p) % q
        if (r === 0n) continue
        const s = (modInverse(k, q) * (digest + x * r)) % q
        if (s === 0n) continue
        return Buffer.concat([fixedWidth(r, 20), fixedWidth(s, 20)])
    }
}

export function verifyDSA(data: Buffer, signature: Buffer, parameters: DSAParameters): boolean {
    if (signature.length !== 40) return false
    const p = decodeBigIntBE(parameters.p)
    const q = decodeBigIntBE(parameters.q)
    const g = decodeBigIntBE(parameters.g)
    const y = decodeBigIntBE(parameters.y)
    const r = decodeBigIntBE(signature.subarray(0, 20))
    const s = decodeBigIntBE(signature.subarray(20))
    if (r <= 0n || r >= q || s <= 0n || s >= q) return false
    const digest = decodeBigIntBE(createHash("sha1").update(data).digest())
    const w = modInverse(s, q)
    const u1 = (digest * w) % q
    const u2 = (r * w) % q
    return ((modPow(g, u1, p) * modPow(y, u2, p)) % p) % q === r
}

export function dsaParametersFromPublicKey(key: KeyObject): DSAParameters {
    assert(key.asymmetricKeyType === "dsa", "Expected a DSA public key")
    const root = parseSequence(key.export({ format: "der", type: "spki" }))
    assert(root.length === 2 && root[1] instanceof asn1js.BitString, "Invalid DSA SPKI")
    const [p, q, g] = parseAlgorithmIdentifier(root[0])
    const y = parseEmbeddedInteger(root[1].valueBlock.valueHexView, "DSA public value")
    const parameters = { p, q, g, y }
    validateDSAParameters(parameters)
    return parameters
}

export function dsaParametersFromPrivateKey(key: KeyObject): DSAPrivateParameters {
    assert(key.asymmetricKeyType === "dsa", "Expected a DSA private key")
    const root = parseSequence(key.export({ format: "der", type: "pkcs8" }))
    assert(
        root.length === 3 &&
            root[0] instanceof asn1js.Integer &&
            root[2] instanceof asn1js.OctetString,
        "Invalid DSA PKCS#8 key",
    )
    assert(integerBuffer(root[0]).equals(Buffer.from([0])), "Unsupported DSA PKCS#8 version")
    const [p, q, g] = parseAlgorithmIdentifier(root[1])
    const x = parseEmbeddedInteger(root[2].valueBlock.valueHexView, "DSA private value")
    const y = canonicalMpint(
        encodeBigIntBE(modPow(decodeBigIntBE(g), decodeBigIntBE(x), decodeBigIntBE(p))),
    )
    const parameters = { p, q, g, y, x }
    validateDSAPrivateParameters(parameters)
    return parameters
}

function parseSequence(der: Buffer): asn1js.BaseBlock[] {
    const decoded = asn1js.fromBER(der)
    assert(
        decoded.offset === der.length && decoded.result instanceof asn1js.Sequence,
        "Invalid DER sequence",
    )
    return decoded.result.valueBlock.value
}

function parseAlgorithmIdentifier(block: asn1js.BaseBlock): [Buffer, Buffer, Buffer] {
    assert(block instanceof asn1js.Sequence, "Invalid DSA algorithm identifier")
    const values = block.valueBlock.value
    assert(
        values.length === 2 &&
            values[0] instanceof asn1js.ObjectIdentifier &&
            values[0].valueBlock.toString() === DSA_OID &&
            values[1] instanceof asn1js.Sequence,
        "Invalid DSA algorithm identifier",
    )
    const parameters = values[1].valueBlock.value
    assert(
        parameters.length === 3 && parameters.every((value) => value instanceof asn1js.Integer),
        "Invalid DSA parameters",
    )
    return parameters.map((value) => canonicalMpint(integerBuffer(value as asn1js.Integer))) as [
        Buffer,
        Buffer,
        Buffer,
    ]
}

function parseEmbeddedInteger(der: ArrayBuffer | ArrayBufferView, name: string): Buffer {
    const decoded = asn1js.fromBER(der)
    assert(
        decoded.offset === der.byteLength && decoded.result instanceof asn1js.Integer,
        `Invalid ${name}`,
    )
    return canonicalMpint(integerBuffer(decoded.result))
}

function integerBuffer(integer: asn1js.Integer): Buffer {
    return Buffer.from(integer.valueBlock.valueHexView)
}

function canonicalMpint(value: Buffer): Buffer {
    assert(value.length > 0, "DSA DER integer is empty")
    let offset = 0
    while (offset < value.length - 1 && value[offset] === 0 && (value[offset + 1] & 0x80) === 0)
        offset++
    const unsignedValue = value.subarray(offset)
    return (unsignedValue[0] & 0x80) === 0
        ? Buffer.from(unsignedValue)
        : Buffer.concat([Buffer.from([0]), unsignedValue])
}

function positiveMpintValue(value: Buffer, name: string): bigint {
    assert(value.length > 0, `${name} must be positive`)
    assert((value[0] & 0x80) === 0, `${name} must not be negative`)
    assert(
        value.length === 1 || value[0] !== 0 || (value[1] & 0x80) !== 0,
        `${name} is not a canonical mpint`,
    )
    const integer = decodeBigIntBE(value)
    assert(integer > 0n, `${name} must be positive`)
    return integer
}

function unsigned(value: Buffer): Buffer {
    return value[0] === 0 ? value.subarray(1) : value
}

function bitLength(value: bigint): number {
    return value.toString(2).length
}

function modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
    let result = 1n
    base %= modulus
    while (exponent > 0n) {
        if ((exponent & 1n) !== 0n) result = (result * base) % modulus
        exponent >>= 1n
        base = (base * base) % modulus
    }
    return result
}

function modInverse(value: bigint, modulus: bigint): bigint {
    let oldR = value
    let r = modulus
    let oldS = 1n
    let s = 0n
    while (r !== 0n) {
        const quotient = oldR / r
        ;[oldR, r] = [r, oldR - quotient * r]
        ;[oldS, s] = [s, oldS - quotient * s]
    }
    assert(oldR === 1n, "DSA value has no modular inverse")
    return ((oldS % modulus) + modulus) % modulus
}

function randomScalar(q: bigint): bigint {
    while (true) {
        const value = decodeBigIntBE(randomBytes(20))
        if (value > 0n && value < q) return value
    }
}

function fixedWidth(value: bigint, width: number): Buffer {
    const encoded = encodeBigIntBE(value)
    assert(encoded.length <= width, "DSA integer exceeds its fixed width")
    const result = Buffer.alloc(width)
    encoded.copy(result, width - encoded.length)
    return result
}
