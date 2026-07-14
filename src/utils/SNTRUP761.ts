import assert from "node:assert"
import { createHash, randomBytes } from "node:crypto"

export const SNTRUP761_PUBLIC_KEY_BYTES = 1158
export const SNTRUP761_SECRET_KEY_BYTES = 1763
export const SNTRUP761_CIPHERTEXT_BYTES = 1039
export const SNTRUP761_SHARED_SECRET_BYTES = 32

const P = 761
const Q = 4591
const W = 286
const Q12 = (Q - 1) / 2
const SMALL_BYTES = (P + 3) >> 2
const SECRET_POLYNOMIAL_BYTES = 2 * SMALL_BYTES
const CONFIRM_BYTES = 32
const ROUNDED_BYTES = SNTRUP761_CIPHERTEXT_BYTES - CONFIRM_BYTES

export interface SNTRUP761KeyPair {
    publicKey: Buffer
    secretKey: Buffer
}

export interface SNTRUP761Encapsulation {
    ciphertext: Buffer
    sharedSecret: Buffer
}

/** Streamlined NTRU Prime sntrup761 KEM from the public-domain reference algorithm. */
export function generateSNTRUP761KeyPair(): SNTRUP761KeyPair {
    const publicKey = Buffer.alloc(SNTRUP761_PUBLIC_KEY_BYTES)
    const secretKey = Buffer.alloc(SNTRUP761_SECRET_KEY_BYTES)
    const { h, f, gInverse } = keyGen()
    rqEncode(publicKey, h)
    smallEncode(secretKey.subarray(0, SMALL_BYTES), f)
    smallEncode(secretKey.subarray(SMALL_BYTES, SECRET_POLYNOMIAL_BYTES), gInverse)
    publicKey.copy(secretKey, SECRET_POLYNOMIAL_BYTES)
    const rho = randomBytes(SMALL_BYTES)
    rho.copy(secretKey, SECRET_POLYNOMIAL_BYTES + SNTRUP761_PUBLIC_KEY_BYTES)
    const cache = hashPrefix(4, publicKey)
    cache.copy(secretKey, SNTRUP761_SECRET_KEY_BYTES - 32)
    rho.fill(0)
    cache.fill(0)
    h.fill(0)
    f.fill(0)
    gInverse.fill(0)
    return { publicKey, secretKey }
}

export function encapsulateSNTRUP761(publicKey: Buffer): SNTRUP761Encapsulation {
    assert(
        publicKey.length === SNTRUP761_PUBLIC_KEY_BYTES,
        `sntrup761 public keys must be ${SNTRUP761_PUBLIC_KEY_BYTES} bytes`,
    )
    const ciphertext = Buffer.alloc(SNTRUP761_CIPHERTEXT_BYTES)
    const cache = hashPrefix(4, publicKey)
    const r = shortRandom()
    const rEncoded = hide(ciphertext, r, publicKey, cache)
    const sharedSecret = hashSession(1, rEncoded, ciphertext)
    cache.fill(0)
    r.fill(0)
    rEncoded.fill(0)
    return { ciphertext, sharedSecret }
}

export function decapsulateSNTRUP761(ciphertext: Buffer, secretKey: Buffer): Buffer {
    assert(
        ciphertext.length === SNTRUP761_CIPHERTEXT_BYTES,
        `sntrup761 ciphertexts must be ${SNTRUP761_CIPHERTEXT_BYTES} bytes`,
    )
    assert(
        secretKey.length === SNTRUP761_SECRET_KEY_BYTES,
        `sntrup761 secret keys must be ${SNTRUP761_SECRET_KEY_BYTES} bytes`,
    )
    const publicKey = secretKey.subarray(
        SECRET_POLYNOMIAL_BYTES,
        SECRET_POLYNOMIAL_BYTES + SNTRUP761_PUBLIC_KEY_BYTES,
    )
    const rho = secretKey.subarray(
        SECRET_POLYNOMIAL_BYTES + SNTRUP761_PUBLIC_KEY_BYTES,
        SNTRUP761_SECRET_KEY_BYTES - 32,
    )
    const cache = secretKey.subarray(SNTRUP761_SECRET_KEY_BYTES - 32)
    const r = zDecrypt(ciphertext, secretKey)
    const candidate = Buffer.alloc(SNTRUP761_CIPHERTEXT_BYTES)
    const rEncoded = hide(candidate, r, publicKey, cache)
    let different = 0
    for (let i = 0; i < ciphertext.length; i++) different |= ciphertext[i] ^ candidate[i]
    const mask = -Number(different !== 0)
    for (let i = 0; i < rEncoded.length; i++) {
        rEncoded[i] ^= mask & (rEncoded[i] ^ rho[i])
    }
    const sharedSecret = hashSession(1 + mask, rEncoded, ciphertext)
    r.fill(0)
    candidate.fill(0)
    rEncoded.fill(0)
    return sharedSecret
}

function f3Freeze(value: number): number {
    return value - 3 * ((10923 * value + 16384) >> 15)
}

function fqFreeze(value: number): number {
    const q16 = Math.floor((0x10000 + Q / 2) / Q)
    const q20 = Math.floor((0x100000 + Q / 2) / Q)
    const q28 = Math.floor((0x10000000 + Q / 2) / Q)
    value -= Q * ((q16 * value) >> 16)
    value -= Q * ((q20 * value) >> 20)
    return value - Q * ((q28 * value + 0x8000000) >> 28)
}

function encode(out: Buffer, values: Uint16Array, moduli: Uint16Array): void {
    let offset = 0
    const recurse = (rValues: Uint16Array, mValues: Uint16Array): void => {
        const length = rValues.length
        if (length === 1) {
            let r = rValues[0]
            let m = mValues[0]
            while (m > 1) {
                out[offset++] = r
                r >>= 8
                m = (m + 255) >> 8
            }
            return
        }
        const nextLength = (length + 1) >> 1
        const nextValues = new Uint16Array(nextLength)
        const nextModuli = new Uint16Array(nextLength)
        let index = 0
        for (; index < length - 1; index += 2) {
            const m0 = mValues[index]
            let r = rValues[index] + rValues[index + 1] * m0
            let m = mValues[index + 1] * m0
            while (m >= 16384) {
                out[offset++] = r
                r = Math.floor(r / 256)
                m = Math.floor((m + 255) / 256)
            }
            nextValues[index >> 1] = r
            nextModuli[index >> 1] = m
        }
        if (index < length) {
            nextValues[index >> 1] = rValues[index]
            nextModuli[index >> 1] = mValues[index]
        }
        recurse(nextValues, nextModuli)
    }
    recurse(values, moduli)
    assert(offset === out.length, "sntrup761 encoder produced an invalid length")
}

function decode(input: Buffer, moduli: Uint16Array): Uint16Array {
    let offset = 0
    const recurse = (mValues: Uint16Array): Uint16Array => {
        const length = mValues.length
        if (length === 1) {
            if (mValues[0] === 1) return new Uint16Array([0])
            const value =
                mValues[0] <= 256 ? input[offset] : input[offset] + 256 * input[offset + 1]
            return new Uint16Array([value % mValues[0]])
        }
        const nextLength = (length + 1) >> 1
        const nextModuli = new Uint16Array(nextLength)
        const bottomRadix = new Uint32Array(length >> 1)
        const bottomValue = new Uint16Array(length >> 1)
        let index = 0
        for (; index < length - 1; index += 2) {
            const modulus = mValues[index] * mValues[index + 1]
            if (modulus > 256 * 16383) {
                bottomRadix[index >> 1] = 65536
                bottomValue[index >> 1] = input[offset] + 256 * input[offset + 1]
                offset += 2
                nextModuli[index >> 1] = Math.floor((Math.floor((modulus + 255) / 256) + 255) / 256)
            } else if (modulus >= 16384) {
                bottomRadix[index >> 1] = 256
                bottomValue[index >> 1] = input[offset++]
                nextModuli[index >> 1] = Math.floor((modulus + 255) / 256)
            } else {
                bottomRadix[index >> 1] = 1
                nextModuli[index >> 1] = modulus
            }
        }
        if (index < length) nextModuli[index >> 1] = mValues[index]
        const nextValues = recurse(nextModuli)
        const result = new Uint16Array(length)
        for (index = 0; index < length - 1; index += 2) {
            const combined =
                bottomValue[index >> 1] + bottomRadix[index >> 1] * nextValues[index >> 1]
            result[index] = combined % mValues[index]
            result[index + 1] = Math.floor(combined / mValues[index]) % mValues[index + 1]
        }
        if (index < length) result[index] = nextValues[index >> 1]
        return result
    }
    return recurse(moduli)
}

function r3FromRq(value: Int16Array): Int8Array {
    const result = new Int8Array(P)
    for (let i = 0; i < P; i++) result[i] = f3Freeze(value[i])
    return result
}

function r3Multiply(left: Int8Array, right: Int8Array): Int8Array {
    const product = new Int16Array(2 * P - 1)
    for (let i = 0; i < P; i++) {
        for (let j = 0; j < P; j++) product[i + j] += left[i] * right[j]
    }
    for (let i = P; i < product.length; i++) product[i - P] += product[i]
    for (let i = P; i < product.length; i++) product[i - P + 1] += product[i]
    const result = new Int8Array(P)
    for (let i = 0; i < P; i++) result[i] = f3Freeze(product[i])
    product.fill(0)
    return result
}

function r3Reciprocal(input: Int8Array): Int8Array | undefined {
    const f = new Int8Array(P + 1)
    const g = new Int8Array(P + 1)
    const v = new Int8Array(P + 1)
    const r = new Int8Array(P + 1)
    r[0] = 1
    f[0] = 1
    f[P - 1] = -1
    f[P] = -1
    for (let i = 0; i < P; i++) g[P - 1 - i] = input[i]
    let delta = 1
    for (let loop = 0; loop < 2 * P - 1; loop++) {
        for (let i = P; i > 0; i--) v[i] = v[i - 1]
        v[0] = 0
        const sign = -g[0] * f[0]
        const swap = -Number(delta > 0 && g[0] !== 0)
        delta ^= swap & (delta ^ -delta)
        delta++
        for (let i = 0; i <= P; i++) {
            let selected = swap & (f[i] ^ g[i])
            f[i] ^= selected
            g[i] ^= selected
            selected = swap & (v[i] ^ r[i])
            v[i] ^= selected
            r[i] ^= selected
        }
        for (let i = 0; i <= P; i++) g[i] = f3Freeze(g[i] + sign * f[i])
        for (let i = 0; i <= P; i++) r[i] = f3Freeze(r[i] + sign * v[i])
        for (let i = 0; i < P; i++) g[i] = g[i + 1]
        g[P] = 0
    }
    if (delta !== 0) {
        f.fill(0)
        g.fill(0)
        v.fill(0)
        r.fill(0)
        return undefined
    }
    const result = new Int8Array(P)
    for (let i = 0; i < P; i++) result[i] = f[0] * v[P - 1 - i]
    f.fill(0)
    g.fill(0)
    v.fill(0)
    r.fill(0)
    return result
}

function rqMultiplySmall(left: Int16Array, right: Int8Array): Int16Array {
    const product = new Int32Array(2 * P - 1)
    for (let i = 0; i < P; i++) {
        for (let j = 0; j < P; j++) product[i + j] += left[i] * right[j]
    }
    for (let i = P; i < product.length; i++) product[i - P] += product[i]
    for (let i = P; i < product.length; i++) product[i - P + 1] += product[i]
    const result = new Int16Array(P)
    for (let i = 0; i < P; i++) result[i] = fqFreeze(product[i])
    product.fill(0)
    return result
}

function fqReciprocal(value: number): number {
    let result = value
    for (let i = 1; i < Q - 2; i++) result = fqFreeze(value * result)
    return result
}

function rqReciprocal3(input: Int8Array): Int16Array {
    const f = new Int16Array(P + 1)
    const g = new Int16Array(P + 1)
    const v = new Int16Array(P + 1)
    const r = new Int16Array(P + 1)
    r[0] = fqReciprocal(3)
    f[0] = 1
    f[P - 1] = -1
    f[P] = -1
    for (let i = 0; i < P; i++) g[P - 1 - i] = input[i]
    let delta = 1
    for (let loop = 0; loop < 2 * P - 1; loop++) {
        for (let i = P; i > 0; i--) v[i] = v[i - 1]
        v[0] = 0
        const swap = -Number(delta > 0 && g[0] !== 0)
        delta ^= swap & (delta ^ -delta)
        delta++
        for (let i = 0; i <= P; i++) {
            let selected = swap & (f[i] ^ g[i])
            f[i] ^= selected
            g[i] ^= selected
            selected = swap & (v[i] ^ r[i])
            v[i] ^= selected
            r[i] ^= selected
        }
        const f0 = f[0]
        const g0 = g[0]
        for (let i = 0; i <= P; i++) g[i] = fqFreeze(f0 * g[i] - g0 * f[i])
        for (let i = 0; i <= P; i++) r[i] = fqFreeze(f0 * r[i] - g0 * v[i])
        for (let i = 0; i < P; i++) g[i] = g[i + 1]
        g[P] = 0
    }
    assert(delta === 0, "sntrup761 short polynomial is not invertible")
    const scale = fqReciprocal(f[0])
    const result = new Int16Array(P)
    for (let i = 0; i < P; i++) result[i] = fqFreeze(scale * v[P - 1 - i])
    f.fill(0)
    g.fill(0)
    v.fill(0)
    r.fill(0)
    return result
}

function sortUnsigned(values: Uint32Array): void {
    const signed = new Int32Array(values.length)
    for (let i = 0; i < values.length; i++) signed[i] = (values[i] ^ 0x80000000) | 0
    let top = 1
    while (top < signed.length - top) top += top
    const minMax = (left: number, right: number): void => {
        const x = signed[left]
        const y = signed[right]
        const mask = -Number(x > y)
        const difference = (x ^ y) & mask
        signed[left] = x ^ difference
        signed[right] = y ^ difference
    }
    for (let p = top; p >= 1; p >>= 1) {
        let i = 0
        while (i + 2 * p <= signed.length) {
            for (let j = i; j < i + p; j++) minMax(j, j + p)
            i += 2 * p
        }
        for (let j = i; j < signed.length - p; j++) minMax(j, j + p)
        i = 0
        let j = 0
        qLoop: for (let q = top; q > p; q >>= 1) {
            if (j !== i) {
                for (;;) {
                    if (j === signed.length - q) break qLoop
                    let a = signed[j + p]
                    for (let r = q; r > p; r >>= 1) {
                        const b = signed[j + r]
                        const mask = -Number(a > b)
                        const difference = (a ^ b) & mask
                        a ^= difference
                        signed[j + r] = b ^ difference
                    }
                    signed[j + p] = a
                    j++
                    if (j === i + p) {
                        i += 2 * p
                        break
                    }
                }
            }
            while (i + p <= signed.length - q) {
                for (j = i; j < i + p; j++) {
                    let a = signed[j + p]
                    for (let r = q; r > p; r >>= 1) {
                        const b = signed[j + r]
                        const mask = -Number(a > b)
                        const difference = (a ^ b) & mask
                        a ^= difference
                        signed[j + r] = b ^ difference
                    }
                    signed[j + p] = a
                }
                i += 2 * p
            }
            j = i
            while (j < signed.length - q) {
                let a = signed[j + p]
                for (let r = q; r > p; r >>= 1) {
                    const b = signed[j + r]
                    const mask = -Number(a > b)
                    const difference = (a ^ b) & mask
                    a ^= difference
                    signed[j + r] = b ^ difference
                }
                signed[j + p] = a
                j++
            }
        }
    }
    for (let i = 0; i < values.length; i++) values[i] = (signed[i] ^ 0x80000000) >>> 0
    signed.fill(0)
}

function randomUint32(): Uint32Array {
    const bytes = randomBytes(P * 4)
    const values = new Uint32Array(P)
    for (let i = 0; i < P; i++) values[i] = bytes.readUInt32LE(i * 4)
    bytes.fill(0)
    return values
}

function shortRandom(): Int8Array {
    const values = randomUint32()
    for (let i = 0; i < W; i++) values[i] &= 0xfffffffe
    for (let i = W; i < P; i++) values[i] = (values[i] & 0xfffffffc) | 1
    sortUnsigned(values)
    const result = new Int8Array(P)
    for (let i = 0; i < P; i++) result[i] = (values[i] & 3) - 1
    values.fill(0)
    return result
}

function smallRandom(): Int8Array {
    const values = randomUint32()
    const result = new Int8Array(P)
    for (let i = 0; i < P; i++) {
        result[i] = Math.floor(((values[i] & 0x3fffffff) * 3) / 0x40000000) - 1
    }
    values.fill(0)
    return result
}

function keyGen(): { h: Int16Array; f: Int8Array; gInverse: Int8Array } {
    let g: Int8Array | undefined
    let gInverse: Int8Array | undefined
    do {
        g?.fill(0)
        g = smallRandom()
        gInverse = r3Reciprocal(g)
    } while (gInverse === undefined)
    assert(g)
    const f = shortRandom()
    const fInverse = rqReciprocal3(f)
    const h = rqMultiplySmall(fInverse, g)
    g.fill(0)
    fInverse.fill(0)
    return { h, f, gInverse }
}

function round(value: Int16Array): Int16Array {
    const result = new Int16Array(P)
    for (let i = 0; i < P; i++) result[i] = value[i] - f3Freeze(value[i])
    return result
}

function encrypt(r: Int8Array, h: Int16Array): Int16Array {
    const product = rqMultiplySmall(h, r)
    const result = round(product)
    product.fill(0)
    return result
}

function decrypt(ciphertext: Int16Array, f: Int8Array, gInverse: Int8Array): Int8Array {
    const cf = rqMultiplySmall(ciphertext, f)
    const cf3 = new Int16Array(P)
    for (let i = 0; i < P; i++) cf3[i] = fqFreeze(3 * cf[i])
    const e = r3FromRq(cf3)
    const ev = r3Multiply(e, gInverse)
    let weight = 0
    for (let i = 0; i < P; i++) weight += ev[i] & 1
    const mask = -Number(weight !== W)
    const result = new Int8Array(P)
    for (let i = 0; i < W; i++) result[i] = ((ev[i] ^ 1) & ~mask) ^ 1
    for (let i = W; i < P; i++) result[i] = ev[i] & ~mask
    cf.fill(0)
    cf3.fill(0)
    e.fill(0)
    ev.fill(0)
    return result
}

function smallEncode(output: Buffer, value: Int8Array): void {
    let inputOffset = 0
    for (let i = 0; i < Math.floor(P / 4); i++) {
        let byte = 0
        for (let j = 0; j < 4; j++) byte += (value[inputOffset++] + 1) << (2 * j)
        output[i] = byte
    }
    output[SMALL_BYTES - 1] = value[inputOffset] + 1
}

function smallDecode(input: Buffer): Int8Array {
    const result = new Int8Array(P)
    let outputOffset = 0
    for (let i = 0; i < Math.floor(P / 4); i++) {
        const byte = input[i]
        for (let j = 0; j < 4; j++) result[outputOffset++] = ((byte >> (2 * j)) & 3) - 1
    }
    result[outputOffset] = (input[SMALL_BYTES - 1] & 3) - 1
    return result
}

function rqEncode(output: Buffer, value: Int16Array): void {
    const values = new Uint16Array(P)
    const moduli = new Uint16Array(P)
    for (let i = 0; i < P; i++) {
        values[i] = value[i] + Q12
        moduli[i] = Q
    }
    encode(output, values, moduli)
}

function rqDecode(input: Buffer): Int16Array {
    const moduli = new Uint16Array(P)
    moduli.fill(Q)
    const values = decode(input, moduli)
    const result = new Int16Array(P)
    for (let i = 0; i < P; i++) result[i] = values[i] - Q12
    return result
}

function roundedEncode(output: Buffer, value: Int16Array): void {
    const values = new Uint16Array(P)
    const moduli = new Uint16Array(P)
    for (let i = 0; i < P; i++) {
        values[i] = ((value[i] + Q12) * 10923) >> 15
        moduli[i] = Math.floor((Q + 2) / 3)
    }
    encode(output, values, moduli)
}

function roundedDecode(input: Buffer): Int16Array {
    const moduli = new Uint16Array(P)
    moduli.fill(Math.floor((Q + 2) / 3))
    const values = decode(input, moduli)
    const result = new Int16Array(P)
    for (let i = 0; i < P; i++) result[i] = values[i] * 3 - Q12
    return result
}

function zEncrypt(output: Buffer, r: Int8Array, publicKey: Buffer): void {
    const h = rqDecode(publicKey)
    const ciphertext = encrypt(r, h)
    roundedEncode(output.subarray(0, ROUNDED_BYTES), ciphertext)
    h.fill(0)
    ciphertext.fill(0)
}

function zDecrypt(ciphertext: Buffer, secretKey: Buffer): Int8Array {
    const f = smallDecode(secretKey.subarray(0, SMALL_BYTES))
    const gInverse = smallDecode(secretKey.subarray(SMALL_BYTES, SECRET_POLYNOMIAL_BYTES))
    const rounded = roundedDecode(ciphertext.subarray(0, ROUNDED_BYTES))
    const result = decrypt(rounded, f, gInverse)
    f.fill(0)
    gInverse.fill(0)
    rounded.fill(0)
    return result
}

function hashPrefix(prefix: number, input: Buffer): Buffer {
    const digest = createHash("sha512")
        .update(Buffer.from([prefix]))
        .update(input)
        .digest()
    const result = Buffer.from(digest.subarray(0, 32))
    digest.fill(0)
    return result
}

function hashConfirm(rEncoded: Buffer, cache: Buffer): Buffer {
    const rHash = hashPrefix(3, rEncoded)
    const input = Buffer.concat([rHash, cache])
    const result = hashPrefix(2, input)
    rHash.fill(0)
    input.fill(0)
    return result
}

function hashSession(prefix: number, rEncoded: Buffer, ciphertext: Buffer): Buffer {
    const rHash = hashPrefix(3, rEncoded)
    const input = Buffer.concat([rHash, ciphertext])
    const result = hashPrefix(prefix, input)
    rHash.fill(0)
    input.fill(0)
    return result
}

function hide(ciphertext: Buffer, r: Int8Array, publicKey: Buffer, cache: Buffer): Buffer {
    const rEncoded = Buffer.alloc(SMALL_BYTES)
    smallEncode(rEncoded, r)
    zEncrypt(ciphertext, r, publicKey)
    const confirmation = hashConfirm(rEncoded, cache)
    confirmation.copy(ciphertext, ROUNDED_BYTES)
    confirmation.fill(0)
    return rEncoded
}
