import assert from "node:assert"
import { readFile } from "node:fs/promises"

import KeyRevocationList from "./KeyRevocationList.js"
import SSHSignature from "./SSHSignature.js"
import PublicKey, { SSHCertificatePublicKey } from "./utils/PublicKey.js"
import { decodeSSHUTF8, encodeSSHUTF8 } from "./utils/SSHText.js"

const MAX_ALLOWED_SIGNERS_LENGTH = 16 * 1024 * 1024
const MAX_ALLOWED_SIGNERS_LINE_LENGTH = 64 * 1024
const MAX_PATTERN_LENGTH = 1023
const MAX_UINT64 = 0xffffffffffffffffn

export interface AllowedSignerVerificationOptions {
    /** Expected signer identity matched against the entry and any user certificate principals. */
    principal: string
    /** Expected SSHSIG namespace and allowed-signers namespace pattern input. */
    namespace: string
    /** Verification instant. Numbers and bigints are Unix seconds; Dates are converted to seconds. */
    at?: Date | number | bigint
    /** Optional revocation policy applied to the embedded signing key or certificate. */
    revocations?: KeyRevocationList
}

export interface AllowedSignerPrincipalLookupOptions {
    /** Lookup instant. Numbers and bigints are Unix seconds; Dates are converted to seconds. */
    at?: Date | number | bigint
    /** Optional revocation policy applied before returning principals. */
    revocations?: KeyRevocationList
}

interface AllowedSignerEntry {
    readonly principalPatterns: readonly string[]
    readonly key: PublicKey
    readonly certificateAuthority: boolean
    readonly namespacePatterns?: readonly string[]
    readonly validAfter?: bigint
    readonly validBefore?: bigint
}

interface ParsedOptions {
    readonly certificateAuthority: boolean
    readonly namespacePatterns?: readonly string[]
    readonly validAfter?: bigint
    readonly validBefore?: bigint
}

/** OpenSSH allowed-signers policy with integrated detached-signature verification. */
export default class AllowedSigners {
    readonly #entries: readonly AllowedSignerEntry[]

    private constructor(entries: readonly AllowedSignerEntry[]) {
        this.#entries = Object.freeze(entries)
    }

    static parse(content: string | Buffer): AllowedSigners {
        try {
            const text = decodeAllowedSigners(content)
            const lines = text.split(/\r\n|\r|\n/u)
            const entries: AllowedSignerEntry[] = []
            for (let index = 0; index < lines.length; index++) {
                const lineNumber = index + 1
                const line = lines[index]!
                assert(
                    Buffer.byteLength(line, "utf8") <= MAX_ALLOWED_SIGNERS_LINE_LENGTH,
                    `Allowed-signers line ${lineNumber} exceeds the maximum length`,
                )
                const trimmed = line.trimStart()
                if (trimmed.length === 0 || trimmed.startsWith("#")) continue
                try {
                    entries.push(parseEntry(trimmed, lineNumber))
                } catch (error) {
                    const reason = error instanceof Error ? error.message : String(error)
                    throw new Error(`Invalid allowed-signers line ${lineNumber}: ${reason}`, {
                        cause: error,
                    })
                }
            }
            return new AllowedSigners(entries)
        } catch (error) {
            if (
                error instanceof Error &&
                error.message.startsWith("Invalid allowed-signers line")
            ) {
                throw error
            }
            const reason = error instanceof Error ? error.message : String(error)
            throw new Error(`Invalid allowed-signers file: ${reason}`, { cause: error })
        }
    }

    static async load(path: string): Promise<AllowedSigners> {
        return AllowedSigners.parse(await readFile(path))
    }

    /** Returns the policy principal fields whose pattern lists positively match this value. */
    matchPrincipals(principal: string): readonly string[] {
        const normalized = normalizePolicyText(principal, "allowed signer principal")
        return Object.freeze(
            this.#entries
                .filter((entry) => matchesPatternList(entry.principalPatterns, normalized))
                .map((entry) => entry.principalPatterns.join(",")),
        )
    }

    /** Finds the first entry's principals authorized for an embedded signature key. */
    findPrincipals(
        signature: SSHSignature | string | Buffer,
        options: AllowedSignerPrincipalLookupOptions = {},
    ): readonly string[] {
        validateLookupOptions(options)
        const parsed = signature instanceof SSHSignature ? signature : SSHSignature.parse(signature)
        if (options.revocations?.isRevoked(parsed.publicKey)) return Object.freeze([])
        const at = normalizeVerificationTime(options.at)
        for (const entry of this.#entries) {
            if (!isEntryTimeValid(entry, at)) continue
            if (!entry.certificateAuthority && entry.key.equals(parsed.publicKey)) {
                return Object.freeze([...entry.principalPatterns])
            }
            const certificate = authorizedCertificate(entry, parsed.publicKey, at)
            if (!certificate) continue
            const principals = entry.principalPatterns.flatMap((pattern) =>
                certificate.data.principals.filter((principal) =>
                    matchesPattern(pattern, principal),
                ),
            )
            if (principals.length > 0) return Object.freeze(principals)
        }
        return Object.freeze([])
    }

    verify(
        message: Buffer,
        signature: SSHSignature | string | Buffer,
        options: AllowedSignerVerificationOptions,
    ): boolean {
        if (!Buffer.isBuffer(message)) {
            throw new TypeError("Allowed-signers verification message must be a buffer")
        }
        if (typeof options !== "object" || options === null) {
            throw new TypeError("Allowed-signers verification options must be an object")
        }
        const parsed = signature instanceof SSHSignature ? signature : SSHSignature.parse(signature)
        const principal = normalizePolicyText(options.principal, "allowed signer principal")
        const namespace = normalizePolicyText(options.namespace, "allowed signer namespace")
        const at = normalizeVerificationTime(options.at)
        validateRevocations(options.revocations)
        if (!parsed.verify(message, namespace)) return false
        if (options.revocations?.isRevoked(parsed.publicKey)) return false
        return this.#entries.some((entry) =>
            authorizesEntry(entry, parsed.publicKey, principal, namespace, at),
        )
    }
}

function validateLookupOptions(options: AllowedSignerPrincipalLookupOptions): void {
    if (typeof options !== "object" || options === null) {
        throw new TypeError("Allowed-signers principal lookup options must be an object")
    }
    validateRevocations(options.revocations)
}

function validateRevocations(revocations: KeyRevocationList | undefined): void {
    if (revocations !== undefined && !(revocations instanceof KeyRevocationList)) {
        throw new TypeError("Allowed-signers revocations must be a key revocation list")
    }
}

function decodeAllowedSigners(content: string | Buffer): string {
    if (typeof content !== "string" && !Buffer.isBuffer(content)) {
        throw new TypeError("Allowed-signers content must be a string or buffer")
    }
    const length = Buffer.isBuffer(content) ? content.length : Buffer.byteLength(content, "utf8")
    assert(length <= MAX_ALLOWED_SIGNERS_LENGTH, "Allowed-signers file exceeds the maximum length")
    const text = Buffer.isBuffer(content)
        ? decodeSSHUTF8(content, "allowed-signers file")
        : (encodeSSHUTF8(content, "allowed-signers file"), content)
    assert(!text.includes("\0"), "Allowed-signers file contains NUL")
    return text
}

function parseEntry(line: string, lineNumber: number): AllowedSignerEntry {
    const [principalsToken, afterPrincipals] = readToken(line)
    assert(principalsToken.length > 0 && afterPrincipals.length > 0, "Missing key")
    const principalPatterns = parsePatternList(principalsToken, "principal", lineNumber)

    let key: PublicKey | undefined
    let parsedOptions: ParsedOptions = { certificateAuthority: false }
    try {
        key = PublicKey.parseString(afterPrincipals)
    } catch {}
    if (!key) {
        const [optionsToken, afterOptions] = readToken(afterPrincipals)
        assert(optionsToken.length > 0 && afterOptions.length > 0, "Missing key after options")
        parsedOptions = parseOptions(optionsToken, lineNumber)
        key = PublicKey.parseString(afterOptions)
    }

    return Object.freeze({
        principalPatterns: Object.freeze(principalPatterns),
        key: PublicKey.parse(key.serialize()),
        ...parsedOptions,
    })
}

function readToken(value: string): [string, string] {
    let quoted = false
    let escaped = false
    let index = 0
    for (; index < value.length; index++) {
        const character = value[index]!
        if (escaped) {
            escaped = false
            continue
        }
        if (character === "\\") {
            escaped = true
            continue
        }
        if (character === '"') {
            quoted = !quoted
            continue
        }
        if (!quoted && /\s/u.test(character)) break
    }
    assert(!quoted && !escaped, "Unterminated quoted or escaped field")
    const token = value.slice(0, index)
    return [token, value.slice(index).trimStart()]
}

function parseOptions(value: string, lineNumber: number): ParsedOptions {
    const parts = splitOptions(value)
    let certificateAuthority = false
    let namespacePatterns: readonly string[] | undefined
    let validAfter: bigint | undefined
    let validBefore: bigint | undefined
    for (const part of parts) {
        const separator = part.indexOf("=")
        const name = (separator === -1 ? part : part.slice(0, separator)).toLowerCase()
        const encodedValue = separator === -1 ? undefined : part.slice(separator + 1)
        if (name === "cert-authority" && encodedValue === undefined) {
            assert(!certificateAuthority, "Duplicate cert-authority option")
            certificateAuthority = true
        } else if (name === "namespaces" && encodedValue !== undefined) {
            assert(namespacePatterns === undefined, "Duplicate namespaces option")
            namespacePatterns = Object.freeze(
                parsePatternList(dequote(encodedValue), "namespace", lineNumber, true),
            )
        } else if (name === "valid-after" && encodedValue !== undefined) {
            assert(validAfter === undefined, "Duplicate valid-after option")
            validAfter = parseAbsoluteTime(dequote(encodedValue))
        } else if (name === "valid-before" && encodedValue !== undefined) {
            assert(validBefore === undefined, "Duplicate valid-before option")
            validBefore = parseAbsoluteTime(dequote(encodedValue))
        } else {
            throw new Error(`Unknown allowed-signers option: ${name}`)
        }
    }
    assert(
        validAfter === undefined || validBefore === undefined || validBefore > validAfter,
        "valid-before must be later than valid-after",
    )
    return Object.freeze({
        certificateAuthority,
        ...(namespacePatterns ? { namespacePatterns } : {}),
        ...(validAfter === undefined ? {} : { validAfter }),
        ...(validBefore === undefined ? {} : { validBefore }),
    })
}

function splitOptions(value: string): string[] {
    const parts: string[] = []
    let start = 0
    let quoted = false
    let escaped = false
    for (let index = 0; index < value.length; index++) {
        const character = value[index]!
        if (escaped) {
            escaped = false
            continue
        }
        if (character === "\\") {
            escaped = true
        } else if (character === '"') {
            quoted = !quoted
        } else if (character === "," && !quoted) {
            parts.push(value.slice(start, index))
            start = index + 1
        }
    }
    assert(!quoted && !escaped, "Unterminated quoted or escaped option")
    parts.push(value.slice(start))
    assert(
        parts.every((part) => part.length > 0),
        "Empty allowed-signers option",
    )
    return parts
}

function dequote(value: string): string {
    assert(value.startsWith('"'), "Allowed-signers option value must be quoted")
    assert(value.length >= 2 && value.endsWith('"'), "Unterminated quoted option")
    return unescapeOption(value.slice(1, -1))
}

function unescapeOption(value: string): string {
    let result = ""
    for (let index = 0; index < value.length; index++) {
        const character = value[index]!
        if (character !== "\\") {
            result += character
            continue
        }
        assert(index + 1 < value.length, "Dangling option escape")
        if (value[index + 1] === '"') {
            result += '"'
            index++
        } else {
            result += character
        }
    }
    return result
}

function parsePatternList(
    value: string,
    field: string,
    lineNumber: number,
    allowWhitespace = false,
): string[] {
    assert(value.length > 0, `Empty ${field} pattern list`)
    const patterns = value.split(",")
    for (const pattern of patterns) {
        const plain = pattern.startsWith("!") ? pattern.slice(1) : pattern
        assert(plain.length > 0, `Empty ${field} pattern on line ${lineNumber}`)
        assert(
            allowWhitespace || !/\s/u.test(pattern),
            `${field} pattern contains whitespace on line ${lineNumber}`,
        )
        assert(
            Buffer.byteLength(plain, "utf8") <= MAX_PATTERN_LENGTH,
            `${field} pattern exceeds ${MAX_PATTERN_LENGTH} bytes on line ${lineNumber}`,
        )
    }
    return patterns
}

function normalizePolicyText(value: string, field: string): string {
    const encoded = encodeSSHUTF8(value, field)
    assert(encoded.length > 0, `${field} must not be empty`)
    assert(!encoded.includes(0), `${field} must not contain NUL`)
    assert(encoded.length <= MAX_ALLOWED_SIGNERS_LINE_LENGTH, `${field} exceeds the maximum length`)
    return value
}

function normalizeVerificationTime(value: Date | number | bigint | undefined): bigint {
    if (value === undefined) return BigInt(Math.floor(Date.now() / 1000))
    if (value instanceof Date) {
        const milliseconds = value.getTime()
        assert(Number.isFinite(milliseconds), "Invalid allowed-signers verification date")
        return validateUnixTime(BigInt(Math.floor(milliseconds / 1000)))
    }
    if (typeof value === "number") {
        assert(
            Number.isSafeInteger(value),
            "Allowed-signers verification time must be integer Unix seconds",
        )
        return validateUnixTime(BigInt(value))
    }
    assert(typeof value === "bigint", "Invalid allowed-signers verification time")
    return validateUnixTime(value)
}

function validateUnixTime(value: bigint): bigint {
    assert(value >= 0n && value <= MAX_UINT64, "Allowed-signers verification time is out of range")
    return value
}

function parseAbsoluteTime(value: string): bigint {
    const match = /^(\d{4})(\d{2})(\d{2})(?:(\d{2})(\d{2})(?:(\d{2}))?)?(Z|UTC)?$/iu.exec(value)
    assert(match, `Invalid allowed-signers timestamp: ${value}`)
    const [, yearRaw, monthRaw, dayRaw, hourRaw, minuteRaw, secondRaw, zone] = match
    const year = Number(yearRaw)
    const month = Number(monthRaw) - 1
    const day = Number(dayRaw)
    const hour = Number(hourRaw ?? 0)
    const minute = Number(minuteRaw ?? 0)
    const second = Number(secondRaw ?? 0)
    const utc = zone !== undefined
    const date = utc
        ? new Date(Date.UTC(year, month, day, hour, minute, second))
        : new Date(year, month, day, hour, minute, second)
    const components = utc
        ? [
              date.getUTCFullYear(),
              date.getUTCMonth(),
              date.getUTCDate(),
              date.getUTCHours(),
              date.getUTCMinutes(),
              date.getUTCSeconds(),
          ]
        : [
              date.getFullYear(),
              date.getMonth(),
              date.getDate(),
              date.getHours(),
              date.getMinutes(),
              date.getSeconds(),
          ]
    assert(
        components.every(
            (component, index) => component === [year, month, day, hour, minute, second][index],
        ),
        `Invalid allowed-signers timestamp: ${value}`,
    )
    const seconds = BigInt(Math.floor(date.getTime() / 1000))
    assert(seconds > 0n, `Invalid allowed-signers timestamp: ${value}`)
    return seconds
}

function authorizesEntry(
    entry: AllowedSignerEntry,
    signingKey: PublicKey,
    principal: string,
    namespace: string,
    at: bigint,
): boolean {
    if (!matchesPatternList(entry.principalPatterns, principal)) return false
    if (entry.namespacePatterns && !matchesPatternList(entry.namespacePatterns, namespace)) {
        return false
    }
    if (!isEntryTimeValid(entry, at)) return false

    if (!entry.certificateAuthority) return entry.key.equals(signingKey)
    return (
        authorizedCertificate(entry, signingKey, at)?.data.principals.includes(principal) ?? false
    )
}

function isEntryTimeValid(entry: AllowedSignerEntry, at: bigint): boolean {
    return !(
        (entry.validAfter !== undefined && at < entry.validAfter) ||
        (entry.validBefore !== undefined && at > entry.validBefore)
    )
}

function authorizedCertificate(
    entry: AllowedSignerEntry,
    signingKey: PublicKey,
    at: bigint,
): SSHCertificatePublicKey | undefined {
    if (!entry.certificateAuthority) return undefined
    const certificate = signingKey.data.algorithm
    return certificate instanceof SSHCertificatePublicKey &&
        certificate.data.signatureKey.equals(entry.key) &&
        certificate.data.role === "user" &&
        certificate.verifyCertificateSignature() &&
        certificate.data.validAfter <= at &&
        at < certificate.data.validBefore
        ? certificate
        : undefined
}

function matchesPatternList(patterns: readonly string[], value: string): boolean {
    let positive = false
    for (const candidate of patterns) {
        const negated = candidate.startsWith("!")
        const pattern = negated ? candidate.slice(1) : candidate
        if (!matchesPattern(pattern, value)) continue
        if (negated) return false
        positive = true
    }
    return positive
}

function matchesPattern(pattern: string, value: string): boolean {
    const patternBytes = Buffer.from(pattern, "utf8")
    const valueBytes = Buffer.from(value, "utf8")
    let states = new Uint8Array(patternBytes.length + 1)
    states[0] = 1
    applyStarClosure(states, patternBytes)
    for (const byte of valueBytes) {
        const next = new Uint8Array(states.length)
        for (let index = 0; index < patternBytes.length; index++) {
            if (states[index] === 0) continue
            const expected = patternBytes[index]
            if (expected === 0x2a) next[index] = 1
            else if (expected === 0x3f || expected === byte) next[index + 1] = 1
        }
        applyStarClosure(next, patternBytes)
        states = next
    }
    return states[patternBytes.length] === 1
}

function applyStarClosure(states: Uint8Array, pattern: Uint8Array): void {
    for (let index = 0; index < pattern.length; index++) {
        if (states[index] === 1 && pattern[index] === 0x2a) states[index + 1] = 1
    }
}
