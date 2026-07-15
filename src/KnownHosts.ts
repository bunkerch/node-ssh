import { createHmac, randomBytes, timingSafeEqual } from "node:crypto"
import { open, readFile, rename, rm, stat } from "node:fs/promises"
import { basename, dirname, join } from "node:path"

import type { ClientHostVerifier } from "./Client.js"
import { parseKey } from "./KeyParsing.js"
import PublicKey, { encodeSSHKeyComment, SSHCertificatePublicKey } from "./utils/PublicKey.js"
import { readNextBuffer } from "./utils/Buffer.js"
import { decodeSSHName, encodeSSHName } from "./utils/SSHName.js"
import { decodeSSHUTF8, encodeSSHUTF8 } from "./utils/SSHText.js"
import { asciiLowercaseBytes, matchesWildcardBytes } from "./utils/Wildcard.js"
import { isPlainConfigurationObject } from "./utils/Configuration.js"

const MAX_KNOWN_HOSTS_LENGTH = 16 * 1024 * 1024
const MAX_KNOWN_HOSTS_LINE_LENGTH = 64 * 1024
const MAX_HOST_PATTERN_LENGTH = 1023

export type KnownHostMarker = "cert-authority" | "revoked"
export type KnownHostStatus = "trusted" | "unknown" | "changed" | "revoked"

export interface KnownHostCheckResult {
    readonly status: KnownHostStatus
    readonly line?: number
    readonly key?: PublicKey
}

export interface KnownHostsReplaceOptions {
    /** SSH port. Port 22 uses the bare hostname; other ports use `[hostname]:port`. */
    port?: number
    /** Store one independently salted HMAC-SHA1 hostname for each key. */
    hashHostname?: boolean
}

interface KnownHostEntry {
    readonly marker?: KnownHostMarker
    readonly hosts: readonly string[]
    readonly keyType: string
    readonly keyBlob: Buffer
    readonly key?: PublicKey
    readonly suffix: string
    readonly line: number
}

interface SourceLine {
    readonly raw: string
    readonly entry?: KnownHostEntry
}

interface KnownHostReplacementKey {
    readonly keyType: string
    readonly keyBlob: Buffer
    readonly comment: string | undefined
}

export class KnownHostsError extends Error {
    readonly status: Exclude<KnownHostStatus, "trusted">
    readonly line?: number

    constructor(result: KnownHostCheckResult, host: string) {
        if (result.status === "trusted") {
            throw new TypeError("A trusted known-host result is not an error")
        }
        const description =
            result.status === "revoked"
                ? "is revoked"
                : result.status === "changed"
                  ? "does not match the known host key"
                  : "is not present in known hosts"
        super(`SSH host key for ${host} ${description}`)
        this.name = "KnownHostsError"
        this.status = result.status
        this.line = result.line
    }
}

export default class KnownHosts {
    private lines: SourceLine[]
    private readonly path?: string
    private update = Promise.resolve()

    private constructor(lines: SourceLine[], path?: string) {
        this.lines = lines
        this.path = path
    }

    static parse(content: string | Buffer): KnownHosts {
        return new KnownHosts(parseKnownHosts(content))
    }

    static async load(path: string): Promise<KnownHosts> {
        let content = ""
        try {
            content = await readFile(path, "utf8")
        } catch (error) {
            if (!isNodeError(error) || error.code !== "ENOENT") throw error
        }
        return new KnownHosts(parseKnownHosts(content), path)
    }

    check(hostname: string, key: PublicKey | Buffer, port = 22): KnownHostCheckResult {
        const host = formatKnownHost(hostname, port)
        const presented = Buffer.isBuffer(key) ? PublicKey.parse(key) : key
        const certificate =
            presented.data.algorithm instanceof SSHCertificatePublicKey
                ? presented.data.algorithm
                : undefined
        const matching = this.lines
            .map(({ entry }) => entry)
            .filter((entry): entry is KnownHostEntry => entry !== undefined)
            .filter((entry) => matchesHostList(entry.hosts, host))

        for (const entry of matching) {
            if (
                entry.marker === "revoked" &&
                (entry.keyBlob.equals(presented.serialize()) ||
                    (certificate &&
                        entry.keyBlob.equals(certificate.data.signatureKey.serialize())))
            ) {
                return { status: "revoked", line: entry.line, key: entry.key }
            }
        }

        for (const entry of matching) {
            if (entry.marker === undefined && entry.keyBlob.equals(presented.serialize())) {
                return { status: "trusted", line: entry.line, key: entry.key }
            }
            if (
                entry.marker === "cert-authority" &&
                certificate !== undefined &&
                entry.keyBlob.equals(certificate.data.signatureKey.serialize()) &&
                certificate.verifyHostCertificate(hostname)
            ) {
                return { status: "trusted", line: entry.line, key: entry.key }
            }
        }

        const conflict = matching.find((entry) => entry.marker !== "revoked")
        return conflict
            ? { status: "changed", line: conflict.line, key: conflict.key }
            : { status: "unknown" }
    }

    verifier(hostname: string, port = 22): ClientHostVerifier {
        const host = formatKnownHost(hostname, port)
        return (serializedKey) => {
            if (!Buffer.isBuffer(serializedKey)) {
                throw new TypeError("Known-hosts verification requires the raw serialized host key")
            }
            const result = this.check(hostname, serializedKey, port)
            if (result.status !== "trusted") throw new KnownHostsError(result, host)
            return true
        }
    }

    async replaceHostKeys(
        hostname: string,
        keys: readonly (PublicKey | string | Buffer)[],
        options: KnownHostsReplaceOptions = {},
    ): Promise<void> {
        if (!Array.isArray(keys)) {
            throw new TypeError("Known-host replacement keys must be an array")
        }
        if (!isPlainConfigurationObject(options)) {
            throw new TypeError("Known-host replacement options must be an object")
        }
        const host = formatKnownHost(hostname, options.port ?? 22)
        const hashHostname = options.hashHostname ?? false
        if (typeof hashHostname !== "boolean") {
            throw new TypeError("Known-host hashHostname option must be a boolean")
        }
        const replacementKeys = keys.map(snapshotReplacementKey)
        const operation = this.update.then(() =>
            this.performReplace(host, replacementKeys, hashHostname),
        )
        this.update = operation.catch(() => undefined)
        return operation
    }

    toString(): string {
        if (this.lines.length === 0) return ""
        return `${this.lines.map(({ raw }) => raw).join("\n")}\n`
    }

    private async performReplace(
        host: string,
        keys: readonly KnownHostReplacementKey[],
        hashHostname: boolean,
    ): Promise<void> {
        if (this.path) {
            let latest = ""
            try {
                latest = await readFile(this.path, "utf8")
            } catch (error) {
                if (!isNodeError(error) || error.code !== "ENOENT") throw error
            }
            this.lines = parseKnownHosts(latest)
        }

        const retained: string[] = []
        for (const line of this.lines) {
            const entry = line.entry
            if (!entry || entry.marker !== undefined) {
                retained.push(line.raw)
                continue
            }
            const hosts = entry.hosts.filter((candidate) => !isReplaceableHost(candidate, host))
            if (hosts.length === entry.hosts.length) {
                retained.push(line.raw)
            } else if (hosts.length > 0) {
                retained.push(
                    `${hosts.join(",")} ${entry.keyType} ${entry.keyBlob.toString("base64")}${entry.suffix}`,
                )
            }
        }

        for (const key of keys) {
            const storedHost = hashHostname ? hashKnownHost(host) : host
            retained.push(
                `${storedHost} ${key.keyType} ${key.keyBlob.toString("base64")}${
                    key.comment ? ` ${key.comment}` : ""
                }`,
            )
        }

        const content = retained.length === 0 ? "" : `${retained.join("\n")}\n`
        const nextLines = parseKnownHosts(content)
        if (this.path) await atomicWrite(this.path, content)
        this.lines = nextLines
    }
}

function parseKnownHosts(content: string | Buffer): SourceLine[] {
    if (typeof content !== "string" && !Buffer.isBuffer(content)) {
        throw new TypeError("Known-hosts data must be a string or buffer")
    }
    const length = Buffer.isBuffer(content) ? content.length : Buffer.byteLength(content, "utf8")
    if (length > MAX_KNOWN_HOSTS_LENGTH) {
        throw new Error("Known-hosts data exceeds the maximum length")
    }
    const text = Buffer.isBuffer(content)
        ? decodeSSHUTF8(content, "Known-hosts data")
        : (encodeSSHUTF8(content, "Known-hosts data"), content)
    if (text.includes("\0")) throw new Error("Known-hosts data contains NUL")
    if (/\r(?!\n)/u.test(text)) throw new Error("Known-hosts data contains a bare carriage return")
    const rawLines = text.split(/\r?\n/u)
    if (rawLines.at(-1) === "") rawLines.pop()
    return rawLines.map((raw, index) => {
        if (Buffer.byteLength(raw, "utf8") > MAX_KNOWN_HOSTS_LINE_LENGTH) {
            throw new Error(`Known-hosts line ${index + 1} exceeds the maximum length`)
        }
        return { raw, entry: parseKnownHostLine(raw, index + 1) }
    })
}

function parseKnownHostLine(raw: string, line: number): KnownHostEntry | undefined {
    const trimmed = raw.trim()
    if (trimmed === "" || trimmed.startsWith("#")) return undefined
    const fields = trimmed.match(/\S+/gu) ?? []
    let field = 0
    let marker: KnownHostMarker | undefined
    if (fields[field]?.startsWith("@")) {
        if (fields[field] !== "@cert-authority" && fields[field] !== "@revoked") {
            throw new Error(`Unsupported known-hosts marker on line ${line}`)
        }
        marker = fields[field].slice(1) as KnownHostMarker
        field++
    }
    if (fields.length - field < 3) throw new Error(`Invalid known-hosts entry on line ${line}`)
    const hosts = fields[field++].split(",")
    if (hosts.some((host) => host.length === 0)) {
        throw new Error(`Empty known-hosts pattern on line ${line}`)
    }
    if (hosts.some((host) => host.startsWith("|")) && hosts.length !== 1) {
        throw new Error(`Hashed known host must be the only pattern on line ${line}`)
    }
    for (const host of hosts) validateHostPattern(host, line)

    const keyType = fields[field++]
    encodeSSHName(keyType, `Known-hosts key type on line ${line}`)
    const encoded = fields[field++]
    if (!/^[A-Za-z0-9+/]+={0,2}$/u.test(encoded) || encoded.length % 4 === 1) {
        throw new Error(`Invalid known-hosts key encoding on line ${line}`)
    }
    const keyBlob = Buffer.from(encoded, "base64")
    if (keyBlob.toString("base64") !== encoded.padEnd(Math.ceil(encoded.length / 4) * 4, "=")) {
        throw new Error(`Non-canonical known-hosts key encoding on line ${line}`)
    }
    let embeddedType: Buffer
    try {
        ;[embeddedType] = readNextBuffer(keyBlob)
    } catch (error) {
        throw new Error(`Invalid known-hosts key on line ${line}`, { cause: error })
    }
    if (decodeSSHName(embeddedType, `Known-hosts key type on line ${line}`) !== keyType) {
        throw new Error(`Known-hosts key type mismatch on line ${line}`)
    }
    let key: PublicKey | undefined
    try {
        key = PublicKey.parse(keyBlob)
    } catch (error) {
        // Preserve syntactically valid algorithms that this library cannot yet interpret.
        if (!(error instanceof Error) || !error.message.startsWith("Unsupported algorithm:")) {
            throw new Error(`Invalid known-hosts key on line ${line}`, { cause: error })
        }
    }
    const keyEnd = ordinalEnd(trimmed, field)
    return {
        marker,
        hosts,
        keyType,
        keyBlob,
        key,
        suffix: trimmed.slice(keyEnd),
        line,
    }
}

function ordinalEnd(value: string, count: number): number {
    const matcher = /\S+/gu
    let match: RegExpExecArray | null = null
    for (let index = 0; index < count; index++) match = matcher.exec(value)
    return match ? match.index + match[0].length : value.length
}

function validateHostPattern(pattern: string, line: number): void {
    if (pattern.startsWith("|")) {
        const match = /^\|1\|([^|]+)\|([^|]+)$/u.exec(pattern)
        if (!match) throw new Error(`Unsupported hashed known host on line ${line}`)
        const salt = decodeHashPart(match[1], line)
        const digest = decodeHashPart(match[2], line)
        if (salt.length !== 20 || digest.length !== 20) {
            throw new Error(`Invalid hashed known host on line ${line}`)
        }
        return
    }
    const plain = pattern.startsWith("!") ? pattern.slice(1) : pattern
    if (plain.length === 0) throw new Error(`Empty negated known-hosts pattern on line ${line}`)
    if (/[\s,]/u.test(pattern)) throw new Error(`Invalid known-hosts pattern on line ${line}`)
    if (Buffer.byteLength(plain, "utf8") > MAX_HOST_PATTERN_LENGTH) {
        throw new Error(
            `Known-hosts pattern exceeds ${MAX_HOST_PATTERN_LENGTH} bytes on line ${line}`,
        )
    }
}

function decodeHashPart(value: string, line: number): Buffer {
    if (!/^[A-Za-z0-9+/]+={0,2}$/u.test(value) || value.length % 4 === 1) {
        throw new Error(`Invalid hashed known host on line ${line}`)
    }
    const decoded = Buffer.from(value, "base64")
    if (decoded.toString("base64") !== value.padEnd(Math.ceil(value.length / 4) * 4, "=")) {
        throw new Error(`Invalid hashed known host on line ${line}`)
    }
    return decoded
}

function matchesHostList(patterns: readonly string[], host: string): boolean {
    let positive = false
    for (const candidate of patterns) {
        const negated = candidate.startsWith("!")
        const pattern = negated ? candidate.slice(1) : candidate
        if (!matchesHost(pattern, host)) continue
        if (negated) return false
        positive = true
    }
    return positive
}

function matchesHost(pattern: string, host: string): boolean {
    if (pattern.startsWith("|")) {
        const [, , encodedSalt, encodedDigest] = pattern.split("|")
        const actual = createHmac("sha1", Buffer.from(encodedSalt, "base64")).update(host).digest()
        const expected = Buffer.from(encodedDigest, "base64")
        return actual.length === expected.length && timingSafeEqual(actual, expected)
    }
    return matchesWildcardBytes(pattern, host, true)
}

function formatKnownHost(hostname: string, port: number): string {
    if (hostname.length === 0 || /[\0\s,]/u.test(hostname)) {
        throw new TypeError("SSH hostname is invalid for known-hosts matching")
    }
    if (!Number.isInteger(port) || port < 1 || port > 65_535) {
        throw new RangeError("SSH port must be an integer between 1 and 65535")
    }
    const normalized = asciiLowercaseBytes(encodeSSHUTF8(hostname, "SSH hostname")).toString("utf8")
    const formatted =
        port === 22
            ? normalized
            : `[${
                  normalized.startsWith("[") && normalized.endsWith("]")
                      ? normalized.slice(1, -1)
                      : normalized
              }]:${port}`
    if (Buffer.byteLength(formatted, "utf8") > MAX_HOST_PATTERN_LENGTH) {
        throw new RangeError(`SSH hostname exceeds ${MAX_HOST_PATTERN_LENGTH} bytes`)
    }
    return formatted
}

function hashKnownHost(host: string): string {
    const salt = randomBytes(20)
    const digest = createHmac("sha1", salt).update(host).digest()
    return `|1|${salt.toString("base64")}|${digest.toString("base64")}`
}

function isReplaceableHost(pattern: string, host: string): boolean {
    if (pattern.startsWith("|")) return matchesHost(pattern, host)
    if (pattern.startsWith("!") || pattern.includes("*") || pattern.includes("?")) return false
    return asciiLowercaseBytes(Buffer.from(pattern, "utf8")).equals(
        asciiLowercaseBytes(Buffer.from(host, "utf8")),
    )
}

function normalizePublicKey(key: PublicKey | string | Buffer): PublicKey {
    if (key instanceof PublicKey) return key
    const parsed = parseKey(key)
    if (!(parsed instanceof PublicKey)) throw new TypeError("Known hosts only accepts public keys")
    return parsed
}

function snapshotReplacementKey(key: PublicKey | string | Buffer): KnownHostReplacementKey {
    const publicKey = normalizePublicKey(key)
    const comment = publicKey.data.comment
    if (comment !== undefined) {
        if (typeof comment !== "string") {
            throw new TypeError("Known-host key comment must be a string")
        }
        encodeSSHKeyComment(comment, "Known-host key comment")
    }
    const keyBlob = Buffer.from(publicKey.serialize())
    const keyType = PublicKey.parse(keyBlob).data.alg
    return Object.freeze({ keyType, keyBlob, comment })
}

async function atomicWrite(path: string, content: string): Promise<void> {
    let mode = 0o600
    try {
        mode = (await stat(path)).mode & 0o777
    } catch (error) {
        if (!isNodeError(error) || error.code !== "ENOENT") throw error
    }
    const temporary = join(
        dirname(path),
        `.${basename(path)}.${process.pid}.${randomBytes(8).toString("hex")}`,
    )
    let published = false
    try {
        const file = await open(temporary, "wx", mode)
        try {
            await file.writeFile(content, "utf8")
            await file.chmod(mode)
            await file.sync()
        } finally {
            await file.close()
        }
        await rename(temporary, path)
        published = true
    } finally {
        if (!published) await rm(temporary, { force: true })
    }
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
    return error instanceof Error && "code" in error
}
