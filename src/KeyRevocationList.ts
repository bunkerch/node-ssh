import { createHash } from "node:crypto"
import { readFile } from "node:fs/promises"

import {
    readNextBinaryBoolean,
    readNextBuffer,
    readNextUint8,
    readNextUint32,
    readNextUint64,
} from "./utils/Buffer.js"
import { parseBufferToMpintBuffer } from "./utils/mpint.js"
import PublicKey, { SSHCertificatePublicKey } from "./utils/PublicKey.js"
import EncodedSignature from "./utils/Signature.js"
import { decodeSSHName } from "./utils/SSHName.js"
import { decodeSSHUTF8 } from "./utils/SSHText.js"

const MAGIC = Buffer.from("SSHKRL\n\0", "ascii")
const FORMAT_VERSION = 1
const CERTIFICATE_SECTION = 1
const EXPLICIT_KEY_SECTION = 2
const SHA1_FINGERPRINT_SECTION = 3
const SIGNATURE_SECTION = 4
const SHA256_FINGERPRINT_SECTION = 5
const EXTENSION_SECTION = 0xff
const CERTIFICATE_SERIAL_LIST = 0x20
const CERTIFICATE_SERIAL_RANGE = 0x21
const CERTIFICATE_SERIAL_BITMAP = 0x22
const CERTIFICATE_KEY_ID = 0x23
const CERTIFICATE_EXTENSION = 0x39
const MAX_KEY_REVOCATION_LIST_LENGTH = 16 * 1024 * 1024
const MAX_UINT64 = 0xffffffffffffffffn

interface CertificateRevocations {
    readonly authority?: Buffer
    readonly serials: ReadonlySet<bigint>
    readonly serialRanges: readonly (readonly [bigint, bigint])[]
    readonly serialBitmaps: readonly {
        readonly offset: bigint
        readonly bitmap: Buffer
    }[]
    readonly keyIdentifiers: ReadonlySet<string>
}

interface ParsedKeyRevocationList {
    readonly version: bigint
    readonly generatedAt: bigint
    readonly comment: string
    readonly certificates: readonly CertificateRevocations[]
    readonly explicitKeys: readonly Buffer[]
    readonly sha1Fingerprints: readonly Buffer[]
    readonly sha256Fingerprints: readonly Buffer[]
    readonly signatureKeys: readonly Buffer[]
}

export default class KeyRevocationList {
    /** Monotonic version recorded in the KRL header. Rollback enforcement is application policy. */
    readonly version: bigint
    /** KRL generation time as unsigned Unix seconds. */
    readonly generatedAt: bigint
    /** Human-readable KRL header comment. */
    readonly comment: string
    private readonly certificates: readonly CertificateRevocations[]
    private readonly explicitKeys: readonly Buffer[]
    private readonly sha1Fingerprints: readonly Buffer[]
    private readonly sha256Fingerprints: readonly Buffer[]
    private readonly signatureKeys: readonly Buffer[]

    private constructor(parsed: ParsedKeyRevocationList) {
        this.version = parsed.version
        this.generatedAt = parsed.generatedAt
        this.comment = parsed.comment
        this.certificates = parsed.certificates
        this.explicitKeys = parsed.explicitKeys
        this.sha1Fingerprints = parsed.sha1Fingerprints
        this.sha256Fingerprints = parsed.sha256Fingerprints
        this.signatureKeys = parsed.signatureKeys
    }

    static parse(content: Buffer): KeyRevocationList {
        if (!Buffer.isBuffer(content)) throw new TypeError("Key revocation list must be a buffer")
        if (content.length > MAX_KEY_REVOCATION_LIST_LENGTH) {
            throw new Error("Key revocation list exceeds the maximum length")
        }

        try {
            return new KeyRevocationList(parseKeyRevocationList(Buffer.from(content)))
        } catch (error) {
            const reason = error instanceof Error ? error.message : String(error)
            throw new Error(`Invalid key revocation list: ${reason}`, { cause: error })
        }
    }

    static async load(path: string): Promise<KeyRevocationList> {
        return KeyRevocationList.parse(await readFile(path))
    }

    /** Tests plain keys and all applicable certificate, embedded-key, and authority records. */
    isRevoked(key: PublicKey | Buffer): boolean {
        const publicKey = Buffer.isBuffer(key) ? PublicKey.parse(key) : key
        const algorithm = publicKey.data.algorithm
        if (algorithm instanceof SSHCertificatePublicKey) {
            const authority = algorithm.data.signatureKey.serialize()
            return (
                this.certificates.some(
                    (revocations) =>
                        (revocations.authority === undefined ||
                            revocations.authority.equals(authority)) &&
                        (revocations.serials.has(algorithm.data.serial) ||
                            revocations.serialRanges.some(
                                ([minimum, maximum]) =>
                                    minimum <= algorithm.data.serial &&
                                    algorithm.data.serial <= maximum,
                            ) ||
                            revocations.serialBitmaps.some(({ offset, bitmap }) =>
                                bitmapContainsSerial(offset, bitmap, algorithm.data.serial),
                            ) ||
                            revocations.keyIdentifiers.has(algorithm.data.identifier)),
                ) ||
                this.isPlainKeyRevoked(algorithm.publicKey) ||
                this.isPlainKeyRevoked(algorithm.data.signatureKey)
            )
        }
        return this.isPlainKeyRevoked(publicKey)
    }

    /** Returns whether an embedded, cryptographically verified signature uses this exact key. */
    isSignedBy(key: PublicKey | Buffer): boolean {
        const serialized = (Buffer.isBuffer(key) ? PublicKey.parse(key) : key).serialize()
        return this.signatureKeys.some((signer) => signer.equals(serialized))
    }

    private isPlainKeyRevoked(publicKey: PublicKey): boolean {
        const serialized = publicKey.serialize()
        return (
            this.explicitKeys.some((revoked) => revoked.equals(serialized)) ||
            containsFingerprint(this.sha1Fingerprints, serialized, "sha1") ||
            containsFingerprint(this.sha256Fingerprints, serialized, "sha256")
        )
    }
}

function parseKeyRevocationList(content: Buffer): ParsedKeyRevocationList {
    if (content.length < MAGIC.length || !content.subarray(0, MAGIC.length).equals(MAGIC)) {
        throw new Error("Invalid key revocation list magic")
    }
    let remaining = content.subarray(MAGIC.length)
    const [formatVersion, afterFormatVersion] = readNextUint32(remaining)
    remaining = afterFormatVersion
    if (formatVersion !== FORMAT_VERSION) {
        throw new Error(`Unsupported key revocation list format version ${formatVersion}`)
    }
    const [version, afterVersion] = readNextUint64(remaining)
    const [generatedAt, afterGeneratedAt] = readNextUint64(afterVersion)
    const [flags, afterFlags] = readNextUint64(afterGeneratedAt)
    remaining = afterFlags
    if (flags !== 0n) throw new Error("Unsupported key revocation list flags")
    ;[, remaining] = readNextBuffer(remaining)
    const [comment, afterComment] = readNextBuffer(remaining)
    remaining = afterComment

    const certificates: CertificateRevocations[] = []
    const explicitKeys: Buffer[] = []
    const sha1Fingerprints: Buffer[] = []
    const sha256Fingerprints: Buffer[] = []
    const signatureKeys: Buffer[] = []
    let signaturesStarted = false
    while (remaining.length > 0) {
        let sectionType: number
        ;[sectionType, remaining] = readNextUint8(remaining)
        if (sectionType === SIGNATURE_SECTION) {
            signaturesStarted = true
            let signatureKeyRaw: Buffer
            ;[signatureKeyRaw, remaining] = readNextBuffer(remaining)
            const signedLength = content.length - remaining.length
            let signatureRaw: Buffer
            ;[signatureRaw, remaining] = readNextBuffer(remaining)
            const signatureKey = PublicKey.parse(signatureKeyRaw)
            const signature = EncodedSignature.parse(signatureRaw)
            if (!signatureKey.verifySignature(content.subarray(0, signedLength), signature)) {
                throw new Error("Invalid key revocation list signature")
            }
            signatureKeys.push(Buffer.from(signatureKeyRaw))
            continue
        }
        if (signaturesStarted) {
            throw new Error("Key revocation list signature sections must be final")
        }
        let section: Buffer
        ;[section, remaining] = readNextBuffer(remaining)
        if (sectionType === CERTIFICATE_SECTION) {
            certificates.push(parseCertificateRevocations(section))
        } else if (sectionType === EXPLICIT_KEY_SECTION) {
            parseExplicitKeys(section, explicitKeys)
        } else if (sectionType === SHA1_FINGERPRINT_SECTION) {
            parseFingerprints(section, 20, sha1Fingerprints)
        } else if (sectionType === SHA256_FINGERPRINT_SECTION) {
            parseFingerprints(section, 32, sha256Fingerprints)
        } else if (sectionType === EXTENSION_SECTION) {
            parseExtension(section)
        } else {
            throw new Error(`Unsupported key revocation list section ${sectionType}`)
        }
    }
    return {
        version,
        generatedAt,
        comment: decodeCString(comment, "key revocation list comment"),
        certificates,
        explicitKeys,
        sha1Fingerprints,
        sha256Fingerprints,
        signatureKeys,
    }
}

function parseExtension(data: Buffer): void {
    let name: Buffer
    let critical: boolean
    ;[name, data] = readNextBuffer(data)
    ;[critical, data] = readNextBinaryBoolean(data)
    ;[, data] = readNextBuffer(data)
    if (data.length !== 0) throw new Error("Unexpected key revocation extension data")
    const decodedName = decodeSSHName(name, "key revocation extension name")
    if (critical) throw new Error(`Unsupported critical extension ${decodedName}`)
}

function parseCertificateRevocations(section: Buffer): CertificateRevocations {
    let authorityRaw: Buffer
    ;[authorityRaw, section] = readNextBuffer(section)
    const authority =
        authorityRaw.length === 0 ? undefined : validatePlainPublicKey(authorityRaw, "authority")
    ;[, section] = readNextBuffer(section)
    const serials = new Set<bigint>()
    const serialRanges: [bigint, bigint][] = []
    const serialBitmaps: { offset: bigint; bitmap: Buffer }[] = []
    const keyIdentifiers = new Set<string>()
    if (section.length === 0) throw new Error("Certificate revocation section is empty")
    while (section.length > 0) {
        let type: number
        let data: Buffer
        ;[type, section] = readNextUint8(section)
        ;[data, section] = readNextBuffer(section)
        if (type === CERTIFICATE_SERIAL_LIST) {
            if (data.length === 0 || data.length % 8 !== 0) {
                throw new Error("Invalid revoked certificate serial list")
            }
            while (data.length > 0) {
                let serial: bigint
                ;[serial, data] = readNextUint64(data)
                if (serial === 0n) throw new Error("Revoked certificate serial zero is invalid")
                serials.add(serial)
            }
        } else if (type === CERTIFICATE_SERIAL_RANGE) {
            let minimum: bigint
            let maximum: bigint
            ;[minimum, data] = readNextUint64(data)
            ;[maximum, data] = readNextUint64(data)
            if (data.length !== 0 || minimum === 0n || minimum > maximum) {
                throw new Error("Invalid revoked certificate serial range")
            }
            serialRanges.push([minimum, maximum])
        } else if (type === CERTIFICATE_SERIAL_BITMAP) {
            let offset: bigint
            let bitmap: Buffer
            ;[offset, data] = readNextUint64(data)
            ;[bitmap, data] = readNextBuffer(data)
            if (data.length !== 0) throw new Error("Invalid revoked certificate serial bitmap")
            parseBufferToMpintBuffer(bitmap)
            const normalized = Buffer.from(bitmap[0] === 0 ? bitmap.subarray(1) : bitmap)
            if (offset === 0n && normalized.length > 0 && (normalized.at(-1)! & 1) !== 0) {
                throw new Error("Revoked certificate serial zero is invalid")
            }
            const highestBit = highestSetBit(normalized)
            if (highestBit !== undefined && offset + BigInt(highestBit) > MAX_UINT64) {
                throw new Error("Revoked certificate serial bitmap wraps the serial space")
            }
            serialBitmaps.push({
                offset,
                bitmap: normalized,
            })
        } else if (type === CERTIFICATE_KEY_ID) {
            if (data.length === 0) throw new Error("Revoked certificate key ID section is empty")
            while (data.length > 0) {
                let identifier: Buffer
                ;[identifier, data] = readNextBuffer(data)
                keyIdentifiers.add(decodeCString(identifier, "revoked certificate key ID"))
            }
        } else if (type === CERTIFICATE_EXTENSION) {
            parseExtension(data)
        } else {
            throw new Error(`Unsupported certificate revocation subsection ${type}`)
        }
    }
    return { authority, serials, serialRanges, serialBitmaps, keyIdentifiers }
}

function decodeCString(value: Buffer, field: string): string {
    if (value.includes(0)) throw new Error(`${field} contains NUL`)
    return decodeSSHUTF8(value, field)
}

function highestSetBit(bitmap: Buffer): number | undefined {
    const index = bitmap.findIndex((byte) => byte !== 0)
    if (index === -1) return undefined
    return (bitmap.length - 1 - index) * 8 + Math.floor(Math.log2(bitmap[index]))
}

function bitmapContainsSerial(offset: bigint, bitmap: Buffer, serial: bigint): boolean {
    if (serial < offset) return false
    const bit = serial - offset
    if (bit >= BigInt(bitmap.length) * 8n) return false
    const byte = bitmap.length - 1 - Number(bit / 8n)
    return (bitmap[byte] & (1 << Number(bit % 8n))) !== 0
}

function parseExplicitKeys(section: Buffer, explicitKeys: Buffer[]): void {
    if (section.length === 0) throw new Error("Explicit key revocation section is empty")
    while (section.length > 0) {
        let serialized: Buffer
        ;[serialized, section] = readNextBuffer(section)
        explicitKeys.push(validatePlainPublicKey(serialized, "explicit key"))
    }
}

function validatePlainPublicKey(serialized: Buffer, field: string): Buffer {
    const key = PublicKey.parse(serialized)
    if (key.data.algorithm instanceof SSHCertificatePublicKey) {
        throw new Error(`Key revocation ${field} contains a certificate`)
    }
    return Buffer.from(serialized)
}

function parseFingerprints(section: Buffer, length: number, fingerprints: Buffer[]): void {
    if (section.length === 0) throw new Error("Key fingerprint revocation section is empty")
    let previous: Buffer | undefined
    while (section.length > 0) {
        let fingerprint: Buffer
        ;[fingerprint, section] = readNextBuffer(section)
        if (fingerprint.length !== length) throw new Error("Invalid revoked key fingerprint length")
        if (previous && Buffer.compare(previous, fingerprint) >= 0) {
            throw new Error("Revoked key fingerprints are not in numeric order")
        }
        previous = fingerprint
        fingerprints.push(Buffer.from(fingerprint))
    }
}

function containsFingerprint(
    fingerprints: readonly Buffer[],
    serialized: Buffer,
    algorithm: "sha1" | "sha256",
): boolean {
    if (fingerprints.length === 0) return false
    const fingerprint = createHash(algorithm).update(serialized).digest()
    return fingerprints.some((revoked) => revoked.equals(fingerprint))
}
