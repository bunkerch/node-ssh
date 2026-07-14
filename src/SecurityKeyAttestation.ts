import { readFile } from "node:fs/promises"

import { readNextBuffer, readNextUint32, serializeBuffer, serializeUint32 } from "./utils/Buffer.js"
import { decodeSSHName } from "./utils/SSHName.js"

export type SecurityKeyAttestationFormat = "ssh-sk-attest-v00" | "ssh-sk-attest-v01"

const VERSION_0: SecurityKeyAttestationFormat = "ssh-sk-attest-v00"
const VERSION_1: SecurityKeyAttestationFormat = "ssh-sk-attest-v01"
const MAXIMUM_ATTESTATION_LENGTH = 16 * 1024 * 1024

interface ParsedSecurityKeyAttestation {
    readonly format: SecurityKeyAttestationFormat
    readonly certificate: Buffer
    readonly enrollmentSignature: Buffer
    readonly authenticatorData?: Buffer
    readonly flags: number
    readonly reserved: Buffer
}

/** Opaque enrollment evidence stored in the published security-key attestation format. */
export default class SecurityKeyAttestation {
    readonly format: SecurityKeyAttestationFormat
    readonly flags: number
    readonly #certificate: Buffer
    readonly #enrollmentSignature: Buffer
    readonly #authenticatorData?: Buffer
    readonly #reserved: Buffer

    private constructor(parsed: ParsedSecurityKeyAttestation) {
        this.format = parsed.format
        this.flags = parsed.flags
        this.#certificate = parsed.certificate
        this.#enrollmentSignature = parsed.enrollmentSignature
        this.#authenticatorData = parsed.authenticatorData
        this.#reserved = parsed.reserved
    }

    get certificate(): Buffer {
        return Buffer.from(this.#certificate)
    }

    get enrollmentSignature(): Buffer {
        return Buffer.from(this.#enrollmentSignature)
    }

    get authenticatorData(): Buffer | undefined {
        return this.#authenticatorData && Buffer.from(this.#authenticatorData)
    }

    get reserved(): Buffer {
        return Buffer.from(this.#reserved)
    }

    static parse(content: Buffer): SecurityKeyAttestation {
        if (!Buffer.isBuffer(content)) {
            throw new TypeError("Security-key attestation must be a buffer")
        }
        if (content.length > MAXIMUM_ATTESTATION_LENGTH) {
            throw new RangeError("Security-key attestation exceeds the maximum length")
        }
        try {
            return new SecurityKeyAttestation(parseAttestation(Buffer.from(content)))
        } catch (error) {
            const reason = error instanceof Error ? error.message : String(error)
            throw new Error(`Invalid security-key attestation: ${reason}`, { cause: error })
        }
    }

    static async load(path: string): Promise<SecurityKeyAttestation> {
        return SecurityKeyAttestation.parse(await readFile(path))
    }

    serialize(): Buffer {
        return Buffer.concat([
            serializeBuffer(Buffer.from(this.format, "ascii")),
            serializeBuffer(this.#certificate),
            serializeBuffer(this.#enrollmentSignature),
            ...(this.#authenticatorData === undefined
                ? []
                : [serializeBuffer(this.#authenticatorData)]),
            serializeUint32(this.flags),
            serializeBuffer(this.#reserved),
        ])
    }
}

function parseAttestation(content: Buffer): ParsedSecurityKeyAttestation {
    let formatRaw: Buffer
    let certificate: Buffer
    let enrollmentSignature: Buffer
    ;[formatRaw, content] = readNextBuffer(content)
    const format = decodeSSHName(formatRaw, "security-key attestation format")
    if (format !== VERSION_0 && format !== VERSION_1) {
        throw new Error(`Unsupported security-key attestation format ${format}`)
    }
    ;[certificate, content] = readNextBuffer(content)
    ;[enrollmentSignature, content] = readNextBuffer(content)

    let authenticatorData: Buffer | undefined
    if (format === VERSION_1) {
        ;[authenticatorData, content] = readNextBuffer(content)
    }
    let flags: number
    let reserved: Buffer
    ;[flags, content] = readNextUint32(content)
    ;[reserved, content] = readNextBuffer(content)
    if (content.length !== 0) throw new Error("Security-key attestation has trailing data")

    return {
        format,
        certificate: Buffer.from(certificate),
        enrollmentSignature: Buffer.from(enrollmentSignature),
        ...(authenticatorData === undefined
            ? {}
            : { authenticatorData: Buffer.from(authenticatorData) }),
        flags,
        reserved: Buffer.from(reserved),
    }
}
