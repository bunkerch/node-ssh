import { createHash, timingSafeEqual } from "node:crypto"

import PublicKey from "./utils/PublicKey.js"

const MAX_RDATA_LENGTH = 65_535

/** DNS SSHFP public-key algorithm numbers assigned by the IANA registry. */
export enum SSHFPAlgorithm {
    RSA = 1,
    DSA = 2,
    ECDSA = 3,
    Ed25519 = 4,
    Ed448 = 6,
}

/** DNS SSHFP fingerprint-type numbers assigned by the IANA registry. */
export enum SSHFPFingerprintType {
    SHA1 = 1,
    SHA256 = 2,
}

export type SSHFPVerificationResult = "match" | "mismatch" | "no-supported-records"

function fingerprintLength(type: number): number | undefined {
    if (type === SSHFPFingerprintType.SHA1) return 20
    if (type === SSHFPFingerprintType.SHA256) return 32
    return undefined
}

function hashName(type: SSHFPFingerprintType): "sha1" | "sha256" {
    return type === SSHFPFingerprintType.SHA256 ? "sha256" : "sha1"
}

function publicKeyAlgorithm(publicKey: PublicKey): SSHFPAlgorithm | undefined {
    switch (publicKey.data.alg) {
        case "ssh-rsa":
            return SSHFPAlgorithm.RSA
        case "ssh-dss":
            return SSHFPAlgorithm.DSA
        case "ecdsa-sha2-nistp256":
        case "ecdsa-sha2-nistp384":
        case "ecdsa-sha2-nistp521":
            return SSHFPAlgorithm.ECDSA
        case "ssh-ed25519":
            return SSHFPAlgorithm.Ed25519
        case "ssh-ed448":
            return SSHFPAlgorithm.Ed448
        default:
            return undefined
    }
}

function validatePublicKey(publicKey: PublicKey): void {
    if (!(publicKey instanceof PublicKey)) {
        throw new TypeError("SSHFP public key must be a PublicKey")
    }
}

/**
 * One SSHFP RDATA value. DNS owner names, TTLs, and DNSSEC validation state are deliberately not
 * part of this value object.
 */
export default class SSHFPRecord {
    readonly algorithm: number
    readonly fingerprintType: number
    readonly #fingerprint: Buffer

    constructor(algorithm: number, fingerprintType: number, fingerprint: Buffer) {
        if (!Number.isInteger(algorithm) || algorithm < 0 || algorithm > 0xff) {
            throw new TypeError("SSHFP algorithm must be an unsigned octet")
        }
        if (!Number.isInteger(fingerprintType) || fingerprintType < 0 || fingerprintType > 0xff) {
            throw new TypeError("SSHFP fingerprint type must be an unsigned octet")
        }
        if (!Buffer.isBuffer(fingerprint)) {
            throw new TypeError("SSHFP fingerprint must be a buffer")
        }
        if (fingerprint.length === 0) {
            throw new Error("SSHFP fingerprint must not be empty")
        }
        if (fingerprint.length > MAX_RDATA_LENGTH - 2) {
            throw new Error("SSHFP fingerprint exceeds the maximum DNS RDATA length")
        }
        const expectedLength = fingerprintLength(fingerprintType)
        if (expectedLength !== undefined && fingerprint.length !== expectedLength) {
            throw new Error(
                `SSHFP fingerprint type ${fingerprintType} requires ${expectedLength} bytes`,
            )
        }

        this.algorithm = algorithm
        this.fingerprintType = fingerprintType
        this.#fingerprint = Buffer.from(fingerprint)
    }

    /** A defensive copy of the opaque fingerprint bytes. */
    get fingerprint(): Buffer {
        return Buffer.from(this.#fingerprint)
    }

    /** Parses the complete binary RDATA of one SSHFP resource record. */
    static parse(rdata: Buffer): SSHFPRecord {
        if (!Buffer.isBuffer(rdata)) throw new TypeError("SSHFP RDATA must be a buffer")
        if (rdata.length > MAX_RDATA_LENGTH) {
            throw new Error("SSHFP RDATA exceeds the maximum DNS RDATA length")
        }
        if (rdata.length < 3) throw new Error("SSHFP RDATA is truncated")
        return new SSHFPRecord(rdata[0], rdata[1], rdata.subarray(2))
    }

    /**
     * Parses the presentation-format RDATA fields, without a DNS owner name, class, TTL, or `SSHFP`
     * mnemonic.
     */
    static parseText(rdata: string): SSHFPRecord {
        if (typeof rdata !== "string") throw new TypeError("SSHFP text RDATA must be a string")
        const match = /^(\d{1,3})\s+(\d{1,3})\s+([0-9a-f]+)$/iu.exec(rdata.trim())
        if (!match) throw new Error("Invalid SSHFP presentation-format RDATA")
        const algorithm = Number(match[1])
        const fingerprintType = Number(match[2])
        const fingerprintHex = match[3]
        if (fingerprintHex.length % 2 !== 0) {
            throw new Error("SSHFP presentation fingerprint must contain complete octets")
        }
        if (fingerprintHex.length > (MAX_RDATA_LENGTH - 2) * 2) {
            throw new Error("SSHFP fingerprint exceeds the maximum DNS RDATA length")
        }
        return new SSHFPRecord(algorithm, fingerprintType, Buffer.from(fingerprintHex, "hex"))
    }

    /** Generates a fingerprint over the exact SSH public-key blob. SHA-256 is the default. */
    static fromPublicKey(
        publicKey: PublicKey,
        fingerprintType: SSHFPFingerprintType = SSHFPFingerprintType.SHA256,
    ): SSHFPRecord {
        validatePublicKey(publicKey)
        if (
            fingerprintType !== SSHFPFingerprintType.SHA1 &&
            fingerprintType !== SSHFPFingerprintType.SHA256
        ) {
            throw new Error(`Unsupported SSHFP fingerprint type ${fingerprintType}`)
        }
        const algorithm = publicKeyAlgorithm(publicKey)
        if (algorithm === undefined) {
            throw new Error(
                `Public key algorithm ${publicKey.data.alg} has no supported SSHFP code`,
            )
        }
        return new SSHFPRecord(
            algorithm,
            fingerprintType,
            createHash(hashName(fingerprintType)).update(publicKey.serialize()).digest(),
        )
    }

    serialize(): Buffer {
        return Buffer.concat([
            Buffer.from([this.algorithm, this.fingerprintType]),
            this.#fingerprint,
        ])
    }

    /** Returns the three presentation-format RDATA fields accepted by DNS zone-file tools. */
    toString(): string {
        return `${this.algorithm} ${this.fingerprintType} ${this.#fingerprint.toString("hex")}`
    }
}

/**
 * Verifies one public key against an authenticated SSHFP RRset.
 *
 * The caller must establish the owner name and DNSSEC authenticity before treating `match` as
 * trust. SHA-256 records take precedence over SHA-1 records as required by RFC 6594.
 */
export function verifySSHFP(
    publicKey: PublicKey,
    records: readonly SSHFPRecord[],
): SSHFPVerificationResult {
    validatePublicKey(publicKey)
    if (!Array.isArray(records)) throw new TypeError("SSHFP records must be an array")
    if (!records.every((record) => record instanceof SSHFPRecord)) {
        throw new TypeError("SSHFP records must contain SSHFPRecord values")
    }

    const algorithm = publicKeyAlgorithm(publicKey)
    if (algorithm === undefined) return "no-supported-records"
    const applicable = records.filter((record) => record.algorithm === algorithm)
    const preferredType = applicable.some(
        (record) => record.fingerprintType === SSHFPFingerprintType.SHA256,
    )
        ? SSHFPFingerprintType.SHA256
        : applicable.some((record) => record.fingerprintType === SSHFPFingerprintType.SHA1)
          ? SSHFPFingerprintType.SHA1
          : undefined
    if (preferredType === undefined) return "no-supported-records"

    const expected = createHash(hashName(preferredType)).update(publicKey.serialize()).digest()
    return applicable.some((record) => {
        if (record.fingerprintType !== preferredType) return false
        const fingerprint = record.fingerprint
        return fingerprint.length === expected.length && timingSafeEqual(fingerprint, expected)
    })
        ? "match"
        : "mismatch"
}
