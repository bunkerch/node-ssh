import { serializeBuffer, serializeUint8 } from "./utils/Buffer.js"
import { encodeSSHName } from "./utils/SSHName.js"
import { encodeSSHLanguageTag, encodeSSHUTF8 } from "./utils/SSHText.js"

export const GSSAPI_WITH_MIC = "gssapi-with-mic"
export const KERBEROS_V5_GSSAPI_OID = Buffer.from("06092a864886f712010202", "hex")

export interface GSSAPIContextStep {
    /** Whether context establishment completed after processing this token. */
    complete: boolean
    /** Required on completion; whether per-message integrity is available. */
    integrity?: boolean
    /** Non-empty token to send to the peer before the next step or final acknowledgement. */
    token?: Buffer
    /** Mechanism-defined authenticated peer identity, available to server authorization policy. */
    peerIdentity?: unknown
    /** Mechanism-defined delegated credentials, when delegation was requested and granted. */
    delegatedCredentials?: unknown
}

export interface GSSAPIClientContext {
    step(inputToken?: Buffer): GSSAPIContextStep | Promise<GSSAPIContextStep>
    getMIC(message: Buffer): Buffer | Promise<Buffer>
    close?(): void | Promise<void>
}

export interface GSSAPIServerContext {
    step(inputToken: Buffer): GSSAPIContextStep | Promise<GSSAPIContextStep>
    verifyMIC(message: Buffer, mic: Buffer): boolean | Promise<boolean>
    close?(): void | Promise<void>
}

export interface GSSAPIClientContextOptions {
    hostname: string
    username: string
    service: string
    delegateCredentials: boolean
}

export interface GSSAPIServerContextOptions {
    username: string
    service: string
    remoteAddress?: string
    remotePort?: number
}

export interface GSSAPIClientMechanism {
    /** Complete ASN.1 DER encoding of the GSS-API mechanism object identifier. */
    oid: Buffer
    createContext(
        options: Readonly<GSSAPIClientContextOptions>,
    ): GSSAPIClientContext | Promise<GSSAPIClientContext>
}

export interface GSSAPIServerMechanism {
    /** Complete ASN.1 DER encoding of the GSS-API mechanism object identifier. */
    oid: Buffer
    createContext(
        options: Readonly<GSSAPIServerContextOptions>,
    ): GSSAPIServerContext | Promise<GSSAPIServerContext>
}

export interface GSSAPIErrorOptions {
    majorStatus: number
    minorStatus: number
    message?: string
    languageTag?: string
    token?: Buffer
}

/** A mechanism error whose RFC 4462 status and optional error token may be sent to the peer. */
export class GSSAPIError extends Error {
    readonly majorStatus: number
    readonly minorStatus: number
    readonly languageTag: string
    readonly token?: Buffer

    constructor(options: GSSAPIErrorOptions) {
        super(options.message ?? "GSS-API context establishment failed")
        this.name = "GSSAPIError"
        assertUint32(options.majorStatus, "GSS-API major status")
        assertUint32(options.minorStatus, "GSS-API minor status")
        encodeSSHUTF8(this.message, "GSS-API error message")
        encodeSSHLanguageTag(options.languageTag ?? "")
        this.majorStatus = options.majorStatus
        this.minorStatus = options.minorStatus
        this.languageTag = options.languageTag ?? ""
        this.token = options.token === undefined ? undefined : ownedNonemptyBuffer(options.token)
    }
}

/** Validate and copy a complete ASN.1 DER object-identifier encoding. */
export function normalizeGSSAPIOID(oid: Buffer): Buffer {
    if (!Buffer.isBuffer(oid)) throw new TypeError("GSS-API mechanism OID must be a buffer")
    if (oid.length < 3 || oid[0] !== 0x06) {
        throw new TypeError("GSS-API mechanism OID must be an ASN.1 DER object identifier")
    }

    let offset = 2
    let contentLength = oid[1]
    if ((contentLength & 0x80) !== 0) {
        const lengthOctets = contentLength & 0x7f
        if (lengthOctets < 1 || lengthOctets > 2 || oid.length < 2 + lengthOctets) {
            throw new TypeError("Invalid ASN.1 DER object-identifier length")
        }
        if (oid[2] === 0) throw new TypeError("Non-canonical ASN.1 DER object-identifier length")
        contentLength = 0
        for (let index = 0; index < lengthOctets; index++) {
            contentLength = contentLength * 256 + oid[2 + index]
        }
        if (contentLength < 128 || (contentLength < 256 && lengthOctets !== 1)) {
            throw new TypeError("Non-canonical ASN.1 DER object-identifier length")
        }
        offset += lengthOctets
    }
    if (contentLength < 1 || offset + contentLength !== oid.length) {
        throw new TypeError("Invalid ASN.1 DER object-identifier length")
    }

    const end = offset + contentLength
    while (offset < end) {
        if (oid[offset] === 0x80) {
            throw new TypeError("Non-canonical ASN.1 DER object-identifier component")
        }
        do {
            if (offset >= end) {
                throw new TypeError("Truncated ASN.1 DER object-identifier component")
            }
        } while ((oid[offset++] & 0x80) !== 0)
    }
    return Buffer.from(oid)
}

export function normalizeGSSAPIClientMechanisms(
    mechanisms: readonly GSSAPIClientMechanism[],
): readonly GSSAPIClientMechanism[] {
    return normalizeMechanisms(mechanisms, "client") as readonly GSSAPIClientMechanism[]
}

export function normalizeGSSAPIServerMechanisms(
    mechanisms: readonly GSSAPIServerMechanism[],
): readonly GSSAPIServerMechanism[] {
    return normalizeMechanisms(mechanisms, "server") as readonly GSSAPIServerMechanism[]
}

export function normalizeGSSAPIContextStep(step: GSSAPIContextStep): Readonly<GSSAPIContextStep> {
    if (typeof step !== "object" || step === null || typeof step.complete !== "boolean") {
        throw new TypeError("GSS-API context step must declare whether it is complete")
    }
    if (step.complete && typeof step.integrity !== "boolean") {
        throw new TypeError("A complete GSS-API context step must declare integrity availability")
    }
    if (!step.complete && step.integrity !== undefined) {
        throw new TypeError("An incomplete GSS-API context step must not declare integrity")
    }
    const token =
        step.token === undefined || step.token.length === 0
            ? undefined
            : ownedNonemptyBuffer(step.token)
    return Object.freeze({
        complete: step.complete,
        integrity: step.integrity,
        token,
        peerIdentity: step.peerIdentity,
        delegatedCredentials: step.delegatedCredentials,
    })
}

export function normalizeGSSAPIToken(token: Buffer, name = "GSS-API token"): Buffer {
    if (!Buffer.isBuffer(token) || token.length === 0) {
        throw new TypeError(`${name} must be a non-empty buffer`)
    }
    return Buffer.from(token)
}

/** Build the exact RFC 4462 user-authentication MIC input. */
export function buildGSSAPIUserAuthMIC(
    sessionIdentifier: Buffer,
    username: string,
    service: string,
): Buffer {
    if (!Buffer.isBuffer(sessionIdentifier) || sessionIdentifier.length === 0) {
        throw new TypeError("SSH session identifier must be a non-empty buffer")
    }
    return Buffer.concat([
        serializeBuffer(Buffer.from(sessionIdentifier)),
        serializeUint8(50),
        serializeBuffer(encodeSSHUTF8(username, "SSH username")),
        serializeBuffer(encodeSSHName(service, "SSH service name")),
        serializeBuffer(Buffer.from(GSSAPI_WITH_MIC, "ascii")),
    ])
}

async function closeGSSAPIContext(context: { close?(): void | Promise<void> }): Promise<void> {
    await context.close?.()
}

export { closeGSSAPIContext }

function normalizeMechanisms(
    mechanisms: readonly (GSSAPIClientMechanism | GSSAPIServerMechanism)[],
    role: "client" | "server",
): readonly (GSSAPIClientMechanism | GSSAPIServerMechanism)[] {
    if (!Array.isArray(mechanisms)) {
        throw new TypeError(`SSH ${role} GSS-API mechanisms must be an array`)
    }
    const normalized = mechanisms.map((mechanism) => {
        if (
            typeof mechanism !== "object" ||
            mechanism === null ||
            typeof mechanism.createContext !== "function"
        ) {
            throw new TypeError(`Invalid SSH ${role} GSS-API mechanism`)
        }
        return Object.freeze({
            oid: normalizeGSSAPIOID(mechanism.oid),
            createContext: mechanism.createContext.bind(mechanism),
        }) as GSSAPIClientMechanism | GSSAPIServerMechanism
    })
    for (let index = 0; index < normalized.length; index++) {
        if (normalized.slice(0, index).some(({ oid }) => oid.equals(normalized[index].oid))) {
            throw new TypeError(`Duplicate SSH ${role} GSS-API mechanism OID`)
        }
    }
    return Object.freeze(normalized)
}

function ownedNonemptyBuffer(value: Buffer): Buffer {
    if (!Buffer.isBuffer(value) || value.length === 0) {
        throw new TypeError("GSS-API token must be a non-empty buffer")
    }
    return Buffer.from(value)
}

function assertUint32(value: number, name: string): void {
    if (!Number.isInteger(value) || value < 0 || value > 0xffff_ffff) {
        throw new RangeError(`${name} must be a uint32`)
    }
}
