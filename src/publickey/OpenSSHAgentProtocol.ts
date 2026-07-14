import { serializeBinaryBoolean } from "../utils/BinaryBoolean.js"
import { readNextBinaryBoolean, readNextBuffer, serializeBuffer } from "../utils/Buffer.js"
import PublicKey, { SSHCertificatePublicKey } from "../utils/PublicKey.js"
import EncodedSignature from "../utils/Signature.js"
import { decodeSSHUTF8, encodeSSHUTF8 } from "../utils/SSHText.js"

export const OPENSSH_AGENT_SESSION_BIND = "session-bind@openssh.com"
export const OPENSSH_AGENT_RESTRICT_DESTINATION = "restrict-destination-v00@openssh.com"
export const OPENSSH_AGENT_ASSOCIATED_CERTIFICATES = "associated-certs-v00@openssh.com"
export const MAX_OPENSSH_AGENT_SESSION_IDENTIFIER_LENGTH = 128
export const MAX_OPENSSH_AGENT_SESSION_BINDINGS = 16
export const MAX_OPENSSH_AGENT_DESTINATION_CONSTRAINTS = 1024
export const MAX_OPENSSH_AGENT_ASSOCIATED_CERTIFICATES = 1024

export type OpenSSHAgentDestinationKey = Readonly<{
    publicKey: PublicKey
    certificateAuthority?: boolean
}>

export type OpenSSHAgentDestinationHop = Readonly<{
    hostname: string
    hostKeys: readonly OpenSSHAgentDestinationKey[]
}>

export type OpenSSHAgentDestinationRule = Readonly<{
    /** Undefined identifies the initial hop from the machine running the agent. */
    from?: OpenSSHAgentDestinationHop
    to: Readonly<{
        username?: string
        hostname: string
        hostKeys: readonly OpenSSHAgentDestinationKey[]
    }>
}>

export type OpenSSHAgentDestinationConstraint = Readonly<{
    type: "openssh-restrict-destination"
    destinations: readonly OpenSSHAgentDestinationRule[]
}>

export type OpenSSHAgentAssociatedCertificatesConstraint = Readonly<{
    type: "openssh-associated-certificates"
    certificatesOnly?: boolean
    certificates: readonly PublicKey[]
}>

export type OpenSSHAgentKeyConstraint =
    | OpenSSHAgentDestinationConstraint
    | OpenSSHAgentAssociatedCertificatesConstraint

export type OpenSSHAgentSessionBinding = Readonly<{
    hostKey: PublicKey
    sessionIdentifier: Buffer
    signature: EncodedSignature
    forwarding: boolean
}>

function encodeText(value: string, description: string, allowEmpty: boolean): Buffer {
    const encoded = encodeSSHUTF8(value, description)
    if (!allowEmpty && encoded.length === 0) throw new Error(`${description} must not be empty`)
    if (encoded.includes(0)) throw new Error(`${description} must not contain NUL`)
    return encoded
}

function serializeKeySpecs(keys: readonly OpenSSHAgentDestinationKey[]): Buffer {
    if (!Array.isArray(keys) || keys.length === 0) {
        throw new Error("OpenSSH agent destination hop requires at least one host key")
    }
    return Buffer.concat(
        keys.map((key) => {
            if (typeof key !== "object" || key === null || !(key.publicKey instanceof PublicKey)) {
                throw new TypeError("OpenSSH agent destination host key must be a PublicKey")
            }
            if (
                key.certificateAuthority !== undefined &&
                typeof key.certificateAuthority !== "boolean"
            ) {
                throw new TypeError("OpenSSH agent destination CA marker must be boolean")
            }
            return Buffer.concat([
                serializeBuffer(key.publicKey.serialize()),
                serializeBinaryBoolean(key.certificateAuthority ?? false),
            ])
        }),
    )
}

function serializeHop(
    hop: OpenSSHAgentDestinationHop | OpenSSHAgentDestinationRule["to"] | undefined,
    destination: boolean,
): Buffer {
    if (hop === undefined) {
        if (destination) throw new Error("OpenSSH agent destination constraint requires a target")
        return Buffer.concat([
            serializeBuffer(Buffer.alloc(0)),
            serializeBuffer(Buffer.alloc(0)),
            serializeBuffer(Buffer.alloc(0)),
        ])
    }
    if (typeof hop !== "object" || hop === null) {
        throw new TypeError("OpenSSH agent destination hop must be an object")
    }
    const username = destination && "username" in hop ? (hop.username ?? "") : ""
    const encodedUsername = encodeText(username, "OpenSSH agent destination username", true)
    if (encodedUsername.length > 256) {
        throw new Error("OpenSSH agent destination username exceeds 256 bytes")
    }
    const encodedHostname = encodeText(hop.hostname, "OpenSSH agent destination hostname", false)
    return Buffer.concat([
        serializeBuffer(encodedUsername),
        serializeBuffer(encodedHostname),
        serializeBuffer(Buffer.alloc(0)),
        serializeKeySpecs(hop.hostKeys),
    ])
}

function serializeDestinationRule(rule: OpenSSHAgentDestinationRule): Buffer {
    const from = serializeHop(rule.from, false)
    const to = serializeHop(rule.to, true)
    return serializeBuffer(
        Buffer.concat([
            serializeBuffer(from),
            serializeBuffer(to),
            serializeBuffer(Buffer.alloc(0)),
        ]),
    )
}

function serializeDestinations(constraint: OpenSSHAgentDestinationConstraint): Buffer {
    if (
        !Array.isArray(constraint.destinations) ||
        constraint.destinations.length === 0 ||
        constraint.destinations.length > MAX_OPENSSH_AGENT_DESTINATION_CONSTRAINTS
    ) {
        throw new Error(
            `OpenSSH agent destination restrictions must contain between 1 and ${MAX_OPENSSH_AGENT_DESTINATION_CONSTRAINTS} entries`,
        )
    }
    const destinations = Buffer.concat(constraint.destinations.map(serializeDestinationRule))
    return Buffer.concat([
        Buffer.from([255]),
        serializeBuffer(Buffer.from(OPENSSH_AGENT_RESTRICT_DESTINATION, "ascii")),
        serializeBuffer(destinations),
    ])
}

function serializeAssociatedCertificates(
    constraint: OpenSSHAgentAssociatedCertificatesConstraint,
): Buffer {
    if (
        !Array.isArray(constraint.certificates) ||
        constraint.certificates.length === 0 ||
        constraint.certificates.length > MAX_OPENSSH_AGENT_ASSOCIATED_CERTIFICATES
    ) {
        throw new Error(
            `OpenSSH agent associated certificates must contain between 1 and ${MAX_OPENSSH_AGENT_ASSOCIATED_CERTIFICATES} entries`,
        )
    }
    if (
        constraint.certificatesOnly !== undefined &&
        typeof constraint.certificatesOnly !== "boolean"
    ) {
        throw new TypeError("OpenSSH agent certificates-only marker must be boolean")
    }
    const certificates = Buffer.concat(
        constraint.certificates.map((certificate) => {
            if (
                !(certificate instanceof PublicKey) ||
                !(certificate.data.algorithm instanceof SSHCertificatePublicKey)
            ) {
                throw new TypeError("OpenSSH agent associated key must be an SSH certificate")
            }
            return serializeBuffer(certificate.serialize())
        }),
    )
    return Buffer.concat([
        Buffer.from([255]),
        serializeBuffer(Buffer.from(OPENSSH_AGENT_ASSOCIATED_CERTIFICATES, "ascii")),
        serializeBinaryBoolean(constraint.certificatesOnly ?? false),
        serializeBuffer(certificates),
    ])
}

export function serializeOpenSSHAgentConstraint(
    constraint: OpenSSHAgentKeyConstraint,
    target: "identity" | "token",
): Buffer {
    if (constraint.type === "openssh-restrict-destination") {
        return serializeDestinations(constraint)
    }
    if (constraint.type === "openssh-associated-certificates") {
        if (target !== "token") {
            throw new Error(
                "OpenSSH agent associated certificates are valid only for token requests",
            )
        }
        return serializeAssociatedCertificates(constraint)
    }
    throw new Error("Unsupported OpenSSH agent constraint")
}

function parseKeySpecs(raw: Buffer): readonly OpenSSHAgentDestinationKey[] {
    const keys: OpenSSHAgentDestinationKey[] = []
    while (raw.length !== 0) {
        let keyBlob: Buffer
        let certificateAuthority: boolean
        ;[keyBlob, raw] = readNextBuffer(raw)
        ;[certificateAuthority, raw] = readNextBinaryBoolean(raw)
        keys.push(Object.freeze({ publicKey: PublicKey.parse(keyBlob), certificateAuthority }))
    }
    return Object.freeze(keys)
}

function parseHop(
    raw: Buffer,
    destination: boolean,
): OpenSSHAgentDestinationHop | OpenSSHAgentDestinationRule["to"] | undefined {
    let encodedUsername: Buffer
    let encodedHostname: Buffer
    let reserved: Buffer
    ;[encodedUsername, raw] = readNextBuffer(raw)
    ;[encodedHostname, raw] = readNextBuffer(raw)
    ;[reserved, raw] = readNextBuffer(raw)
    if (reserved.length !== 0) throw new Error("unsupported destination hop extension")
    const username = decodeSSHUTF8(encodedUsername, "OpenSSH agent destination username")
    const hostname = decodeSSHUTF8(encodedHostname, "OpenSSH agent destination hostname")
    if (encodedUsername.includes(0) || encodedHostname.includes(0)) {
        throw new Error("OpenSSH agent destination text contains NUL")
    }
    if (encodedUsername.length > 256) throw new Error("destination username is too long")
    const hostKeys = parseKeySpecs(raw)
    if (!destination) {
        if (username.length !== 0) throw new Error("source username must be empty")
        if ((hostname.length === 0) !== (hostKeys.length === 0)) {
            throw new Error("inconsistent source destination constraint")
        }
        return hostname.length === 0 ? undefined : Object.freeze({ hostname, hostKeys })
    }
    if (hostname.length === 0 || hostKeys.length === 0) {
        throw new Error("incomplete target destination constraint")
    }
    return Object.freeze({
        username: username.length === 0 ? undefined : username,
        hostname,
        hostKeys,
    })
}

function parseDestinations(raw: Buffer): [OpenSSHAgentDestinationConstraint, Buffer] {
    let encodedConstraints: Buffer
    ;[encodedConstraints, raw] = readNextBuffer(raw)
    const destinations: OpenSSHAgentDestinationRule[] = []
    while (encodedConstraints.length !== 0) {
        if (destinations.length >= MAX_OPENSSH_AGENT_DESTINATION_CONSTRAINTS) {
            throw new Error("too many OpenSSH agent destination constraints")
        }
        let encodedConstraint: Buffer
        ;[encodedConstraint, encodedConstraints] = readNextBuffer(encodedConstraints)
        const [encodedFrom, afterFrom] = readNextBuffer(encodedConstraint)
        const [encodedTo, afterTo] = readNextBuffer(afterFrom)
        const [reserved, remaining] = readNextBuffer(afterTo)
        encodedConstraint = remaining
        if (encodedConstraint.length !== 0 || reserved.length !== 0) {
            throw new Error("unsupported destination constraint extension")
        }
        const from = parseHop(encodedFrom, false) as OpenSSHAgentDestinationHop | undefined
        const to = parseHop(encodedTo, true) as OpenSSHAgentDestinationRule["to"]
        destinations.push(Object.freeze({ from, to }))
    }
    if (destinations.length === 0) throw new Error("destination restriction list is empty")
    return [
        Object.freeze({
            type: "openssh-restrict-destination",
            destinations: Object.freeze(destinations),
        }),
        raw,
    ]
}

function parseAssociatedCertificates(
    raw: Buffer,
    target: "identity" | "token",
): [OpenSSHAgentAssociatedCertificatesConstraint, Buffer] {
    if (target !== "token") {
        throw new Error("associated certificates are invalid for identity requests")
    }
    let certificatesOnly: boolean
    let encodedCertificates: Buffer
    ;[certificatesOnly, raw] = readNextBinaryBoolean(raw)
    ;[encodedCertificates, raw] = readNextBuffer(raw)
    const certificates: PublicKey[] = []
    while (encodedCertificates.length !== 0) {
        if (certificates.length >= MAX_OPENSSH_AGENT_ASSOCIATED_CERTIFICATES) {
            throw new Error("too many OpenSSH agent associated certificates")
        }
        let certificateBlob: Buffer
        ;[certificateBlob, encodedCertificates] = readNextBuffer(encodedCertificates)
        const certificate = PublicKey.parse(certificateBlob)
        if (!(certificate.data.algorithm instanceof SSHCertificatePublicKey)) {
            throw new Error("associated key is not an SSH certificate")
        }
        certificates.push(certificate)
    }
    if (certificates.length === 0) throw new Error("associated certificate list is empty")
    return [
        Object.freeze({
            type: "openssh-associated-certificates",
            certificatesOnly,
            certificates: Object.freeze(certificates),
        }),
        raw,
    ]
}

export function parseOpenSSHAgentConstraint(
    name: string,
    raw: Buffer,
    target: "identity" | "token",
): [readonly OpenSSHAgentKeyConstraint[], Buffer] | undefined {
    if (name === OPENSSH_AGENT_RESTRICT_DESTINATION) {
        const [constraint, remaining] = parseDestinations(raw)
        return [[constraint], remaining]
    }
    if (name === OPENSSH_AGENT_ASSOCIATED_CERTIFICATES) {
        const [constraint, remaining] = parseAssociatedCertificates(raw, target)
        return [[constraint], remaining]
    }
    return undefined
}

export function serializeOpenSSHSessionBinding(binding: OpenSSHAgentSessionBinding): Buffer {
    if (typeof binding !== "object" || binding === null) {
        throw new TypeError("OpenSSH agent session binding must be an object")
    }
    if (!(binding.hostKey instanceof PublicKey)) {
        throw new TypeError("OpenSSH agent session binding requires a PublicKey")
    }
    if (!Buffer.isBuffer(binding.sessionIdentifier)) {
        throw new TypeError("OpenSSH agent session identifier must be a buffer")
    }
    if (binding.sessionIdentifier.length > MAX_OPENSSH_AGENT_SESSION_IDENTIFIER_LENGTH) {
        throw new Error("OpenSSH agent session identifier exceeds 128 bytes")
    }
    if (!(binding.signature instanceof EncodedSignature)) {
        throw new TypeError("OpenSSH agent session binding requires an EncodedSignature")
    }
    if (typeof binding.forwarding !== "boolean") {
        throw new TypeError("OpenSSH agent forwarding marker must be boolean")
    }
    if (!binding.hostKey.verifySignature(binding.sessionIdentifier, binding.signature)) {
        throw new Error("OpenSSH agent session binding signature is invalid")
    }
    return Buffer.concat([
        serializeBuffer(binding.hostKey.serialize()),
        serializeBuffer(Buffer.from(binding.sessionIdentifier)),
        serializeBuffer(binding.signature.serialize()),
        serializeBinaryBoolean(binding.forwarding),
    ])
}

export function parseOpenSSHSessionBinding(raw: Buffer): OpenSSHAgentSessionBinding {
    let hostKeyBlob: Buffer
    let sessionIdentifier: Buffer
    let signatureBlob: Buffer
    let forwarding: boolean
    ;[hostKeyBlob, raw] = readNextBuffer(raw)
    ;[sessionIdentifier, raw] = readNextBuffer(raw)
    ;[signatureBlob, raw] = readNextBuffer(raw)
    ;[forwarding, raw] = readNextBinaryBoolean(raw)
    if (raw.length !== 0) throw new Error("session binding has trailing data")
    const binding = Object.freeze({
        hostKey: PublicKey.parse(hostKeyBlob),
        sessionIdentifier: Buffer.from(sessionIdentifier),
        signature: EncodedSignature.parse(signatureBlob),
        forwarding,
    })
    serializeOpenSSHSessionBinding(binding)
    return binding
}
