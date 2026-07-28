import { decodeSSHName, encodeSSHName } from "../utils/SSHName.js"
import {
    decodeSSHLanguageTag,
    decodeSSHUTF8,
    encodeSSHLanguageTag,
    encodeSSHUTF8,
} from "../utils/SSHText.js"

export const PUBLIC_KEY_SUBSYSTEM_VERSION = 3
export const MIN_PUBLIC_KEY_SUBSYSTEM_VERSION = 2
export const MAX_PUBLIC_KEY_SUBSYSTEM_PACKET_LENGTH = 256 * 1024
export const MAX_PUBLIC_KEY_SUBSYSTEM_RESPONSES = 1024
export const MAX_PUBLIC_KEY_SUBSYSTEM_RESPONSE_BYTES = 4 * 1024 * 1024
export const MAX_PUBLIC_KEY_SUBSYSTEM_NAMESPACE_CHARACTERS = 300

const UINT32_MAX = 0xffff_ffff

export class PublicKeySubsystemProtocolError extends Error {
    constructor(message: string) {
        super(message)
        this.name = "PublicKeySubsystemProtocolError"
    }
}

export enum PublicKeySubsystemStatusCode {
    Success = 0,
    AccessDenied = 1,
    StorageExceeded = 2,
    VersionNotSupported = 3,
    KeyNotFound = 4,
    KeyNotSupported = 5,
    KeyAlreadyPresent = 6,
    GeneralFailure = 7,
    RequestNotSupported = 8,
    AttributeNotSupported = 9,
    CertificateNotFound = 192,
    CertificateNotSupported = 193,
    CertificateAlreadyPresent = 194,
    ActionNotAuthorized = 195,
    CannotCreateNamespace = 196,
}

export interface PublicKeySubsystemVersionPacket {
    readonly type: "version"
    readonly version: number
}

export interface PublicKeySubsystemAddAttribute {
    readonly name: string
    readonly value: Buffer
    readonly critical: boolean
}

export interface PublicKeySubsystemAddPacket {
    readonly type: "add"
    readonly algorithm: string
    readonly keyBlob: Buffer
    readonly overwrite: boolean
    readonly attributes: readonly PublicKeySubsystemAddAttribute[]
}

export interface PublicKeySubsystemStatusPacket {
    readonly type: "status"
    readonly code: number
    readonly description: string
    readonly languageTag: string
}

export interface PublicKeySubsystemRemovePacket {
    readonly type: "remove"
    readonly algorithm: string
    readonly keyBlob: Buffer
    /** Present on RFC 7076 version-3 requests and absent on RFC 4819 version-2 requests. */
    readonly attributes?: readonly PublicKeySubsystemAddAttribute[]
}

export interface PublicKeySubsystemListPacket {
    readonly type: "list"
    /** Present on RFC 7076 version-3 requests and absent on RFC 4819 version-2 requests. */
    readonly attributes?: readonly PublicKeySubsystemAddAttribute[]
}

export interface PublicKeySubsystemListAttributesPacket {
    readonly type: "listattributes"
}

export interface PublicKeySubsystemListedAttribute {
    readonly name: string
    readonly value: Buffer
}

export interface PublicKeySubsystemPublicKeyPacket {
    readonly type: "publickey"
    readonly algorithm: string
    readonly keyBlob: Buffer
    readonly attributes: readonly PublicKeySubsystemListedAttribute[]
}

export interface PublicKeySubsystemAttributePacket {
    readonly type: "attribute"
    readonly name: string
    readonly compulsory: boolean
}

export interface PublicKeySubsystemAddCertificatePacket {
    readonly type: "add-certificate"
    readonly format: string
    readonly certificateBlob: Buffer
    readonly overwrite: boolean
    readonly attributes: readonly PublicKeySubsystemAddAttribute[]
}

export interface PublicKeySubsystemRemoveCertificatePacket {
    readonly type: "remove-certificate"
    readonly format: string
    readonly certificateBlob: Buffer
    readonly attributes: readonly PublicKeySubsystemListedAttribute[]
}

export interface PublicKeySubsystemListCertificatesPacket {
    readonly type: "list-certificates"
}

export interface PublicKeySubsystemCertificatePacket {
    readonly type: "certificate"
    readonly format: string
    readonly certificateBlob: Buffer
    readonly attributes: readonly PublicKeySubsystemListedAttribute[]
}

export interface PublicKeySubsystemListNamespacesPacket {
    readonly type: "list-namespaces"
}

export interface PublicKeySubsystemNamespacePacket {
    readonly type: "namespace"
    readonly name: string
}

export interface PublicKeySubsystemUnknownPacket {
    readonly type: "unknown"
    readonly name: string
    readonly data: Buffer
}

export type PublicKeySubsystemPacket =
    | PublicKeySubsystemVersionPacket
    | PublicKeySubsystemAddPacket
    | PublicKeySubsystemStatusPacket
    | PublicKeySubsystemRemovePacket
    | PublicKeySubsystemListPacket
    | PublicKeySubsystemListAttributesPacket
    | PublicKeySubsystemPublicKeyPacket
    | PublicKeySubsystemAttributePacket
    | PublicKeySubsystemAddCertificatePacket
    | PublicKeySubsystemRemoveCertificatePacket
    | PublicKeySubsystemListCertificatesPacket
    | PublicKeySubsystemCertificatePacket
    | PublicKeySubsystemListNamespacesPacket
    | PublicKeySubsystemNamespacePacket
    | PublicKeySubsystemUnknownPacket

export function validatePublicKeySubsystemAttributes(
    attributes: readonly { readonly name: string; readonly value: Buffer }[],
): void {
    for (let index = 0; index < attributes.length; index++) {
        const attribute = attributes[index]!
        encodeSSHName(attribute.name, "Public-key subsystem attribute name")
        if (!Buffer.isBuffer(attribute.value)) {
            throw new TypeError("Public-key subsystem attribute value must be a buffer")
        }
        if (attribute.name === "comment") {
            decodeSSHUTF8(attribute.value, "Public-key subsystem comment attribute")
        } else if (attribute.name === "comment-language") {
            if (index === 0 || attributes[index - 1]!.name !== "comment") {
                throw new Error(
                    "Public-key subsystem comment-language must immediately follow comment",
                )
            }
            decodeSSHLanguageTag(attribute.value, "Public-key subsystem comment-language attribute")
        } else if (attribute.name === "namespace") {
            validatePublicKeySubsystemNamespace(
                decodeSSHUTF8(attribute.value, "Public-key subsystem namespace"),
            )
        }
    }
}

export function validatePublicKeySubsystemNamespace(namespace: string): void {
    encodeSSHUTF8(namespace, "Public-key subsystem namespace")
    if ([...namespace].length > MAX_PUBLIC_KEY_SUBSYSTEM_NAMESPACE_CHARACTERS) {
        throw new RangeError(
            `Public-key subsystem namespace exceeds ${MAX_PUBLIC_KEY_SUBSYSTEM_NAMESPACE_CHARACTERS} characters`,
        )
    }
}

export function publicKeySubsystemNamespace(
    attributes: readonly { readonly name: string; readonly value: Buffer }[],
    required = false,
): string | undefined {
    const namespaces = attributes.filter(({ name }) => name === "namespace")
    if (namespaces.length > 1) {
        throw new Error("Public-key subsystem request must not contain more than one namespace")
    }
    const attribute = namespaces[0]
    if (!attribute) {
        if (required) throw new Error("Public-key subsystem request requires a namespace")
        return undefined
    }
    const namespace = decodeSSHUTF8(attribute.value, "Public-key subsystem namespace")
    validatePublicKeySubsystemNamespace(namespace)
    return namespace
}

class Reader {
    private offset = 0

    constructor(private readonly buffer: Buffer) {}

    get remaining(): number {
        return this.buffer.length - this.offset
    }

    uint32(field: string): number {
        this.require(4, field)
        const value = this.buffer.readUInt32BE(this.offset)
        this.offset += 4
        return value
    }

    boolean(field: string): boolean {
        this.require(1, field)
        const value = this.buffer[this.offset++]!
        return value !== 0
    }

    string(field: string): Buffer {
        const length = this.uint32(`${field} length`)
        this.require(length, field)
        const value = Buffer.from(this.buffer.subarray(this.offset, this.offset + length))
        this.offset += length
        return value
    }

    rest(): Buffer {
        const value = Buffer.from(this.buffer.subarray(this.offset))
        this.offset = this.buffer.length
        return value
    }

    done(): void {
        if (this.remaining !== 0) {
            throw new PublicKeySubsystemProtocolError(
                `Public-key subsystem packet has ${this.remaining} trailing bytes`,
            )
        }
    }

    private require(length: number, field: string): void {
        if (length > this.remaining) {
            throw new PublicKeySubsystemProtocolError(`Truncated public-key subsystem ${field}`)
        }
    }
}

function readRequestAttributes(reader: Reader): readonly PublicKeySubsystemAddAttribute[] {
    const count = reader.uint32("attribute count")
    if (count > Math.floor(reader.remaining / 10)) {
        throw new PublicKeySubsystemProtocolError(
            "Public-key subsystem attribute count exceeds packet data",
        )
    }
    const attributes: PublicKeySubsystemAddAttribute[] = []
    for (let index = 0; index < count; index++) {
        attributes.push({
            name: decodeSSHName(
                reader.string("attribute name"),
                "Public-key subsystem attribute name",
            ),
            value: reader.string("attribute value"),
            critical: reader.boolean("critical attribute flag"),
        })
    }
    return attributes
}

function encodeRequestAttributes(
    attributes: readonly PublicKeySubsystemAddAttribute[],
): readonly Buffer[] {
    return [
        uint32(attributes.length, "attribute count"),
        ...attributes.flatMap((attribute) => [
            string(
                encodeSSHName(attribute.name, "Public-key subsystem attribute name"),
                "attribute name",
            ),
            string(attribute.value, "attribute value"),
            boolean(attribute.critical),
        ]),
    ]
}

function readListedAttributes(reader: Reader): readonly PublicKeySubsystemListedAttribute[] {
    const count = reader.uint32("attribute count")
    if (count > Math.floor(reader.remaining / 9)) {
        throw new PublicKeySubsystemProtocolError(
            "Public-key subsystem attribute count exceeds packet data",
        )
    }
    const attributes: PublicKeySubsystemListedAttribute[] = []
    for (let index = 0; index < count; index++) {
        attributes.push({
            name: decodeSSHName(
                reader.string("attribute name"),
                "Public-key subsystem attribute name",
            ),
            value: reader.string("attribute value"),
        })
    }
    return attributes
}

function encodeListedAttributes(
    attributes: readonly PublicKeySubsystemListedAttribute[],
): readonly Buffer[] {
    return [
        uint32(attributes.length, "attribute count"),
        ...attributes.flatMap((attribute) => [
            string(
                encodeSSHName(attribute.name, "Public-key subsystem attribute name"),
                "attribute name",
            ),
            string(attribute.value, "attribute value"),
        ]),
    ]
}

export function decodePublicKeySubsystemPacket(frame: Buffer): PublicKeySubsystemPacket {
    if (frame.length < 4) throw new PublicKeySubsystemProtocolError("Truncated public-key packet")
    const packetLength = frame.readUInt32BE(0)
    if (packetLength > MAX_PUBLIC_KEY_SUBSYSTEM_PACKET_LENGTH) {
        throw new PublicKeySubsystemProtocolError(
            `Public-key packet length exceeds ${MAX_PUBLIC_KEY_SUBSYSTEM_PACKET_LENGTH} bytes`,
        )
    }
    if (frame.length !== packetLength + 4) {
        throw new PublicKeySubsystemProtocolError(
            "Public-key frame length does not match its length field",
        )
    }
    const reader = new Reader(frame.subarray(4))
    const type = decodeSSHName(reader.string("packet name"), "Public-key subsystem packet name")
    let packet: PublicKeySubsystemPacket
    switch (type) {
        case "version":
            packet = { type, version: reader.uint32("version") }
            break
        case "add": {
            const algorithm = decodeSSHName(
                reader.string("key algorithm"),
                "Public-key subsystem key algorithm",
            )
            const keyBlob = reader.string("key blob")
            const overwrite = reader.boolean("overwrite flag")
            const count = reader.uint32("attribute count")
            if (count > Math.floor(reader.remaining / 10)) {
                throw new PublicKeySubsystemProtocolError(
                    "Public-key subsystem attribute count exceeds packet data",
                )
            }
            const attributes: PublicKeySubsystemAddAttribute[] = []
            for (let index = 0; index < count; index++) {
                attributes.push({
                    name: decodeSSHName(
                        reader.string("attribute name"),
                        "Public-key subsystem attribute name",
                    ),
                    value: reader.string("attribute value"),
                    critical: reader.boolean("critical attribute flag"),
                })
            }
            packet = { type, algorithm, keyBlob, overwrite, attributes }
            break
        }
        case "status": {
            const code = reader.uint32("status code")
            packet = {
                type,
                code,
                description: decodeSSHUTF8(
                    reader.string("status description"),
                    "Public-key subsystem status description",
                ),
                languageTag: decodeSSHLanguageTag(
                    reader.string("status language tag"),
                    "Public-key subsystem status language tag",
                ),
            }
            break
        }
        case "remove": {
            const algorithm = decodeSSHName(
                reader.string("key algorithm"),
                "Public-key subsystem key algorithm",
            )
            const keyBlob = reader.string("key blob")
            packet = {
                type,
                algorithm,
                keyBlob,
                ...(reader.remaining === 0 ? {} : { attributes: readRequestAttributes(reader) }),
            }
            break
        }
        case "list":
            packet = {
                type,
                ...(reader.remaining === 0 ? {} : { attributes: readRequestAttributes(reader) }),
            }
            break
        case "listattributes":
            packet = { type }
            break
        case "publickey": {
            const algorithm = decodeSSHName(
                reader.string("key algorithm"),
                "Public-key subsystem key algorithm",
            )
            const keyBlob = reader.string("key blob")
            const count = reader.uint32("attribute count")
            if (count > Math.floor(reader.remaining / 9)) {
                throw new PublicKeySubsystemProtocolError(
                    "Public-key subsystem attribute count exceeds packet data",
                )
            }
            const attributes: PublicKeySubsystemListedAttribute[] = []
            for (let index = 0; index < count; index++) {
                attributes.push({
                    name: decodeSSHName(
                        reader.string("attribute name"),
                        "Public-key subsystem attribute name",
                    ),
                    value: reader.string("attribute value"),
                })
            }
            packet = { type, algorithm, keyBlob, attributes }
            break
        }
        case "attribute":
            packet = {
                type,
                name: decodeSSHName(
                    reader.string("attribute name"),
                    "Public-key subsystem attribute name",
                ),
                compulsory: reader.boolean("compulsory attribute flag"),
            }
            break
        case "add-certificate":
            packet = {
                type,
                format: decodeSSHName(
                    reader.string("certificate format"),
                    "Public-key subsystem certificate format",
                ),
                certificateBlob: reader.string("certificate blob"),
                overwrite: reader.boolean("overwrite flag"),
                attributes: readRequestAttributes(reader),
            }
            break
        case "remove-certificate":
            packet = {
                type,
                format: decodeSSHName(
                    reader.string("certificate format"),
                    "Public-key subsystem certificate format",
                ),
                certificateBlob: reader.string("certificate blob"),
                attributes: readListedAttributes(reader),
            }
            break
        case "list-certificates":
        case "list-namespaces":
            packet = { type }
            break
        case "certificate":
            packet = {
                type,
                format: decodeSSHName(
                    reader.string("certificate format"),
                    "Public-key subsystem certificate format",
                ),
                certificateBlob: reader.string("certificate blob"),
                attributes: readListedAttributes(reader),
            }
            break
        case "namespace":
            packet = {
                type,
                name: decodeSSHUTF8(
                    reader.string("namespace name"),
                    "Public-key subsystem namespace",
                ),
            }
            break
        default:
            packet = { type: "unknown", name: type, data: reader.rest() }
    }
    reader.done()
    return packet
}

export function encodePublicKeySubsystemPacket(packet: PublicKeySubsystemPacket): Buffer {
    const parts: Buffer[] = [
        string(
            encodeSSHName(
                packet.type === "unknown" ? packet.name : packet.type,
                "Public-key subsystem packet name",
            ),
            "packet name",
        ),
    ]
    switch (packet.type) {
        case "version":
            parts.push(uint32(packet.version, "version"))
            break
        case "add":
            parts.push(
                string(
                    encodeSSHName(packet.algorithm, "Public-key subsystem key algorithm"),
                    "key algorithm",
                ),
                string(packet.keyBlob, "key blob"),
                boolean(packet.overwrite),
                uint32(packet.attributes.length, "attribute count"),
                ...packet.attributes.flatMap((attribute) => [
                    string(
                        encodeSSHName(attribute.name, "Public-key subsystem attribute name"),
                        "attribute name",
                    ),
                    string(attribute.value, "attribute value"),
                    boolean(attribute.critical),
                ]),
            )
            break
        case "status":
            parts.push(
                uint32(packet.code, "status code"),
                string(
                    encodeSSHUTF8(packet.description, "Public-key subsystem status description"),
                    "status description",
                ),
                string(
                    encodeSSHLanguageTag(
                        packet.languageTag,
                        "Public-key subsystem status language tag",
                    ),
                    "status language tag",
                ),
            )
            break
        case "remove":
            parts.push(
                string(
                    encodeSSHName(packet.algorithm, "Public-key subsystem key algorithm"),
                    "key algorithm",
                ),
                string(packet.keyBlob, "key blob"),
                ...(packet.attributes === undefined
                    ? []
                    : encodeRequestAttributes(packet.attributes)),
            )
            break
        case "list":
            if (packet.attributes !== undefined) {
                parts.push(...encodeRequestAttributes(packet.attributes))
            }
            break
        case "listattributes":
            break
        case "publickey":
            parts.push(
                string(
                    encodeSSHName(packet.algorithm, "Public-key subsystem key algorithm"),
                    "key algorithm",
                ),
                string(packet.keyBlob, "key blob"),
                uint32(packet.attributes.length, "attribute count"),
                ...packet.attributes.flatMap((attribute) => [
                    string(
                        encodeSSHName(attribute.name, "Public-key subsystem attribute name"),
                        "attribute name",
                    ),
                    string(attribute.value, "attribute value"),
                ]),
            )
            break
        case "attribute":
            parts.push(
                string(
                    encodeSSHName(packet.name, "Public-key subsystem attribute name"),
                    "attribute name",
                ),
                boolean(packet.compulsory),
            )
            break
        case "add-certificate":
            parts.push(
                string(
                    encodeSSHName(packet.format, "Public-key subsystem certificate format"),
                    "certificate format",
                ),
                string(packet.certificateBlob, "certificate blob"),
                boolean(packet.overwrite),
                ...encodeRequestAttributes(packet.attributes),
            )
            break
        case "remove-certificate":
            parts.push(
                string(
                    encodeSSHName(packet.format, "Public-key subsystem certificate format"),
                    "certificate format",
                ),
                string(packet.certificateBlob, "certificate blob"),
                ...encodeListedAttributes(packet.attributes),
            )
            break
        case "list-certificates":
        case "list-namespaces":
            break
        case "certificate":
            parts.push(
                string(
                    encodeSSHName(packet.format, "Public-key subsystem certificate format"),
                    "certificate format",
                ),
                string(packet.certificateBlob, "certificate blob"),
                ...encodeListedAttributes(packet.attributes),
            )
            break
        case "namespace":
            parts.push(
                string(
                    encodeSSHUTF8(packet.name, "Public-key subsystem namespace"),
                    "namespace name",
                ),
            )
            break
        case "unknown":
            if (!Buffer.isBuffer(packet.data)) {
                throw new TypeError("Public-key subsystem unknown packet data must be a buffer")
            }
            parts.push(packet.data)
            break
    }
    const payload = Buffer.concat(parts)
    if (payload.length > MAX_PUBLIC_KEY_SUBSYSTEM_PACKET_LENGTH) {
        throw new PublicKeySubsystemProtocolError(
            `Public-key packet length exceeds ${MAX_PUBLIC_KEY_SUBSYSTEM_PACKET_LENGTH} bytes`,
        )
    }
    return Buffer.concat([uint32(payload.length, "packet length"), payload])
}

export class PublicKeySubsystemPacketParser {
    private buffered = Buffer.allocUnsafe(4)
    private bufferedLength = 0
    private expectedLength = 4
    private readingLength = true

    push(chunk: Buffer): PublicKeySubsystemPacket[] {
        if (!Buffer.isBuffer(chunk)) {
            throw new TypeError("Public-key subsystem stream chunk must be a buffer")
        }
        if (chunk.length === 0) return []
        const packets: PublicKeySubsystemPacket[] = []
        let offset = 0
        while (offset < chunk.length) {
            const copied = chunk.copy(
                this.buffered,
                this.bufferedLength,
                offset,
                offset + this.expectedLength - this.bufferedLength,
            )
            this.bufferedLength += copied
            offset += copied
            if (this.bufferedLength < this.expectedLength) break

            if (this.readingLength) {
                const packetLength = this.buffered.readUInt32BE(0)
                if (packetLength > MAX_PUBLIC_KEY_SUBSYSTEM_PACKET_LENGTH) {
                    throw new PublicKeySubsystemProtocolError(
                        `Public-key packet length exceeds ${MAX_PUBLIC_KEY_SUBSYSTEM_PACKET_LENGTH} bytes`,
                    )
                }
                this.expectedLength = packetLength + 4
                const frame = Buffer.allocUnsafe(this.expectedLength)
                this.buffered.copy(frame, 0, 0, 4)
                this.buffered = frame
                this.readingLength = false
                if (this.bufferedLength < this.expectedLength) continue
            }

            packets.push(decodePublicKeySubsystemPacket(this.buffered))
            this.buffered = Buffer.allocUnsafe(4)
            this.bufferedLength = 0
            this.expectedLength = 4
            this.readingLength = true
        }
        return packets
    }

    end(): void {
        if (this.bufferedLength !== 0) {
            throw new PublicKeySubsystemProtocolError("Truncated public-key subsystem stream")
        }
    }
}

function uint32(value: number, field: string): Buffer {
    if (!Number.isSafeInteger(value) || value < 0 || value > UINT32_MAX) {
        throw new RangeError(`Public-key subsystem ${field} must be a uint32`)
    }
    const buffer = Buffer.allocUnsafe(4)
    buffer.writeUInt32BE(value)
    return buffer
}

function boolean(value: boolean): Buffer {
    if (typeof value !== "boolean") {
        throw new TypeError("Public-key subsystem boolean must be true or false")
    }
    return Buffer.from([value ? 1 : 0])
}

function string(value: Buffer, field: string): Buffer {
    if (!Buffer.isBuffer(value)) {
        throw new TypeError(`Public-key subsystem ${field} must be a buffer`)
    }
    return Buffer.concat([uint32(value.length, `${field} length`), value])
}
