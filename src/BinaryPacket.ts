import crypto, { timingSafeEqual } from "node:crypto"
import { SEQUENCE_NUMBER_MODULO } from "./constants.js"

export const MINIMUM_BINARY_PACKET_LENGTH = 16
export const MAXIMUM_BINARY_PACKET_SIZE = 35000

export interface PacketMAC {
    computeMAC(sequenceNumber: number, packet: Buffer): Buffer
}

export interface PacketEncryptor {
    encrypt(plaintext: Buffer): Buffer
}

export interface PacketDecryptor {
    decrypt(ciphertext: Buffer): Buffer
}

export interface PacketCompressor {
    compress(payload: Buffer): Buffer
}

export interface PacketDecompressor {
    decompress(payload: Buffer): Buffer
}

export interface PacketAEADEncryptor {
    encryptPacket(
        sequenceNumber: number,
        plaintext: Buffer,
    ): { ciphertext: Buffer; authenticationTag: Buffer }
}

export interface PacketAEADDecryptor {
    decryptPacketLength(sequenceNumber: number, encryptedLength: Buffer): Buffer
    decryptPacket(sequenceNumber: number, ciphertext: Buffer, authenticationTag: Buffer): Buffer
}

export interface OutboundPacketCipherProtection {
    cipher: PacketEncryptor
    mac: PacketMAC
    blockSize: number
    macLength: number
    encryptThenMac?: boolean
    aead?: false
    dispose?: () => void
}

export interface InboundPacketCipherProtection {
    cipher: PacketDecryptor
    mac: PacketMAC
    blockSize: number
    macLength: number
    encryptThenMac?: boolean
    aead?: false
    dispose?: () => void
}

export interface OutboundPacketAEADProtection {
    cipher: PacketAEADEncryptor
    blockSize: number
    authTagLength: number
    aead: true
    dispose?: () => void
}

export interface InboundPacketAEADProtection {
    cipher: PacketAEADDecryptor
    blockSize: number
    authTagLength: number
    aead: true
    dispose?: () => void
}

export type OutboundPacketProtection = OutboundPacketCipherProtection | OutboundPacketAEADProtection

export type InboundPacketProtection = InboundPacketCipherProtection | InboundPacketAEADProtection

export interface EncodedBinaryPacket {
    sequenceNumber: number
    data: Buffer
}

export interface DecodedBinaryPacket {
    sequenceNumber: number
    payload: Buffer
    padding: Buffer
    data: Buffer
}

export interface BinaryPacketOptions {
    maximumPacketSize?: number
}

export interface BinaryPacketEncoderOptions extends BinaryPacketOptions {
    randomBytes?: (size: number) => Buffer
}

function validateMaximumPacketSize(maximumPacketSize: number): void {
    if (
        !Number.isSafeInteger(maximumPacketSize) ||
        maximumPacketSize < MAXIMUM_BINARY_PACKET_SIZE
    ) {
        throw new Error(
            `Maximum SSH packet size must be at least ${MAXIMUM_BINARY_PACKET_SIZE} bytes`,
        )
    }
}

function validateProtection(
    protection: { blockSize: number } & (
        | { aead: true; authTagLength: number }
        | { aead?: false; macLength: number }
    ),
): void {
    if (!Number.isSafeInteger(protection.blockSize) || protection.blockSize < 8) {
        throw new Error("SSH cipher block size must be an integer of at least 8 bytes")
    }
    const authenticationLength = protection.aead ? protection.authTagLength : protection.macLength
    if (
        !Number.isSafeInteger(authenticationLength) ||
        authenticationLength < (protection.aead ? 1 : 0)
    ) {
        throw new Error(
            protection.aead
                ? "SSH AEAD authentication tag length must be a positive integer"
                : "SSH MAC length must be a non-negative integer",
        )
    }
}

export class BinaryPacketEncoder {
    private readonly maximumPacketSize: number
    private readonly randomBytes: (size: number) => Buffer
    private protection?: OutboundPacketProtection
    private compressor?: PacketCompressor
    private sequenceNumber = 0
    private sequenceNumberWrapped = false
    private protectedBytes = 0
    private disposed = false

    constructor(options: BinaryPacketEncoderOptions = {}) {
        this.maximumPacketSize = options.maximumPacketSize ?? MAXIMUM_BINARY_PACKET_SIZE
        validateMaximumPacketSize(this.maximumPacketSize)
        this.randomBytes = options.randomBytes ?? crypto.randomBytes
    }

    setProtection(protection: OutboundPacketProtection): void {
        if (this.disposed) throw new Error("SSH binary packet encoder is disposed")
        validateProtection(protection)
        if (this.protection !== protection) this.protection?.dispose?.()
        this.protection = protection
        this.protectedBytes = 0
    }

    setCompression(compressor: PacketCompressor | undefined): void {
        if (this.disposed) throw new Error("SSH binary packet encoder is disposed")
        this.compressor = compressor
    }

    dispose(): void {
        if (this.disposed) return
        this.disposed = true
        this.protection?.dispose?.()
        this.protection = undefined
        this.compressor = undefined
    }

    resetSequenceNumber(): void {
        this.sequenceNumber = 0
        this.sequenceNumberWrapped = false
    }

    get hasSequenceNumberWrapped(): boolean {
        return this.sequenceNumberWrapped
    }

    /** Wire bytes emitted under the current packet-protection keys. */
    get bytesProtected(): number {
        return this.protectedBytes
    }

    encode(payload: Buffer): EncodedBinaryPacket {
        if (this.disposed) throw new Error("SSH binary packet encoder is disposed")
        if (payload.length === 0) {
            throw new Error("SSH binary packet payload must not be empty")
        }

        payload = this.compressor?.compress(payload) ?? payload
        if (payload.length === 0) {
            throw new Error("SSH compression produced an empty packet payload")
        }

        const blockSize = Math.max(8, this.protection?.blockSize ?? 8)
        const aead = this.protection?.aead === true
        const encryptThenMac =
            this.protection?.aead !== true && this.protection?.encryptThenMac === true
        const bodyOnlyAlignment = aead || encryptThenMac
        const alignedLength = (bodyOnlyAlignment ? 1 : 5) + payload.length
        let paddingLength = blockSize - (alignedLength % blockSize)
        if (paddingLength < 4) paddingLength += blockSize
        if (paddingLength > 255) {
            throw new Error("SSH binary packet padding must not exceed 255 bytes")
        }

        const packetLength = 1 + payload.length + paddingLength
        const authenticationLength =
            this.protection?.aead === true
                ? this.protection.authTagLength
                : (this.protection?.macLength ?? 0)
        const totalLength = 4 + packetLength + authenticationLength
        if (totalLength > this.maximumPacketSize) {
            throw new Error(
                `SSH binary packet size ${totalLength} exceeds maximum ${this.maximumPacketSize}`,
            )
        }

        const padding = this.randomBytes(paddingLength)
        if (padding.length !== paddingLength) {
            throw new Error("SSH padding source returned an unexpected number of bytes")
        }

        const plaintext = Buffer.allocUnsafe(4 + packetLength)
        plaintext.writeUInt32BE(packetLength, 0)
        plaintext[4] = paddingLength
        payload.copy(plaintext, 5)
        padding.copy(plaintext, 5 + payload.length)

        const sequenceNumber = this.sequenceNumber
        let packet: Buffer
        let authentication: Buffer
        if (this.protection?.aead) {
            const result = this.protection.cipher.encryptPacket(sequenceNumber, plaintext)
            if (result.ciphertext.length !== plaintext.length) {
                throw new Error("SSH AEAD cipher changed the binary packet length")
            }
            if (result.authenticationTag.length !== authenticationLength) {
                throw new Error(
                    `SSH AEAD cipher produced a ${result.authenticationTag.length}-byte authentication tag; expected ${authenticationLength}`,
                )
            }
            packet = result.ciphertext
            authentication = result.authenticationTag
        } else if (this.protection && encryptThenMac) {
            const ciphertext = this.protection.cipher.encrypt(plaintext.subarray(4))
            if (ciphertext.length !== plaintext.length - 4) {
                throw new Error("SSH cipher changed the binary packet length")
            }
            packet = Buffer.concat([plaintext.subarray(0, 4), ciphertext])
            authentication = this.protection.mac.computeMAC(sequenceNumber, packet)
        } else {
            packet = this.protection?.cipher.encrypt(plaintext) ?? plaintext
            if (packet.length !== plaintext.length) {
                throw new Error("SSH cipher changed the binary packet length")
            }
            authentication =
                this.protection?.mac.computeMAC(sequenceNumber, plaintext) ?? Buffer.alloc(0)
        }

        if (authentication.length !== authenticationLength) {
            throw new Error(
                `SSH MAC produced ${authentication.length} bytes; expected ${authenticationLength}`,
            )
        }

        if (this.sequenceNumber === SEQUENCE_NUMBER_MODULO - 1) this.sequenceNumberWrapped = true
        this.sequenceNumber = (this.sequenceNumber + 1) % SEQUENCE_NUMBER_MODULO
        const data = Buffer.concat([packet, authentication])
        if (this.protection) {
            this.protectedBytes = Math.min(
                Number.MAX_SAFE_INTEGER,
                this.protectedBytes + data.length,
            )
        }
        return { sequenceNumber, data }
    }
}

export class BinaryPacketDecoder {
    private readonly maximumPacketSize: number
    private protection?: InboundPacketProtection
    private decompressor?: PacketDecompressor
    private buffered = Buffer.alloc(0)
    private decryptedFirstBlock?: Buffer
    private sequenceNumber = 0
    private sequenceNumberWrapped = false
    private protectedBytes = 0
    private disposed = false

    constructor(options: BinaryPacketOptions = {}) {
        this.maximumPacketSize = options.maximumPacketSize ?? MAXIMUM_BINARY_PACKET_SIZE
        validateMaximumPacketSize(this.maximumPacketSize)
    }

    get bufferedLength(): number {
        return this.buffered.length
    }

    resetSequenceNumber(): void {
        this.sequenceNumber = 0
        this.sequenceNumberWrapped = false
    }

    get hasSequenceNumberWrapped(): boolean {
        return this.sequenceNumberWrapped
    }

    /** Authenticated wire bytes accepted under the current packet-protection keys. */
    get bytesProtected(): number {
        return this.protectedBytes
    }

    push(chunk: Buffer): void {
        if (this.disposed) throw new Error("SSH binary packet decoder is disposed")
        if (chunk.length === 0) return
        this.buffered = Buffer.concat([this.buffered, chunk])
    }

    setProtection(protection: InboundPacketProtection): void {
        if (this.disposed) throw new Error("SSH binary packet decoder is disposed")
        if (this.decryptedFirstBlock) {
            throw new Error("Cannot change SSH packet protection while decoding a packet")
        }
        validateProtection(protection)
        if (this.protection !== protection) this.protection?.dispose?.()
        this.protection = protection
        this.protectedBytes = 0
    }

    setCompression(decompressor: PacketDecompressor | undefined): void {
        if (this.disposed) throw new Error("SSH binary packet decoder is disposed")
        if (this.decryptedFirstBlock) {
            throw new Error("Cannot change SSH compression while decoding a packet")
        }
        this.decompressor = decompressor
    }

    dispose(): void {
        if (this.disposed) return
        this.disposed = true
        this.protection?.dispose?.()
        this.protection = undefined
        this.decompressor = undefined
        this.decryptedFirstBlock?.fill(0)
        this.decryptedFirstBlock = undefined
        this.buffered.fill(0)
        this.buffered = Buffer.alloc(0)
    }

    read(): DecodedBinaryPacket | undefined {
        if (this.disposed) throw new Error("SSH binary packet decoder is disposed")
        const blockSize = Math.max(8, this.protection?.blockSize ?? 8)
        const aead = this.protection?.aead === true
        const encryptThenMac =
            this.protection?.aead !== true && this.protection?.encryptThenMac === true
        const separatelyProcessedLength = aead || encryptThenMac
        const bodyOnlyAlignment = aead || encryptThenMac
        const minimumPacketLength = Math.max(MINIMUM_BINARY_PACKET_LENGTH, blockSize)
        if (this.buffered.length < (separatelyProcessedLength ? 4 : minimumPacketLength)) {
            return undefined
        }

        let firstBlock: Buffer
        if (this.protection?.aead) {
            firstBlock = this.protection.cipher.decryptPacketLength(
                this.sequenceNumber,
                this.buffered.subarray(0, 4),
            )
        } else if (this.protection && !separatelyProcessedLength) {
            const decryptedFirstBlock =
                this.decryptedFirstBlock ??
                this.protection.cipher.decrypt(this.buffered.subarray(0, blockSize))
            this.decryptedFirstBlock = decryptedFirstBlock
            firstBlock = decryptedFirstBlock
        } else if (!separatelyProcessedLength) {
            firstBlock = this.buffered.subarray(0, blockSize)
        } else {
            firstBlock = this.buffered.subarray(0, 4)
        }
        const expectedFirstBlockLength = separatelyProcessedLength ? 4 : blockSize
        if (firstBlock.length !== expectedFirstBlockLength) {
            throw new Error("SSH cipher returned an incomplete first packet block")
        }

        const packetLength = firstBlock.readUInt32BE(0)
        const authenticationLength =
            this.protection?.aead === true
                ? this.protection.authTagLength
                : (this.protection?.macLength ?? 0)
        const encryptedLength = 4 + packetLength
        const totalLength = encryptedLength + authenticationLength

        if (totalLength > this.maximumPacketSize) {
            throw new Error(
                `SSH binary packet size ${totalLength} exceeds maximum ${this.maximumPacketSize}`,
            )
        }
        if (encryptedLength < (bodyOnlyAlignment ? 4 + blockSize : minimumPacketLength)) {
            throw new Error(`SSH binary packet is shorter than ${minimumPacketLength} bytes`)
        }
        if ((bodyOnlyAlignment ? packetLength : encryptedLength) % blockSize !== 0) {
            throw new Error("SSH binary packet length is not a cipher block multiple")
        }
        if (this.buffered.length < totalLength) return undefined

        let plaintext: Buffer
        if (this.protection?.aead) {
            const ciphertext = this.buffered.subarray(0, encryptedLength)
            const authenticationTag = this.buffered.subarray(encryptedLength, totalLength)
            if (authenticationTag.length !== authenticationLength) {
                throw new Error("SSH binary packet has an invalid authentication tag length")
            }
            plaintext = this.protection.cipher.decryptPacket(
                this.sequenceNumber,
                ciphertext,
                authenticationTag,
            )
            if (plaintext.length !== encryptedLength) {
                throw new Error("SSH AEAD cipher returned an incomplete packet")
            }
            if (!plaintext.subarray(0, 4).equals(firstBlock)) {
                throw new Error("SSH AEAD cipher returned an inconsistent packet length")
            }
        } else if (this.protection && encryptThenMac) {
            const authenticated = this.buffered.subarray(0, encryptedLength)
            const receivedMAC = this.buffered.subarray(encryptedLength, totalLength)
            const expectedMAC = this.protection.mac.computeMAC(this.sequenceNumber, authenticated)
            if (
                expectedMAC.length !== authenticationLength ||
                receivedMAC.length !== authenticationLength
            ) {
                throw new Error("SSH binary packet has an invalid MAC length")
            }
            if (!timingSafeEqual(expectedMAC, receivedMAC)) {
                throw new Error("SSH binary packet MAC verification failed")
            }
            const body = this.protection.cipher.decrypt(this.buffered.subarray(4, encryptedLength))
            if (body.length !== packetLength) {
                throw new Error("SSH cipher returned an incomplete packet")
            }
            plaintext = Buffer.concat([firstBlock, body])
        } else if (this.protection) {
            const remaining = this.protection.cipher.decrypt(
                this.buffered.subarray(blockSize, encryptedLength),
            )
            plaintext = Buffer.concat([firstBlock, remaining])
            if (plaintext.length !== encryptedLength) {
                throw new Error("SSH cipher returned an incomplete packet")
            }

            const receivedMAC = this.buffered.subarray(encryptedLength, totalLength)
            const expectedMAC = this.protection.mac.computeMAC(this.sequenceNumber, plaintext)
            if (
                expectedMAC.length !== authenticationLength ||
                receivedMAC.length !== authenticationLength
            ) {
                throw new Error("SSH binary packet has an invalid MAC length")
            }
            if (!timingSafeEqual(expectedMAC, receivedMAC)) {
                throw new Error("SSH binary packet MAC verification failed")
            }
        } else {
            plaintext = this.buffered.subarray(0, encryptedLength)
        }

        const paddingLength = plaintext[4]
        if (paddingLength < 4) {
            throw new Error("SSH binary packet padding is shorter than 4 bytes")
        }
        if (packetLength <= paddingLength + 1) {
            throw new Error("SSH binary packet payload is empty or has an invalid length")
        }

        const payloadLength = packetLength - paddingLength - 1
        let payload = plaintext.subarray(5, 5 + payloadLength)
        payload = this.decompressor?.decompress(payload) ?? payload
        if (payload.length === 0) {
            throw new Error("SSH binary packet payload is empty after decompression")
        }
        const padding = plaintext.subarray(5 + payloadLength, encryptedLength)
        const data = this.buffered.subarray(0, totalLength)
        const sequenceNumber = this.sequenceNumber

        this.buffered = this.buffered.subarray(totalLength)
        this.decryptedFirstBlock = undefined
        if (this.protection) {
            this.protectedBytes = Math.min(
                Number.MAX_SAFE_INTEGER,
                this.protectedBytes + totalLength,
            )
        }
        if (this.sequenceNumber === SEQUENCE_NUMBER_MODULO - 1) this.sequenceNumberWrapped = true
        this.sequenceNumber = (this.sequenceNumber + 1) % SEQUENCE_NUMBER_MODULO

        return { sequenceNumber, payload, padding, data }
    }
}
