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

export interface OutboundPacketProtection {
    cipher: PacketEncryptor
    mac: PacketMAC
    blockSize: number
    macLength: number
    encryptThenMac?: boolean
}

export interface InboundPacketProtection {
    cipher: PacketDecryptor
    mac: PacketMAC
    blockSize: number
    macLength: number
    encryptThenMac?: boolean
}

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

function validateProtection(protection: { blockSize: number; macLength: number }): void {
    if (!Number.isSafeInteger(protection.blockSize) || protection.blockSize < 8) {
        throw new Error("SSH cipher block size must be an integer of at least 8 bytes")
    }
    if (!Number.isSafeInteger(protection.macLength) || protection.macLength < 0) {
        throw new Error("SSH MAC length must be a non-negative integer")
    }
}

export class BinaryPacketEncoder {
    private readonly maximumPacketSize: number
    private readonly randomBytes: (size: number) => Buffer
    private protection?: OutboundPacketProtection
    private sequenceNumber = 0

    constructor(options: BinaryPacketEncoderOptions = {}) {
        this.maximumPacketSize = options.maximumPacketSize ?? MAXIMUM_BINARY_PACKET_SIZE
        validateMaximumPacketSize(this.maximumPacketSize)
        this.randomBytes = options.randomBytes ?? crypto.randomBytes
    }

    setProtection(protection: OutboundPacketProtection): void {
        validateProtection(protection)
        this.protection = protection
    }

    encode(payload: Buffer): EncodedBinaryPacket {
        if (payload.length === 0) {
            throw new Error("SSH binary packet payload must not be empty")
        }

        const blockSize = Math.max(8, this.protection?.blockSize ?? 8)
        const encryptThenMac = this.protection?.encryptThenMac === true
        const alignedLength = (encryptThenMac ? 1 : 5) + payload.length
        let paddingLength = blockSize - (alignedLength % blockSize)
        if (paddingLength < 4) paddingLength += blockSize
        if (paddingLength > 255) {
            throw new Error("SSH binary packet padding must not exceed 255 bytes")
        }

        const packetLength = 1 + payload.length + paddingLength
        const macLength = this.protection?.macLength ?? 0
        const totalLength = 4 + packetLength + macLength
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
        let authenticated: Buffer
        if (this.protection && encryptThenMac) {
            const ciphertext = this.protection.cipher.encrypt(plaintext.subarray(4))
            if (ciphertext.length !== plaintext.length - 4) {
                throw new Error("SSH cipher changed the binary packet length")
            }
            packet = Buffer.concat([plaintext.subarray(0, 4), ciphertext])
            authenticated = packet
        } else {
            packet = this.protection?.cipher.encrypt(plaintext) ?? plaintext
            if (packet.length !== plaintext.length) {
                throw new Error("SSH cipher changed the binary packet length")
            }
            authenticated = plaintext
        }

        const mac =
            this.protection?.mac.computeMAC(sequenceNumber, authenticated) ?? Buffer.alloc(0)
        if (mac.length !== macLength) {
            throw new Error(`SSH MAC produced ${mac.length} bytes; expected ${macLength}`)
        }

        this.sequenceNumber = (this.sequenceNumber + 1) % SEQUENCE_NUMBER_MODULO
        return { sequenceNumber, data: Buffer.concat([packet, mac]) }
    }
}

export class BinaryPacketDecoder {
    private readonly maximumPacketSize: number
    private protection?: InboundPacketProtection
    private buffered = Buffer.alloc(0)
    private decryptedFirstBlock?: Buffer
    private sequenceNumber = 0

    constructor(options: BinaryPacketOptions = {}) {
        this.maximumPacketSize = options.maximumPacketSize ?? MAXIMUM_BINARY_PACKET_SIZE
        validateMaximumPacketSize(this.maximumPacketSize)
    }

    get bufferedLength(): number {
        return this.buffered.length
    }

    push(chunk: Buffer): void {
        if (chunk.length === 0) return
        this.buffered = Buffer.concat([this.buffered, chunk])
    }

    setProtection(protection: InboundPacketProtection): void {
        if (this.decryptedFirstBlock) {
            throw new Error("Cannot change SSH packet protection while decoding a packet")
        }
        validateProtection(protection)
        this.protection = protection
    }

    read(): DecodedBinaryPacket | undefined {
        const blockSize = Math.max(8, this.protection?.blockSize ?? 8)
        const encryptThenMac = this.protection?.encryptThenMac === true
        const minimumPacketLength = Math.max(MINIMUM_BINARY_PACKET_LENGTH, blockSize)
        if (this.buffered.length < (encryptThenMac ? 4 : minimumPacketLength)) return undefined

        let firstBlock: Buffer
        if (this.protection && !encryptThenMac) {
            this.decryptedFirstBlock ??= this.protection.cipher.decrypt(
                this.buffered.subarray(0, blockSize),
            )
            firstBlock = this.decryptedFirstBlock
        } else if (!encryptThenMac) {
            firstBlock = this.buffered.subarray(0, blockSize)
        } else {
            firstBlock = this.buffered.subarray(0, 4)
        }
        if (!encryptThenMac && firstBlock.length !== blockSize) {
            throw new Error("SSH cipher returned an incomplete first packet block")
        }

        const packetLength = firstBlock.readUInt32BE(0)
        const macLength = this.protection?.macLength ?? 0
        const encryptedLength = 4 + packetLength
        const totalLength = encryptedLength + macLength

        if (totalLength > this.maximumPacketSize) {
            throw new Error(
                `SSH binary packet size ${totalLength} exceeds maximum ${this.maximumPacketSize}`,
            )
        }
        if (encryptedLength < (encryptThenMac ? 4 + blockSize : minimumPacketLength)) {
            throw new Error(`SSH binary packet is shorter than ${minimumPacketLength} bytes`)
        }
        if ((encryptThenMac ? packetLength : encryptedLength) % blockSize !== 0) {
            throw new Error("SSH binary packet length is not a cipher block multiple")
        }
        if (this.buffered.length < totalLength) return undefined

        let plaintext: Buffer
        if (this.protection && encryptThenMac) {
            const authenticated = this.buffered.subarray(0, encryptedLength)
            const receivedMAC = this.buffered.subarray(encryptedLength, totalLength)
            const expectedMAC = this.protection.mac.computeMAC(this.sequenceNumber, authenticated)
            if (expectedMAC.length !== macLength || receivedMAC.length !== macLength) {
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
            if (expectedMAC.length !== macLength || receivedMAC.length !== macLength) {
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
        const payload = plaintext.subarray(5, 5 + payloadLength)
        const padding = plaintext.subarray(5 + payloadLength, encryptedLength)
        const data = this.buffered.subarray(0, totalLength)
        const sequenceNumber = this.sequenceNumber

        this.buffered = this.buffered.subarray(totalLength)
        this.decryptedFirstBlock = undefined
        this.sequenceNumber = (this.sequenceNumber + 1) % SEQUENCE_NUMBER_MODULO

        return { sequenceNumber, payload, padding, data }
    }
}
