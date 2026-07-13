import {
    BinaryPacketDecoder,
    BinaryPacketEncoder,
    MAXIMUM_BINARY_PACKET_SIZE,
} from "../../src/BinaryPacket.js"
import AES128CTR from "../../src/algorithms/encryption/aes128-ctr.js"
import HMACSHA2256 from "../../src/algorithms/mac/hmac-sha2-256.js"

const deterministicPadding = (size: number): Buffer => Buffer.alloc(size, 0xa5)

function createProtectionPair() {
    const key = Buffer.from("00112233445566778899aabbccddeeff", "hex")
    const iv = Buffer.from("ffeeddccbbaa99887766554433221100", "hex")
    const macKey = Buffer.alloc(HMACSHA2256.key_length, 0x42)

    return {
        outbound: {
            cipher: new AES128CTR(key, iv),
            mac: new HMACSHA2256(macKey),
            blockSize: AES128CTR.block_size,
            macLength: HMACSHA2256.digest_length,
        },
        inbound: {
            cipher: new AES128CTR(key, iv),
            mac: new HMACSHA2256(macKey),
            blockSize: AES128CTR.block_size,
            macLength: HMACSHA2256.digest_length,
        },
    }
}

function createETMProtectionPair() {
    const protection = createProtectionPair()
    return {
        outbound: { ...protection.outbound, encryptThenMac: true },
        inbound: { ...protection.inbound, encryptThenMac: true },
    }
}

describe("BinaryPacket", () => {
    test("encodes RFC 4253 framing with deterministic minimum padding", () => {
        const encoder = new BinaryPacketEncoder({ randomBytes: deterministicPadding })
        const encoded = encoder.encode(Buffer.from([20]))

        expect(encoded.sequenceNumber).toBe(0)
        expect(encoded.data.length).toBe(16)
        expect(encoded.data.readUInt32BE(0)).toBe(12)
        expect(encoded.data[4]).toBe(10)
        expect(encoded.data[5]).toBe(20)
        expect(encoded.data.subarray(6)).toEqual(Buffer.alloc(10, 0xa5))
    })

    test("decodes an unprotected packet at every fragmentation boundary", () => {
        const payload = Buffer.from("140102030405", "hex")
        const encoded = new BinaryPacketEncoder({ randomBytes: deterministicPadding }).encode(
            payload,
        ).data

        for (let split = 0; split <= encoded.length; split++) {
            const decoder = new BinaryPacketDecoder()
            decoder.push(encoded.subarray(0, split))
            const beforeRemainder = decoder.read()
            if (split < encoded.length) expect(beforeRemainder).toBeUndefined()

            decoder.push(encoded.subarray(split))
            const decoded = beforeRemainder ?? decoder.read()
            expect(decoded?.sequenceNumber).toBe(0)
            expect(decoded?.payload).toEqual(payload)
            expect(decoded?.data).toEqual(encoded)
            expect(decoder.bufferedLength).toBe(0)
        }
    })

    test("decodes multiple packets and advances sequence numbers", () => {
        const encoder = new BinaryPacketEncoder({ randomBytes: deterministicPadding })
        const first = encoder.encode(Buffer.from([20]))
        const second = encoder.encode(Buffer.from([21]))
        const decoder = new BinaryPacketDecoder()
        decoder.push(Buffer.concat([first.data, second.data]))

        expect(decoder.read()?.sequenceNumber).toBe(0)
        expect(decoder.read()?.sequenceNumber).toBe(1)
        expect(decoder.read()).toBeUndefined()
    })

    test("switches to encryption and MAC after an unprotected NEWKEYS packet", () => {
        const encoder = new BinaryPacketEncoder({ randomBytes: deterministicPadding })
        const newKeys = encoder.encode(Buffer.from([21]))
        const protection = createProtectionPair()
        encoder.setProtection(protection.outbound)
        const encrypted = encoder.encode(Buffer.from("050000000c7373682d7573657261757468", "hex"))

        const decoder = new BinaryPacketDecoder()
        decoder.push(Buffer.concat([newKeys.data, encrypted.data]))
        expect(decoder.read()?.payload).toEqual(Buffer.from([21]))

        decoder.setProtection(protection.inbound)
        const decoded = decoder.read()
        expect(decoded?.sequenceNumber).toBe(1)
        expect(decoded?.payload).toEqual(Buffer.from("050000000c7373682d7573657261757468", "hex"))
        expect(decoder.bufferedLength).toBe(0)
    })

    test("decodes protected packets at every fragmentation boundary", () => {
        const payload = Buffer.from("3200000000", "hex")

        for (let split = 0; split <= 80; split++) {
            const protection = createProtectionPair()
            const encoder = new BinaryPacketEncoder({ randomBytes: deterministicPadding })
            encoder.setProtection(protection.outbound)
            const encoded = encoder.encode(payload).data
            if (split > encoded.length) continue

            const decoder = new BinaryPacketDecoder()
            decoder.setProtection(protection.inbound)
            decoder.push(encoded.subarray(0, split))
            const beforeRemainder = decoder.read()
            if (split < encoded.length) expect(beforeRemainder).toBeUndefined()

            decoder.push(encoded.subarray(split))
            expect((beforeRemainder ?? decoder.read())?.payload).toEqual(payload)
        }
    })

    test("matches a fixed OpenSSH encrypt-then-MAC packet at every fragmentation boundary", () => {
        const payload = Buffer.from("3200000000", "hex")
        const expected = Buffer.from(
            "000000107813393918a2e8d8ab4657879e5ffe9007483086a0346f359eaa8b566ba5329fbc91163f1d4cd5e02b11c84fc3332742",
            "hex",
        )

        const encodedProtection = createETMProtectionPair()
        const encoder = new BinaryPacketEncoder({ randomBytes: deterministicPadding })
        encoder.setProtection(encodedProtection.outbound)
        expect(encoder.encode(payload).data).toEqual(expected)

        for (let split = 0; split <= expected.length; split++) {
            const protection = createETMProtectionPair()
            const decoder = new BinaryPacketDecoder()
            decoder.setProtection(protection.inbound)
            decoder.push(expected.subarray(0, split))
            const beforeRemainder = decoder.read()
            if (split < expected.length) expect(beforeRemainder).toBeUndefined()
            decoder.push(expected.subarray(split))
            expect((beforeRemainder ?? decoder.read())?.payload).toEqual(payload)
        }
    })

    test("verifies an ETM tag before decrypting ciphertext", () => {
        const outbound = createETMProtectionPair()
        const encoder = new BinaryPacketEncoder({ randomBytes: deterministicPadding })
        encoder.setProtection(outbound.outbound)
        const encoded = Buffer.from(encoder.encode(Buffer.from([20])).data)
        encoded[5] ^= 0xff

        const inbound = createETMProtectionPair().inbound
        let decryptions = 0
        const decoder = new BinaryPacketDecoder()
        decoder.setProtection({
            ...inbound,
            cipher: {
                decrypt: (ciphertext) => {
                    decryptions++
                    return inbound.cipher.decrypt(ciphertext)
                },
            },
        })
        decoder.push(encoded)

        expect(() => decoder.read()).toThrow("MAC verification failed")
        expect(decryptions).toBe(0)
    })

    test("rejects a modified MAC", () => {
        const protection = createProtectionPair()
        const encoder = new BinaryPacketEncoder({ randomBytes: deterministicPadding })
        encoder.setProtection(protection.outbound)
        const encoded = Buffer.from(encoder.encode(Buffer.from([20])).data)
        encoded[encoded.length - 1] ^= 0xff

        const decoder = new BinaryPacketDecoder()
        decoder.setProtection(protection.inbound)
        decoder.push(encoded)
        expect(() => decoder.read()).toThrow("MAC verification failed")
    })

    test("supports the RFC-required maximum packet size", () => {
        const payload = Buffer.alloc(34991, 0x01)
        const encoder = new BinaryPacketEncoder({ randomBytes: deterministicPadding })
        const encoded = encoder.encode(payload).data
        expect(encoded.length).toBe(MAXIMUM_BINARY_PACKET_SIZE)

        const decoder = new BinaryPacketDecoder()
        decoder.push(encoded)
        expect(decoder.read()?.payload).toEqual(payload)
    })

    test("rejects oversized lengths before buffering the claimed packet", () => {
        const decoder = new BinaryPacketDecoder()
        const headerBlock = Buffer.alloc(16)
        headerBlock.writeUInt32BE(MAXIMUM_BINARY_PACKET_SIZE, 0)
        headerBlock[4] = 4
        decoder.push(headerBlock)

        expect(() => decoder.read()).toThrow("exceeds maximum")
    })

    test.each([
        ["short padding", 12, 3],
        ["non-block multiple", 13, 4],
        ["empty payload", 12, 11],
    ])("rejects malformed framing: %s", (_, packetLength, paddingLength) => {
        const decoder = new BinaryPacketDecoder()
        const packet = Buffer.alloc(24)
        packet.writeUInt32BE(packetLength, 0)
        packet[4] = paddingLength
        decoder.push(packet)

        expect(() => decoder.read()).toThrow()
    })

    test("rejects outbound packets above the configured maximum", () => {
        const encoder = new BinaryPacketEncoder({ randomBytes: deterministicPadding })

        expect(() => encoder.encode(Buffer.alloc(34992, 0x01))).toThrow("exceeds maximum")
    })
})
