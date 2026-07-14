import {
    BinaryPacketDecoder,
    BinaryPacketEncoder,
    MAXIMUM_BINARY_PACKET_SIZE,
} from "../../src/BinaryPacket.js"
import AES128CTR from "../../src/algorithms/encryption/aes128-ctr.js"
import AES128GCMOpenSSH from "../../src/algorithms/encryption/aes128-gcm-openssh.js"
import ChaCha20Poly1305OpenSSH from "../../src/algorithms/encryption/chacha20-poly1305-openssh.js"
import HMACSHA2256 from "../../src/algorithms/mac/hmac-sha2-256.js"
import HMACSHA196 from "../../src/algorithms/mac/hmac-sha1-96.js"
import HMACSHA196ETM from "../../src/algorithms/mac/hmac-sha1-96-etm.js"
import HMACMD5 from "../../src/algorithms/mac/hmac-md5.js"
import HMACMD596 from "../../src/algorithms/mac/hmac-md5-96.js"
import HMACMD5ETM from "../../src/algorithms/mac/hmac-md5-etm.js"
import HMACMD596ETM from "../../src/algorithms/mac/hmac-md5-96-etm.js"

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

function createSHA196ProtectionPair(encryptThenMac: boolean) {
    const key = Buffer.from("00112233445566778899aabbccddeeff", "hex")
    const iv = Buffer.from("ffeeddccbbaa99887766554433221100", "hex")
    const macKey = Buffer.alloc(HMACSHA196.key_length, 0x24)
    const MAC = encryptThenMac ? HMACSHA196ETM : HMACSHA196
    return {
        outbound: {
            cipher: new AES128CTR(key, iv),
            mac: new MAC(macKey),
            blockSize: AES128CTR.block_size,
            macLength: MAC.digest_length,
            encryptThenMac,
        },
        inbound: {
            cipher: new AES128CTR(key, iv),
            mac: new MAC(macKey),
            blockSize: AES128CTR.block_size,
            macLength: MAC.digest_length,
            encryptThenMac,
        },
    }
}

function createMD5ProtectionPair(
    MAC: typeof HMACMD5 | typeof HMACMD596 | typeof HMACMD5ETM | typeof HMACMD596ETM,
) {
    const key = Buffer.from("00112233445566778899aabbccddeeff", "hex")
    const iv = Buffer.from("ffeeddccbbaa99887766554433221100", "hex")
    const macKey = Buffer.alloc(MAC.key_length, 0x42)
    return {
        outbound: {
            cipher: new AES128CTR(key, iv),
            mac: new MAC(macKey),
            blockSize: AES128CTR.block_size,
            macLength: MAC.digest_length,
            encryptThenMac: MAC.encrypt_then_mac,
        },
        inbound: {
            cipher: new AES128CTR(key, iv),
            mac: new MAC(macKey),
            blockSize: AES128CTR.block_size,
            macLength: MAC.digest_length,
            encryptThenMac: MAC.encrypt_then_mac,
        },
    }
}

function createAEADProtectionPair() {
    const key = Buffer.alloc(16)
    const iv = Buffer.alloc(12)
    return {
        outbound: {
            aead: true as const,
            cipher: new AES128GCMOpenSSH(key, iv),
            blockSize: AES128GCMOpenSSH.block_size,
            authTagLength: AES128GCMOpenSSH.auth_tag_length,
        },
        inbound: {
            aead: true as const,
            cipher: new AES128GCMOpenSSH(key, iv),
            blockSize: AES128GCMOpenSSH.block_size,
            authTagLength: AES128GCMOpenSSH.auth_tag_length,
        },
    }
}

function createChaChaProtectionPair() {
    const key = Buffer.from(Array.from({ length: 64 }, (_, index) => index))
    const iv = Buffer.alloc(0)
    return {
        outbound: {
            aead: true as const,
            cipher: new ChaCha20Poly1305OpenSSH(key, iv),
            blockSize: ChaCha20Poly1305OpenSSH.block_size,
            authTagLength: ChaCha20Poly1305OpenSSH.auth_tag_length,
        },
        inbound: {
            aead: true as const,
            cipher: new ChaCha20Poly1305OpenSSH(key, iv),
            blockSize: ChaCha20Poly1305OpenSSH.block_size,
            authTagLength: ChaCha20Poly1305OpenSSH.auth_tag_length,
        },
    }
}

describe("BinaryPacket", () => {
    test("counts authenticated wire bytes per packet-protection epoch", () => {
        const encoder = new BinaryPacketEncoder({ randomBytes: deterministicPadding })
        const decoder = new BinaryPacketDecoder()
        const unprotected = encoder.encode(Buffer.from("initial exchange"))
        decoder.push(unprotected.data)
        expect(decoder.read()?.payload).toEqual(Buffer.from("initial exchange"))
        expect(encoder.bytesProtected).toBe(0)
        expect(decoder.bytesProtected).toBe(0)

        const protection = createProtectionPair()
        encoder.setProtection(protection.outbound)
        decoder.setProtection(protection.inbound)

        const encoded = encoder.encode(Buffer.from("protected payload"))
        expect(encoder.bytesProtected).toBe(encoded.data.length)
        decoder.push(encoded.data)
        expect(decoder.read()?.payload).toEqual(Buffer.from("protected payload"))
        expect(decoder.bytesProtected).toBe(encoded.data.length)

        const replacement = createProtectionPair()
        encoder.setProtection(replacement.outbound)
        decoder.setProtection(replacement.inbound)
        expect(encoder.bytesProtected).toBe(0)
        expect(decoder.bytesProtected).toBe(0)
    })

    test.each([false, true])(
        "authenticates packets with a 96-bit HMAC-SHA1 tag (etm=%s)",
        (encryptThenMac) => {
            const payload = Buffer.from("5e000000070000000474657374", "hex")
            const encoder = new BinaryPacketEncoder({ randomBytes: deterministicPadding })
            encoder.setProtection(createSHA196ProtectionPair(encryptThenMac).outbound)
            const encoded = encoder.encode(payload).data
            expect(encoded.subarray(-12)).toHaveLength(12)

            const decoder = new BinaryPacketDecoder()
            decoder.setProtection(createSHA196ProtectionPair(encryptThenMac).inbound)
            decoder.push(encoded)
            expect(decoder.read()?.payload).toEqual(payload)

            const modified = Buffer.from(encoded)
            modified[modified.length - 1] ^= 0x01
            const rejectingDecoder = new BinaryPacketDecoder()
            rejectingDecoder.setProtection(createSHA196ProtectionPair(encryptThenMac).inbound)
            rejectingDecoder.push(modified)
            expect(() => rejectingDecoder.read()).toThrow("MAC verification failed")
        },
    )

    test.each([HMACMD5, HMACMD596, HMACMD5ETM, HMACMD596ETM])(
        "authenticates and rejects tampering with %s packets",
        (MAC) => {
            const payload = Buffer.from("5e00000007000000046d643521", "hex")
            const encoder = new BinaryPacketEncoder({ randomBytes: deterministicPadding })
            encoder.setProtection(createMD5ProtectionPair(MAC).outbound)
            const encoded = encoder.encode(payload).data
            expect(encoded.subarray(-MAC.digest_length)).toHaveLength(MAC.digest_length)

            const decoder = new BinaryPacketDecoder()
            decoder.setProtection(createMD5ProtectionPair(MAC).inbound)
            decoder.push(encoded)
            expect(decoder.read()?.payload).toEqual(payload)

            const modified = Buffer.from(encoded)
            modified[modified.length - 1] ^= 0x01
            const rejectingDecoder = new BinaryPacketDecoder()
            rejectingDecoder.setProtection(createMD5ProtectionPair(MAC).inbound)
            rejectingDecoder.push(modified)
            expect(() => rejectingDecoder.read()).toThrow("MAC verification failed")
        },
    )

    test("resets both implicit sequence counters after NEWKEYS", () => {
        const encoder = new BinaryPacketEncoder({ randomBytes: deterministicPadding })
        const decoder = new BinaryPacketDecoder()

        expect(encoder.encode(Buffer.from([20])).sequenceNumber).toBe(0)
        const packet = encoder.encode(Buffer.from([21]))
        expect(packet.sequenceNumber).toBe(1)
        decoder.push(packet.data)
        expect(decoder.read()?.sequenceNumber).toBe(0)

        encoder.resetSequenceNumber()
        decoder.resetSequenceNumber()
        const firstAfterNewKeys = encoder.encode(Buffer.from([7]))
        decoder.push(firstAfterNewKeys.data)
        expect(firstAfterNewKeys.sequenceNumber).toBe(0)
        expect(decoder.read()?.sequenceNumber).toBe(0)
        expect(encoder.hasSequenceNumberWrapped).toBe(false)
        expect(decoder.hasSequenceNumberWrapped).toBe(false)
    })

    test("retains sequence wrap evidence until NEWKEYS resets each direction", () => {
        const encoder = new BinaryPacketEncoder({ randomBytes: deterministicPadding })
        const encoderState = encoder as unknown as { sequenceNumber: number }
        encoderState.sequenceNumber = 0xffff_ffff
        const wrappedPacket = encoder.encode(Buffer.from([2]))

        expect(wrappedPacket.sequenceNumber).toBe(0xffff_ffff)
        expect(encoder.hasSequenceNumberWrapped).toBe(true)
        expect(encoder.encode(Buffer.from([2])).sequenceNumber).toBe(0)

        const decoder = new BinaryPacketDecoder()
        const decoderState = decoder as unknown as { sequenceNumber: number }
        decoderState.sequenceNumber = 0xffff_ffff
        decoder.push(wrappedPacket.data)
        expect(decoder.read()?.sequenceNumber).toBe(0xffff_ffff)
        expect(decoder.hasSequenceNumberWrapped).toBe(true)

        encoder.resetSequenceNumber()
        decoder.resetSequenceNumber()
        expect(encoder.hasSequenceNumberWrapped).toBe(false)
        expect(decoder.hasSequenceNumberWrapped).toBe(false)
    })

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

    test("matches fixed independently generated AES-GCM SSH packets", () => {
        const payload = Buffer.from("3200000000", "hex")
        const expected = [
            Buffer.from(
                "0000001009badace60b60637568d671cd4175bdd9a5bcd4e0f1b1df5e1cb8d501abdb81d",
                "hex",
            ),
            Buffer.from(
                "000000106433d9300788d718fe974931c058e23da259872c073de091f471d5ffc0ef318d",
                "hex",
            ),
        ]

        const encoder = new BinaryPacketEncoder({ randomBytes: deterministicPadding })
        encoder.setProtection(createAEADProtectionPair().outbound)
        expect(encoder.encode(payload).data).toEqual(expected[0])
        expect(encoder.encode(payload).data).toEqual(expected[1])

        for (let split = 0; split <= expected[0].length; split++) {
            const decoder = new BinaryPacketDecoder()
            decoder.setProtection(createAEADProtectionPair().inbound)
            decoder.push(expected[0].subarray(0, split))
            const beforeRemainder = decoder.read()
            if (split < expected[0].length) expect(beforeRemainder).toBeUndefined()
            decoder.push(expected[0].subarray(split))
            expect((beforeRemainder ?? decoder.read())?.payload).toEqual(payload)
        }
    })

    test("rejects modified AES-GCM packet lengths, ciphertext, and tags", () => {
        const encoder = new BinaryPacketEncoder({ randomBytes: deterministicPadding })
        encoder.setProtection(createAEADProtectionPair().outbound)
        const encoded = encoder.encode(Buffer.from("3200000000", "hex")).data

        for (const offset of [3, 4, encoded.length - 1]) {
            const modified = Buffer.from(encoded)
            modified[offset] ^= 0x01
            const decoder = new BinaryPacketDecoder()
            decoder.setProtection(createAEADProtectionPair().inbound)
            decoder.push(modified)
            expect(() => decoder.read()).toThrow()
        }
    })

    test("matches fixed independently generated ChaCha20-Poly1305 SSH packets", () => {
        const payload = Buffer.from("3200000000", "hex")
        const expected = [
            Buffer.from(
                "94450e49128a4231ade60374b6c4f9c40ae6eb828399b62625d3409d9b3678bc14fcc039",
                "hex",
            ),
            Buffer.from(
                "c922a7b5636e7cd9310a1ddf88d4db8a16b1b2b7b2e0fa4ee7251ad0710567fb5d1f6955",
                "hex",
            ),
        ]

        const encoder = new BinaryPacketEncoder({ randomBytes: deterministicPadding })
        encoder.setProtection(createChaChaProtectionPair().outbound)
        expect(encoder.encode(payload).data).toEqual(expected[0])
        expect(encoder.encode(payload).data).toEqual(expected[1])

        for (let split = 0; split <= expected[0].length; split++) {
            const decoder = new BinaryPacketDecoder()
            decoder.setProtection(createChaChaProtectionPair().inbound)
            decoder.push(expected[0].subarray(0, split))
            const beforeRemainder = decoder.read()
            if (split < expected[0].length) expect(beforeRemainder).toBeUndefined()
            decoder.push(expected[0].subarray(split))
            expect((beforeRemainder ?? decoder.read())?.payload).toEqual(payload)
        }
    })

    test("rejects modified ChaCha20-Poly1305 lengths, ciphertext, and tags", () => {
        const encoder = new BinaryPacketEncoder({ randomBytes: deterministicPadding })
        encoder.setProtection(createChaChaProtectionPair().outbound)
        const encoded = encoder.encode(Buffer.from("3200000000", "hex")).data

        for (const offset of [0, 4, encoded.length - 1]) {
            const modified = Buffer.from(encoded)
            modified[offset] ^= 0x01
            const decoder = new BinaryPacketDecoder()
            decoder.setProtection(createChaChaProtectionPair().inbound)
            decoder.push(modified)
            expect(() => decoder.read()).toThrow()
        }
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
