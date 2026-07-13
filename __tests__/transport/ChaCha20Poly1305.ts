import ChaCha20Poly1305OpenSSH from "../../src/algorithms/encryption/chacha20-poly1305-openssh.js"

const key = Buffer.from(Array.from({ length: 64 }, (_, index) => index))
const packet = Buffer.from("000000100a3200000000a5a5a5a5a5a5a5a5a5a5", "hex")

describe("OpenSSH ChaCha20-Poly1305", () => {
    test("decrypts the packet length separately and authenticates before returning plaintext", () => {
        const encrypted = new ChaCha20Poly1305OpenSSH(key, Buffer.alloc(0)).encryptPacket(7, packet)
        const decryptor = new ChaCha20Poly1305OpenSSH(key, Buffer.alloc(0))

        expect(decryptor.decryptPacketLength(7, encrypted.ciphertext.subarray(0, 4))).toEqual(
            packet.subarray(0, 4),
        )
        expect(
            decryptor.decryptPacket(7, encrypted.ciphertext, encrypted.authenticationTag),
        ).toEqual(packet)

        const modifiedTag = Buffer.from(encrypted.authenticationTag)
        modifiedTag[0] ^= 0x01
        expect(() =>
            new ChaCha20Poly1305OpenSSH(key, Buffer.alloc(0)).decryptPacket(
                7,
                encrypted.ciphertext,
                modifiedTag,
            ),
        ).toThrow("authentication failed")
    })

    test("rejects sequence reuse and wrap under one key", () => {
        const reused = new ChaCha20Poly1305OpenSSH(key, Buffer.alloc(0))
        reused.encryptPacket(7, packet)
        expect(() => reused.encryptPacket(7, packet)).toThrow("nonce reuse; rekey is required")

        const wrapped = new ChaCha20Poly1305OpenSSH(key, Buffer.alloc(0))
        wrapped.encryptPacket(0xffff_ffff, packet)
        expect(() => wrapped.encryptPacket(0, packet)).toThrow("nonce reuse; rekey is required")

        const inboundWrap = new ChaCha20Poly1305OpenSSH(key, Buffer.alloc(0))
        const finalPacket = new ChaCha20Poly1305OpenSSH(key, Buffer.alloc(0)).encryptPacket(
            0xffff_ffff,
            packet,
        )
        inboundWrap.decryptPacket(
            0xffff_ffff,
            finalPacket.ciphertext,
            finalPacket.authenticationTag,
        )
        expect(() =>
            inboundWrap.decryptPacketLength(0, finalPacket.ciphertext.subarray(0, 4)),
        ).toThrow("nonce reuse; rekey is required")
    })

    test("validates key, IV, packet, tag, and sequence inputs", () => {
        expect(() => new ChaCha20Poly1305OpenSSH(Buffer.alloc(63), Buffer.alloc(0))).toThrow(
            "key must be 64 bytes",
        )
        expect(() => new ChaCha20Poly1305OpenSSH(Buffer.alloc(64), Buffer.alloc(1))).toThrow(
            "does not use a derived IV",
        )
        const cipher = new ChaCha20Poly1305OpenSSH(key, Buffer.alloc(0))
        expect(() => cipher.encryptPacket(0, Buffer.alloc(3))).toThrow("missing its length")
        expect(() => cipher.decryptPacketLength(-1, Buffer.alloc(4))).toThrow("sequence number")
        expect(() => cipher.decryptPacket(0, packet, Buffer.alloc(15))).toThrow(
            "tag must be 16 bytes",
        )
    })
})
