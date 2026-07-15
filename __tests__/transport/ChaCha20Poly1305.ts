import ChaCha20Poly1305OpenSSH, {
    ChaCha20Poly1305,
} from "../../src/algorithms/encryption/chacha20-poly1305-openssh.js"

const key = Buffer.from(Array.from({ length: 64 }, (_, index) => index))
const packet = Buffer.from("000000100a3200000000a5a5a5a5a5a5a5a5a5a5", "hex")

describe("SSH ChaCha20-Poly1305", () => {
    test.each([ChaCha20Poly1305, ChaCha20Poly1305OpenSSH])(
        "matches the published packet for $alg_name",
        (Cipher) => {
            const publishedKey = Buffer.from(
                "8bbff6855fc102338c373e73aac0c914f076a905b2444a32eecaffeae22becc5e9b7a7a5825a8249346ec1c28301cf394543fc7569887d76e168f37562ac0740",
                "hex",
            )
            const plaintext = Buffer.from(
                "00000048065e00000000000000384c6f72656d20697073756d20646f6c6f722073697420616d65742c20636f6e7365637465747572206164697069736963696e6720656c69744e43e804dc6c",
                "hex",
            )
            const expectedCiphertext = Buffer.from(
                "2c3ecce4a5bc05895bf07a7ba956b6c68829ac7c83b780b7000ecde745afc705bbc378ce03a280236b87b53bed5839662302b164b6286a48cd1e097138e3cb909b8b2b829dd18d2a35ff82d9",
                "hex",
            )
            const expectedTag = Buffer.from("95349e855bf02c298ef775f2d1a7e8b8", "hex")

            const encrypted = new Cipher(publishedKey, Buffer.alloc(0)).encryptPacket(7, plaintext)
            expect(encrypted.ciphertext).toEqual(expectedCiphertext)
            expect(encrypted.authenticationTag).toEqual(expectedTag)

            const decryptor = new Cipher(publishedKey, Buffer.alloc(0))
            expect(decryptor.decryptPacketLength(7, expectedCiphertext.subarray(0, 4))).toEqual(
                plaintext.subarray(0, 4),
            )
            expect(decryptor.decryptPacket(7, expectedCiphertext, expectedTag)).toEqual(plaintext)
        },
    )

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
