import AES128GCMOpenSSH from "../../src/algorithms/encryption/aes128-gcm-openssh.js"
import AES256GCMOpenSSH from "../../src/algorithms/encryption/aes256-gcm-openssh.js"
import { AEADAES128GCM, AEADAES256GCM } from "../../src/algorithms/encryption/aead-aes-gcm.js"

describe("RFC 5647 AES-GCM", () => {
    test("uses the registered encryption and MAC names", () => {
        expect(AEADAES128GCM.alg_name).toBe("AEAD_AES_128_GCM")
        expect(AEADAES128GCM.required_mac).toBe("AEAD_AES_128_GCM")
        expect(AEADAES256GCM.alg_name).toBe("AEAD_AES_256_GCM")
        expect(AEADAES256GCM.required_mac).toBe("AEAD_AES_256_GCM")
    })

    test("matches the NIST AES-128-GCM authenticated-encryption vector", () => {
        const key = Buffer.alloc(16)
        const iv = Buffer.alloc(12)
        const plaintext = Buffer.alloc(16)
        const expectedCiphertext = Buffer.from("0388dace60b6a392f328c2b971b2fe78", "hex")
        const expectedTag = Buffer.from("ab6e47d42cec13bdf53a67b21257bddf", "hex")

        const encrypted = new AES128GCMOpenSSH(key, iv).encryptAuthenticated(
            plaintext,
            Buffer.alloc(0),
        )
        expect(encrypted.ciphertext).toEqual(expectedCiphertext)
        expect(encrypted.authenticationTag).toEqual(expectedTag)

        expect(
            new AES128GCMOpenSSH(key, iv).decryptAuthenticated(
                expectedCiphertext,
                Buffer.alloc(0),
                expectedTag,
            ),
        ).toEqual(plaintext)
    })

    test("forms the RFC 5647 packet with its length as authenticated data", () => {
        const key = Buffer.from("000102030405060708090a0b0c0d0e0f", "hex")
        const iv = Buffer.from("101112131415161718191a1b", "hex")
        const packet = Buffer.from(
            "00000020" +
                "10" +
                "5041594c4f41442d564543544f5221" +
                "000102030405060708090a0b0c0d0e0f",
            "hex",
        )
        const cipher = new AEADAES128GCM(key, iv)

        expect(cipher.encryptPacket(0, packet)).toEqual({
            ciphertext: Buffer.from(
                "00000020d47e42f64300f7ab3a8b18b69368b91f3abd768432f16db88dc2231a6b081fa2",
                "hex",
            ),
            authenticationTag: Buffer.from("5d0f67d77660dec3491b09c3cbeb3286", "hex"),
        })
    })

    test("rejects modified ciphertext, associated data, and authentication tags", () => {
        const key = Buffer.alloc(32, 0x42)
        const iv = Buffer.from("0102030405060708090a0b0c", "hex")
        const associatedData = Buffer.from("00000010", "hex")
        const plaintext = Buffer.alloc(16, 0xa5)
        const encrypted = new AES256GCMOpenSSH(key, iv).encryptAuthenticated(
            plaintext,
            associatedData,
        )

        for (const [ciphertext, aad, tag] of [
            [Buffer.from(encrypted.ciphertext), associatedData, encrypted.authenticationTag],
            [encrypted.ciphertext, Buffer.from(associatedData), encrypted.authenticationTag],
            [encrypted.ciphertext, associatedData, Buffer.from(encrypted.authenticationTag)],
        ] as const) {
            if (ciphertext !== encrypted.ciphertext) ciphertext[0] ^= 0x01
            else if (aad !== associatedData) aad[0] ^= 0x01
            else tag[0] ^= 0x01

            expect(() =>
                new AES256GCMOpenSSH(key, iv).decryptAuthenticated(ciphertext, aad, tag),
            ).toThrow("authentication failed")
        }
    })

    test("validates key, IV, and tag lengths", () => {
        expect(() => new AES128GCMOpenSSH(Buffer.alloc(15), Buffer.alloc(12))).toThrow(
            "key must be 16 bytes",
        )
        expect(() => new AES128GCMOpenSSH(Buffer.alloc(16), Buffer.alloc(11))).toThrow(
            "IV must be 12 bytes",
        )
        expect(() =>
            new AES128GCMOpenSSH(Buffer.alloc(16), Buffer.alloc(12)).decryptAuthenticated(
                Buffer.alloc(16),
                Buffer.alloc(4),
                Buffer.alloc(15),
            ),
        ).toThrow("tag must be 16 bytes")
    })

    test("refuses to reuse an invocation counter after its uint64 maximum", () => {
        const iv = Buffer.from("01020304ffffffffffffffff", "hex")
        const cipher = new AES128GCMOpenSSH(Buffer.alloc(16), iv)
        cipher.encryptAuthenticated(Buffer.alloc(16), Buffer.alloc(4))

        expect(() => cipher.encryptAuthenticated(Buffer.alloc(16), Buffer.alloc(4))).toThrow(
            "counter exhausted; rekey is required",
        )
    })
})
