import { BinaryPacketDecoder, BinaryPacketEncoder } from "../../src/BinaryPacket.js"
import AES128CBC from "../../src/algorithms/encryption/aes128-cbc.js"
import AES192CBC from "../../src/algorithms/encryption/aes192-cbc.js"
import AES256CBC from "../../src/algorithms/encryption/aes256-cbc.js"
import BlowfishCBC from "../../src/algorithms/encryption/blowfish-cbc.js"
import Cast128CBC from "../../src/algorithms/encryption/cast128-cbc.js"
import TripleDESCBC from "../../src/algorithms/encryption/triple-des-cbc.js"
import HMACSHA2256 from "../../src/algorithms/mac/hmac-sha2-256.js"

const aesIV = Buffer.from("000102030405060708090a0b0c0d0e0f", "hex")
const aesPlaintext = [
    Buffer.from("6bc1bee22e409f96e93d7e117393172a", "hex"),
    Buffer.from("ae2d8a571e03ac9c9eb76fac45af8e51", "hex"),
]

describe("RFC 4253 CBC ciphers", () => {
    test("cast128-cbc matches the RFC 2144 128-bit-key vector", () => {
        const key = Buffer.from("0123456712345678234567893456789a", "hex")
        const iv = Buffer.alloc(8)
        const plaintext = Buffer.from("0123456789abcdef", "hex")
        const ciphertext = Buffer.from("238b4fe5847e44b2", "hex")
        const encryptor = new Cast128CBC(key, iv)
        key.fill(0)
        iv.fill(0xff)

        expect(encryptor.encrypt(plaintext)).toEqual(ciphertext)
        expect(
            new Cast128CBC(
                Buffer.from("0123456712345678234567893456789a", "hex"),
                Buffer.alloc(8),
            ).decrypt(ciphertext),
        ).toEqual(plaintext)
    })

    test("cast128-cbc matches an independent multi-block CBC vector", () => {
        const key = Buffer.from("0123456712345678234567893456789a", "hex")
        const iv = Buffer.from("fedcba9876543210", "hex")
        const plaintext = Buffer.from("00112233445566778899aabbccddeeff", "hex")
        const ciphertext = Buffer.from("ce09aca5613861388c37e87e48d15546", "hex")

        expect(new Cast128CBC(key, iv).encrypt(plaintext)).toEqual(ciphertext)
        expect(new Cast128CBC(key, iv).decrypt(ciphertext)).toEqual(plaintext)
    })

    test("blowfish-cbc matches the published 128-bit-key chaining vector", () => {
        const key = Buffer.from("0123456789abcdeff0e1d2c3b4a59687", "hex")
        const iv = Buffer.from("fedcba9876543210", "hex")
        const plaintext = Buffer.from(
            "37363534333231204e6f77206973207468652074696d6520666f722000000000",
            "hex",
        )
        const ciphertext = Buffer.from(
            "6b77b4d63006dee605b156e27403979358deb9e7154616d959f1652bd5ff92cc",
            "hex",
        )
        const encryptor = new BlowfishCBC(key, iv)
        key.fill(0)
        iv.fill(0)

        expect(encryptor.encrypt(plaintext)).toEqual(ciphertext)
        expect(
            new BlowfishCBC(
                Buffer.from("0123456789abcdeff0e1d2c3b4a59687", "hex"),
                Buffer.from("fedcba9876543210", "hex"),
            ).decrypt(ciphertext),
        ).toEqual(plaintext)
    })

    test.each([
        [
            AES128CBC,
            "2b7e151628aed2a6abf7158809cf4f3c",
            ["7649abac8119b246cee98e9b12e9197d", "5086cb9b507219ee95db113a917678b2"],
        ],
        [
            AES192CBC,
            "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
            ["4f021db243bc633d7178183a9fa071e8", "b4d9ada9ad7dedf4e5e738763f69145a"],
        ],
        [
            AES256CBC,
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
            ["f58c4c04d6e5f1ba779eabfb5f7bfbd6", "9cfc4e967edb808d679f777bc6702c7d"],
        ],
    ] as const)("matches the NIST chained vector for %p", (Cipher, keyHex, expectedHex) => {
        const key = Buffer.from(keyHex, "hex")
        const encryptor = new Cipher(key, aesIV)
        const ciphertext = aesPlaintext.map((block) => encryptor.encrypt(block))
        expect(ciphertext).toEqual(expectedHex.map((hex) => Buffer.from(hex, "hex")))

        const decryptor = new Cipher(key, aesIV)
        expect(ciphertext.map((block) => decryptor.decrypt(block))).toEqual(aesPlaintext)
    })

    test("matches an independently generated three-key 3DES-CBC vector", () => {
        const key = Buffer.from("0123456789abcdeffedcba98765432100123456789abcdef", "hex")
        const iv = Buffer.from("1234567890abcdef", "hex")
        const plaintext = Buffer.from("4e6f77206973207468652074696d6520", "hex")
        const ciphertext = Buffer.from("f85d4ab92066789e1d0430671f28ae7a", "hex")

        expect(new TripleDESCBC(key, iv).encrypt(plaintext)).toEqual(ciphertext)
        expect(new TripleDESCBC(key, iv).decrypt(ciphertext)).toEqual(plaintext)
    })

    test("preserves CBC state when the packet decoder reads the first block separately", () => {
        const key = Buffer.from("2b7e151628aed2a6abf7158809cf4f3c", "hex")
        const macKey = Buffer.alloc(HMACSHA2256.key_length, 0x42)
        const payload = Buffer.alloc(80, 0x5a)
        const encoder = new BinaryPacketEncoder({ randomBytes: (size) => Buffer.alloc(size, 0xa5) })
        encoder.setProtection({
            cipher: new AES128CBC(key, aesIV),
            mac: new HMACSHA2256(macKey),
            blockSize: AES128CBC.block_size,
            macLength: HMACSHA2256.digest_length,
        })
        const encoded = encoder.encode(payload).data

        for (let split = 0; split <= encoded.length; split++) {
            const decoder = new BinaryPacketDecoder()
            decoder.setProtection({
                cipher: new AES128CBC(key, aesIV),
                mac: new HMACSHA2256(macKey),
                blockSize: AES128CBC.block_size,
                macLength: HMACSHA2256.digest_length,
            })
            decoder.push(encoded.subarray(0, split))
            const partial = decoder.read()
            if (split < encoded.length) expect(partial).toBeUndefined()
            decoder.push(encoded.subarray(split))
            expect((partial ?? decoder.read())?.payload).toEqual(payload)
        }
    })

    test("validates key, IV, and block lengths", () => {
        expect(() => new AES128CBC(Buffer.alloc(15), Buffer.alloc(16))).toThrow(
            "key must be 16 bytes",
        )
        expect(() => new AES128CBC(Buffer.alloc(16), Buffer.alloc(15))).toThrow(
            "IV must be 16 bytes",
        )
        const cipher = new TripleDESCBC(Buffer.alloc(24), Buffer.alloc(8))
        expect(() => cipher.encrypt(Buffer.alloc(7))).toThrow("multiple of 8 bytes")
        expect(() => cipher.decrypt(Buffer.alloc(9))).toThrow("multiple of 8 bytes")
        expect(() => new BlowfishCBC(Buffer.alloc(15), Buffer.alloc(8))).toThrow(
            "key must be 16 bytes",
        )
        expect(() => new BlowfishCBC(Buffer.alloc(16), Buffer.alloc(7))).toThrow(
            "IV must be 8 bytes",
        )
        expect(() =>
            new BlowfishCBC(Buffer.alloc(16), Buffer.alloc(8)).encrypt(Buffer.alloc(9)),
        ).toThrow("multiple of 8 bytes")
        expect(() => new Cast128CBC(Buffer.alloc(15), Buffer.alloc(8))).toThrow(
            "key must be 16 bytes",
        )
        expect(() => new Cast128CBC(Buffer.alloc(16), Buffer.alloc(7))).toThrow(
            "IV must be 8 bytes",
        )
        expect(() =>
            new Cast128CBC(Buffer.alloc(16), Buffer.alloc(8)).decrypt(Buffer.alloc(7)),
        ).toThrow("multiple of 8 bytes")
    })
})
