import { chacha20, poly1305 } from "../../src/utils/chacha20.js"

describe("ChaCha20 and Poly1305 primitives", () => {
    test("matches the RFC 8439 ChaCha20 encryption vector", () => {
        const key = Buffer.from(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "hex",
        )
        // RFC 8439's first 32 nonce bits are zero, making its state equivalent to the
        // original 64-bit-counter/64-bit-nonce layout used by the SSH construction.
        const nonce = Buffer.from("0000004a00000000", "hex")
        const plaintext = Buffer.from(
            "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.",
            "ascii",
        )
        const expected = Buffer.from(
            "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d",
            "hex",
        )

        expect(chacha20(plaintext, key, 1n, nonce)).toEqual(expected)
    })

    test("matches the RFC 8439 Poly1305 vector", () => {
        const key = Buffer.from(
            "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b",
            "hex",
        )
        const message = Buffer.from("Cryptographic Forum Research Group", "ascii")

        expect(poly1305(message, key)).toEqual(
            Buffer.from("a8061dc1305136c6c22b8baf0c0127a9", "hex"),
        )
    })

    test("rejects invalid key, nonce, and counter sizes", () => {
        expect(() => chacha20(Buffer.alloc(1), Buffer.alloc(31), 0n)).toThrow("key length")
        expect(() => chacha20(Buffer.alloc(1), Buffer.alloc(32), 0n, Buffer.alloc(7))).toThrow(
            "nonce length",
        )
        expect(() => chacha20(Buffer.alloc(65), Buffer.alloc(32), 0xffff_ffff_ffff_ffffn)).toThrow(
            "counter overflow",
        )
        expect(() => poly1305(Buffer.alloc(0), Buffer.alloc(31))).toThrow("key length")
    })
})
