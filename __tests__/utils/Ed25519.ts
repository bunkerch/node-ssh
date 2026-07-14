import PublicKey, { SSHED25519PublicKey } from "../../src/utils/PublicKey.js"

const rfc8709Key = Buffer.from(
    "0000000b7373682d6564323535313900000020" +
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "hex",
)

describe("RFC 8709 Ed25519 public keys", () => {
    test("parses an exact 32-octet fixed key", () => {
        const key = PublicKey.parse(rfc8709Key)

        expect(key.data.alg).toBe("ssh-ed25519")
        expect(key.serialize()).toEqual(rfc8709Key)
    })

    test.each([31, 33])("rejects a %i-octet public key", (length) => {
        const malformed = Buffer.concat([
            rfc8709Key.subarray(0, 15),
            Buffer.from([0, 0, 0, length]),
            Buffer.alloc(length),
        ])

        expect(() => PublicKey.parse(malformed)).toThrow("Invalid Ed25519 public key length")
    })

    test("does not retain caller-owned key storage", () => {
        const raw = Buffer.from(rfc8709Key.subarray(-32))
        const key = new SSHED25519PublicKey({ publicKey: raw })
        raw.fill(0xff)

        expect(key.serialize()).toEqual(rfc8709Key.subarray(15))
    })
})
