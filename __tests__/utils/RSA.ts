import PrivateKey, { SSHRSAPrivateKey } from "../../src/utils/PrivateKey.js"
import PublicKey, { SSHRSAPublicKey } from "../../src/utils/PublicKey.js"

const fixedPublicKey = Buffer.from("000000077373682d7273610000000111000000020ca1", "hex")

describe("RFC 4253 RSA keys", () => {
    test("parses a canonical fixed public-key blob", () => {
        const key = PublicKey.parse(fixedPublicKey)

        expect(key.data.alg).toBe("ssh-rsa")
        expect(key.serialize()).toEqual(fixedPublicKey)
    })

    test.each([
        ["zero exponent", "00000000", "000000020ca1"],
        ["even exponent", "0000000104", "000000020ca1"],
        ["non-canonical exponent", "000000020011", "000000020ca1"],
        ["negative modulus", "0000000111", "0000000181"],
    ])("rejects a %s", (_name, exponent, modulus) => {
        expect(() =>
            PublicKey.parse(Buffer.from(`000000077373682d727361${exponent}${modulus}`, "hex")),
        ).toThrow()
    })

    test("validates private relationships and isolates retained components", async () => {
        const generated = await SSHRSAPrivateKey.generate(1024)
        const source = generated.data.algorithm as SSHRSAPrivateKey
        const inputs = Object.fromEntries(
            Object.entries(source.data).map(([name, value]) => [name, Buffer.from(value)]),
        ) as unknown as ConstructorParameters<typeof SSHRSAPrivateKey>[0]
        const algorithm = new SSHRSAPrivateKey(inputs)
        for (const value of Object.values(inputs)) value.fill(0xff)

        const key = new PrivateKey({
            alg: "ssh-rsa",
            algorithm,
            publicKey: algorithm.getPublicKey(),
        })
        const message = Buffer.from("stable RSA key ownership")
        expect(key.data.publicKey.verifySignature(message, key.sign(message, "rsa-sha2-256"))).toBe(
            true,
        )

        const mismatched = { ...source.data, modulus: Buffer.from(source.data.modulus) }
        mismatched.modulus[mismatched.modulus.length - 1] ^= 2
        expect(() => new SSHRSAPrivateKey(mismatched)).toThrow("prime factors")
    })

    test("rejects composite factors even when every RSA relationship is consistent", () => {
        expect(
            () =>
                new SSHRSAPrivateKey({
                    modulus: Buffer.from([45]),
                    publicExponent: Buffer.from([5]),
                    privateExponent: Buffer.from([5]),
                    iqmp: Buffer.from([2]),
                    p: Buffer.from([9]),
                    q: Buffer.from([5]),
                }),
        ).toThrow("Invalid RSA primes")
    })

    test("does not retain caller-owned public-key storage", () => {
        const exponent = Buffer.from([0x11])
        const modulus = Buffer.from([0x0c, 0xa1])
        const key = new SSHRSAPublicKey({ publicExponent: exponent, modulus })
        exponent.fill(0xff)
        modulus.fill(0xff)

        expect(key.serialize()).toEqual(fixedPublicKey.subarray(11))
    })
})
