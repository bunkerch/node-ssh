import PublicKey, { SSHED25519PublicKey } from "../../src/utils/PublicKey.js"
import PrivateKey, { SSHED25519PrivateKey } from "../../src/utils/PrivateKey.js"

const rfc8709Key = Buffer.from(
    "0000000b7373682d6564323535313900000020" +
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "hex",
)
const rfc8032Seed = Buffer.from(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    "hex",
)
const rfc8032PublicKey = Buffer.from(
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    "hex",
)
const rfc8032Signature = Buffer.from(
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" +
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
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

    test("matches the RFC 8032 empty-message signature vector", () => {
        const algorithm = new SSHED25519PrivateKey({
            publicKey: rfc8032PublicKey,
            privateKey: Buffer.concat([rfc8032Seed, rfc8032PublicKey]),
        })
        const key = new PrivateKey({
            alg: "ssh-ed25519",
            algorithm,
            publicKey: algorithm.getPublicKey(),
        })

        expect(key.sign(Buffer.alloc(0)).data.data).toEqual(rfc8032Signature)
    })

    test("rejects private material that does not derive the claimed public key", () => {
        const privateKey = Buffer.concat([rfc8032Seed, rfc8032PublicKey])
        const wrongPublicKey = Buffer.from(rfc8032PublicKey)
        wrongPublicKey[0] ^= 0x80

        expect(() => new SSHED25519PrivateKey({ publicKey: wrongPublicKey, privateKey })).toThrow(
            "do not match",
        )

        const wrongSeed = Buffer.from(privateKey)
        wrongSeed[0] ^= 0x80
        expect(
            () => new SSHED25519PrivateKey({ publicKey: rfc8032PublicKey, privateKey: wrongSeed }),
        ).toThrow("do not match")
    })

    test("does not retain caller-owned private-key storage", () => {
        const publicKey = Buffer.from(rfc8032PublicKey)
        const privateKey = Buffer.concat([rfc8032Seed, publicKey])
        const key = new SSHED25519PrivateKey({ publicKey, privateKey })
        publicKey.fill(0xff)
        privateKey.fill(0xff)

        expect(key.sign(Buffer.alloc(0)).data.data).toEqual(rfc8032Signature)
        expect(key.getPublicKey().data.algorithm).toBeInstanceOf(SSHED25519PublicKey)
    })
})
