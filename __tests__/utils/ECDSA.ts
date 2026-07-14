import EncodedSignature from "../../src/utils/Signature.js"
import PrivateKey, { SSHECDSAPrivateKey } from "../../src/utils/PrivateKey.js"
import PublicKey, { ECDSA_CURVES, SSHECDSAPublicKey } from "../../src/utils/PublicKey.js"

const rfc6979P256PublicKey = Buffer.from(
    "0000001365636473612d736861322d6e69737470323536" +
        "000000086e69737470323536" +
        "0000004104" +
        "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6" +
        "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
    "hex",
)
const rfc6979P256Signature = new EncodedSignature({
    alg: "ecdsa-sha2-nistp256",
    data: Buffer.from(
        "0000002100efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716" +
            "0000002100f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
        "hex",
    ),
})
const rfc6979P256PrivateKey = Buffer.from(
    "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
    "hex",
)
const rfc6979P256Point = Buffer.from(rfc6979P256PublicKey.subarray(-65))

describe("RFC 5656 ECDSA keys and signatures", () => {
    test("verifies the RFC 6979 P-256 SHA-256 signature in SSH mpint encoding", () => {
        const publicKey = PublicKey.parse(rfc6979P256PublicKey)

        expect(publicKey.data.alg).toBe("ecdsa-sha2-nistp256")
        expect(publicKey.serialize()).toEqual(rfc6979P256PublicKey)
        expect(publicKey.verifySignature(Buffer.from("sample"), rfc6979P256Signature)).toBe(true)

        const tampered = new EncodedSignature({
            alg: rfc6979P256Signature.data.alg,
            data: Buffer.from(rfc6979P256Signature.data.data),
        })
        tampered.data.data[tampered.data.data.length - 1] ^= 1
        expect(publicKey.verifySignature(Buffer.from("sample"), tampered)).toBe(false)
    })

    test("generates, serializes, signs, and verifies every required NIST curve", async () => {
        for (const algorithm of [
            "ecdsa-sha2-nistp256",
            "ecdsa-sha2-nistp384",
            "ecdsa-sha2-nistp521",
        ]) {
            const privateKey = await PrivateKey.generate(algorithm)
            const parsed = PrivateKey.fromString(privateKey.toString())
            const data = Buffer.from(`signed with ${algorithm}`)
            const signature = parsed.sign(data)

            expect(parsed.data.alg).toBe(algorithm)
            expect(parsed.data.publicKey.equals(privateKey.data.publicKey)).toBe(true)
            expect(signature.data.alg).toBe(algorithm)
            expect(parsed.data.publicKey.verifySignature(data, signature)).toBe(true)
        }
    })

    test("rejects malformed curve points and mismatched signature algorithms", () => {
        const publicKey = PublicKey.parse(rfc6979P256PublicKey)
        const malformed = Buffer.from(rfc6979P256PublicKey)
        malformed[malformed.length - 1] ^= 1

        expect(() => PublicKey.parse(malformed)).toThrow("Invalid nistp256 public key")
        expect(
            publicKey.verifySignature(
                Buffer.from("sample"),
                new EncodedSignature({
                    alg: "ecdsa-sha2-nistp384",
                    data: rfc6979P256Signature.data.data,
                }),
            ),
        ).toBe(false)
    })

    test("does not retain caller-owned public or private key storage", () => {
        const publicInput = Buffer.from(rfc6979P256Point)
        const publicAlgorithm = new SSHECDSAPublicKey(ECDSA_CURVES[0], {
            publicKey: publicInput,
        })
        publicInput.fill(0xff)
        expect(publicAlgorithm.serialize().subarray(-65)).toEqual(rfc6979P256Point)

        const privatePublicInput = Buffer.from(rfc6979P256Point)
        const privateInput = Buffer.from(rfc6979P256PrivateKey)
        const privateAlgorithm = new SSHECDSAPrivateKey(ECDSA_CURVES[0], {
            publicKey: privatePublicInput,
            privateKey: privateInput,
        })
        privatePublicInput.fill(0xff)
        privateInput.fill(0xff)

        const key = new PrivateKey({
            alg: ECDSA_CURVES[0].algorithm,
            algorithm: privateAlgorithm,
            publicKey: privateAlgorithm.getPublicKey(),
        })
        const message = Buffer.from("stable ECDSA key ownership")
        expect(key.data.publicKey.verifySignature(message, key.sign(message))).toBe(true)
        expect(privateAlgorithm.data.publicKey).toEqual(rfc6979P256Point)
        expect(privateAlgorithm.data.privateKey).toEqual(rfc6979P256PrivateKey)
    })
})
