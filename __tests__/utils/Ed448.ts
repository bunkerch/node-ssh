import EncodedSignature from "../../src/utils/Signature.js"
import PrivateKey, { SSHED448PrivateKey } from "../../src/utils/PrivateKey.js"
import PublicKey, { SSHED448PublicKey } from "../../src/utils/PublicKey.js"

const execFileAsync = promisify(execFile)

// RFC 8032, Section 7.4, "Blank". The SSH framing assertions come from RFC 8709.
const seed = Buffer.from(
    "6c82a562cb808d10d632be89c8513ebf" +
        "6c929f34ddfa8c9f63c9960ef6e348a3" +
        "528c8a3fcc2f044e39a3fc5b94492f8f" +
        "032e7549a20098f95b",
    "hex",
)
const publicBytes = Buffer.from(
    "5fd7449b59b461fd2ce787ec616ad46a" +
        "1da1342485a70e1f8a0ea75d80e96778" +
        "edf124769b46c7061bd6783df1e50f6c" +
        "d1fa1abeafe8256180",
    "hex",
)
const signatureBytes = Buffer.from(
    "533a37f6bbe457251f023c0d88f976ae" +
        "2dfb504a843e34d2074fd823d41a591f" +
        "2b233f034f628281f2fd7a22ddd47d78" +
        "28c59bd0a21bfd3980ff0d2028d4b18a" +
        "9df63e006c5d1c2d345b925d8dc00b41" +
        "04852db99ac5c7cdda8530a113a0f4db" +
        "b61149f05a7363268c71d95808ff2e65" +
        "2600",
    "hex",
)

function vectorPrivateKey(): PrivateKey {
    const algorithm = new SSHED448PrivateKey({
        publicKey: publicBytes,
        privateKey: Buffer.concat([seed, publicBytes]),
    })
    return new PrivateKey({
        alg: "ssh-ed448",
        algorithm,
        publicKey: algorithm.getPublicKey(),
    })
}

describe("RFC 8709 Ed448 keys", () => {
    test("matches the RFC 8032 empty-message signature vector", () => {
        const privateKey = vectorPrivateKey()
        const signature = privateKey.sign(Buffer.alloc(0))

        expect(signature.data.alg).toBe("ssh-ed448")
        expect(signature.data.data).toEqual(signatureBytes)
        expect(privateKey.data.publicKey.verifySignature(Buffer.alloc(0), signature)).toBe(true)
        expect(
            privateKey.data.publicKey.verifySignature(
                Buffer.from([0]),
                new EncodedSignature({ alg: "ssh-ed448", data: signatureBytes }),
            ),
        ).toBe(false)
    })

    test("uses the exact RFC 8709 public-key and signature frames", () => {
        const publicKey = vectorPrivateKey().data.publicKey
        const expectedKey = Buffer.concat([
            Buffer.from("000000097373682d656434343800000039", "hex"),
            publicBytes,
        ])
        const expectedSignature = Buffer.concat([
            Buffer.from("000000097373682d656434343800000072", "hex"),
            signatureBytes,
        ])

        expect(publicKey.serialize()).toEqual(expectedKey)
        expect(PublicKey.parse(expectedKey).equals(publicKey)).toBe(true)
        expect(
            new EncodedSignature({ alg: "ssh-ed448", data: signatureBytes }).serialize(),
        ).toEqual(expectedSignature)
    })

    test("rejects malformed lengths and incompatible signature names", () => {
        expect(() => new SSHED448PublicKey({ publicKey: Buffer.alloc(56) })).toThrow(
            "Invalid Ed448 public key length",
        )
        expect(
            () =>
                new SSHED448PrivateKey({
                    publicKey: publicBytes,
                    privateKey: Buffer.alloc(114),
                }),
        ).toThrow("do not match")

        const wrongSeed = Buffer.concat([seed, publicBytes])
        wrongSeed[0] ^= 0x80
        expect(
            () =>
                new SSHED448PrivateKey({
                    publicKey: publicBytes,
                    privateKey: wrongSeed,
                }),
        ).toThrow("do not match")

        const key = vectorPrivateKey()
        expect(() => key.sign(Buffer.alloc(0), "ssh-ed25519")).toThrow(
            "Unsupported Ed448 signature algorithm",
        )
        expect(
            key.data.publicKey.verifySignature(
                Buffer.alloc(0),
                new EncodedSignature({ alg: "ssh-ed448", data: Buffer.alloc(113) }),
            ),
        ).toBe(false)
    })

    test("round-trips generated private keys", async () => {
        const generated = await PrivateKey.generate("ssh-ed448")
        const message = Buffer.from("generated Ed448")
        expect(generated.data.publicKey.verifySignature(message, generated.sign(message))).toBe(
            true,
        )
        expect(
            PrivateKey.fromString(generated.toString()).data.publicKey.equals(
                generated.data.publicKey,
            ),
        ).toBe(true)

        const keyObject = generated.data.algorithm as SSHED448PrivateKey
        const imported = vectorPrivateKey()
        expect(keyObject.data.privateKey).toHaveLength(114)
        expect(imported.data.publicKey.data.algorithm).toBeInstanceOf(SSHED448PublicKey)
    })

    test("imports native PKCS#8 and SubjectPublicKeyInfo containers", async () => {
        const script = String.raw`
            import { generateKeyPairSync } from "node:crypto"
            import PrivateKey from "./dist/utils/PrivateKey.js"
            import PublicKey from "./dist/utils/PublicKey.js"
            const native = generateKeyPairSync("ed448")
            const privateKey = PrivateKey.fromPEM(native.privateKey.export({ format: "pem", type: "pkcs8" }).toString())
            const publicKey = PublicKey.fromPEM(native.publicKey.export({ format: "pem", type: "spki" }))
            const message = Buffer.from("native Ed448 PEM")
            if (!privateKey.data.publicKey.equals(publicKey)) process.exit(2)
            if (!publicKey.verifySignature(message, privateKey.sign(message))) process.exit(3)
            process.stdout.write(privateKey.data.alg)
        `
        const { stdout } = await execFileAsync("node", ["--input-type=module", "-e", script])
        expect(stdout).toBe("ssh-ed448")
    })
})
import { execFile } from "node:child_process"
import { promisify } from "node:util"
