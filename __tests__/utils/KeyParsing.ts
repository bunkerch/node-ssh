import { generateKeyPairSync } from "node:crypto"
import { mkdtemp, rm, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { execFile } from "node:child_process"
import { promisify } from "node:util"
import { parseKey } from "../../src/KeyParsing.js"
import PrivateKey from "../../src/utils/PrivateKey.js"
import PublicKey from "../../src/utils/PublicKey.js"

const execFileAsync = promisify(execFile)

describe("key parsing", () => {
    test.each([
        ["Ed25519", {}],
        ["RSA", { modulusLength: 2048 }],
        ["EC", { namedCurve: "prime256v1" }],
        ["EC", { namedCurve: "secp384r1" }],
        ["EC", { namedCurve: "secp521r1" }],
    ] as const)("imports %s SubjectPublicKeyInfo PEM", async (type, options) => {
        const nodeType = type === "Ed25519" ? "ed25519" : type === "RSA" ? "rsa" : "ec"
        const { privateKey, publicKey } = generateKeyPairSync(nodeType, options)
        const privatePEM = privateKey.export({ format: "pem", type: "pkcs8" }).toString()
        const publicPEM = publicKey.export({ format: "pem", type: "spki" }).toString()
        const parsedPrivate = parseKey(privatePEM)
        const parsedPublic = parseKey(publicPEM)
        expect(parsedPrivate).toBeInstanceOf(PrivateKey)
        expect(parsedPublic).toBeInstanceOf(PublicKey)

        const message = Buffer.from(`public PEM ${type}`)
        const signature = (parsedPrivate as PrivateKey).sign(message)
        expect((parsedPublic as PublicKey).verifySignature(message, signature)).toBe(true)

        const directory = await mkdtemp(join(tmpdir(), "modernssh-public-pem-"))
        try {
            const path = join(directory, "key.pub")
            await writeFile(path, (parsedPublic as PublicKey).toString())
            const { stdout } = await execFileAsync("ssh-keygen", ["-lf", path])
            expect(stdout).toContain((parsedPublic as PublicKey).hash("sha256"))
        } finally {
            await rm(directory, { recursive: true, force: true })
        }
    })

    test("imports PKCS#1 RSA public PEM", () => {
        const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 })
        const parsedPrivate = parseKey(privateKey.export({ format: "pem", type: "pkcs8" }))
        const parsedPublic = parseKey(publicKey.export({ format: "pem", type: "pkcs1" }))
        const message = Buffer.from("PKCS#1 public key")
        expect(
            (parsedPublic as PublicKey).verifySignature(
                message,
                (parsedPrivate as PrivateKey).sign(message),
            ),
        ).toBe(true)
    })

    test("routes authorized lines, wire blobs, and private containers", async () => {
        const privateKey = await PrivateKey.generate("ssh-ed25519")
        privateKey.data.publicKey.data.comment = "route@example.test"
        const publicLine = privateKey.data.publicKey.toString()
        expect((parseKey(publicLine) as PublicKey).equals(privateKey.data.publicKey)).toBe(true)
        expect(
            (parseKey(Buffer.from(publicLine)) as PublicKey).equals(privateKey.data.publicKey),
        ).toBe(true)
        expect(
            (parseKey(privateKey.data.publicKey.serialize()) as PublicKey).equals(
                privateKey.data.publicKey,
            ),
        ).toBe(true)
        expect(
            (parseKey(privateKey.serialize()) as PrivateKey).data.publicKey.equals(
                privateKey.data.publicKey,
            ),
        ).toBe(true)
        expect(
            (parseKey(privateKey.toString()) as PrivateKey).data.publicKey.equals(
                privateKey.data.publicKey,
            ),
        ).toBe(true)
    })

    test("routes encrypted private keys and rejects passphrases for public keys", async () => {
        const privateKey = await PrivateKey.generate("ssh-ed25519")
        const encrypted = privateKey.toString({ passphrase: "secret", rounds: 1 })
        expect(
            (parseKey(encrypted, "secret") as PrivateKey).data.publicKey.equals(
                privateKey.data.publicKey,
            ),
        ).toBe(true)
        expect(() => parseKey(privateKey.data.publicKey.toString(), "secret")).toThrow(
            "only valid for private keys",
        )
    })

    test("rejects unsupported public-key families", () => {
        const { publicKey } = generateKeyPairSync("x25519")
        const pem = publicKey.export({ format: "pem", type: "spki" })
        expect(() => parseKey(pem)).toThrow("Unsupported public key type: X25519")
    })
})
