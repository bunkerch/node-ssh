import { generateKeyPairSync } from "node:crypto"
import { mkdtemp, rm, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { execFile } from "node:child_process"
import { promisify } from "node:util"
import { parseKey, parseKeys } from "../../src/KeyParsing.js"
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
        const [algorithm, encoded, comment] = publicLine.split(" ")
        const unpadded = encoded.replace(/=+$/u, "")
        expect(
            PublicKey.parseString(`${algorithm} ${unpadded} ${comment}`).equals(
                privateKey.data.publicKey,
            ),
        ).toBe(true)
        expect(() =>
            PublicKey.parseString(`${algorithm} ${encoded.slice(0, 4)}!${encoded.slice(4)}`),
        ).toThrow("Invalid public key base64")
        expect(() => PublicKey.parseString(`${algorithm} A`)).toThrow(
            "Invalid public key base64 length",
        )
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

    test("parses ordered multi-key private containers without ambiguity", async () => {
        const keys = await Promise.all([
            PrivateKey.generate("ssh-ed25519"),
            PrivateKey.generate("ecdsa-sha2-nistp256"),
            PrivateKey.generate("ssh-ed448"),
        ])
        keys.forEach((key, index) => {
            key.data.comment = `key-${index + 1}`
        })

        for (const encrypted of [false, true]) {
            const options = encrypted ? { passphrase: "multi-secret", rounds: 1 } : undefined
            const raw = PrivateKey.serializeMany(keys, options)
            const armored = PrivateKey.toStringMany(keys, options)
            const passphrase = encrypted ? "multi-secret" : undefined
            for (const parsed of [
                PrivateKey.parseAll(raw, passphrase),
                PrivateKey.fromStringAll(armored, passphrase),
                parseKeys(raw, passphrase) as PrivateKey[],
                parseKeys(armored, passphrase) as PrivateKey[],
            ]) {
                expect(parsed.map((key) => key.data.comment)).toEqual(["key-1", "key-2", "key-3"])
                parsed.forEach((key, index) => {
                    expect(key.data.publicKey.equals(keys[index].data.publicKey)).toBe(true)
                    const message = Buffer.from(`multi-key-${index}`)
                    expect(key.data.publicKey.verifySignature(message, key.sign(message))).toBe(
                        true,
                    )
                })
            }
        }

        const raw = PrivateKey.serializeMany(keys)
        expect(() => PrivateKey.parse(raw)).toThrow("use parseAll()")
        expect(() => PrivateKey.fromString(PrivateKey.toStringMany(keys))).toThrow(
            "use fromStringAll()",
        )
        expect(() => parseKey(raw)).toThrow("use parseKeys()")
    })

    test("rejects invalid multi-key counts, envelopes, and padding", async () => {
        const first = await PrivateKey.generate("ssh-ed25519")
        const second = await PrivateKey.generate("ssh-ed25519")
        const raw = PrivateKey.serializeMany([first, second])

        const empty = Buffer.from(raw)
        empty.writeUInt32BE(0, 35)
        expect(() => PrivateKey.parseAll(empty)).toThrow("at least one key")

        const excessive = Buffer.from(raw)
        excessive.writeUInt32BE(0xffffffff, 35)
        expect(() => PrivateKey.parseAll(excessive)).toThrow("Invalid private key count")

        const swapped = Buffer.from(raw)
        const firstFrame = Buffer.concat([
            Buffer.from([0, 0, 0, first.data.publicKey.serialize().length]),
            first.data.publicKey.serialize(),
        ])
        const secondFrame = Buffer.concat([
            Buffer.from([0, 0, 0, second.data.publicKey.serialize().length]),
            second.data.publicKey.serialize(),
        ])
        const firstOffset = swapped.indexOf(firstFrame, 39)
        const secondOffset = swapped.indexOf(secondFrame, firstOffset + firstFrame.length)
        expect(firstOffset).toBeGreaterThan(0)
        expect(secondOffset).toBeGreaterThan(firstOffset)
        firstFrame.copy(swapped, secondOffset)
        secondFrame.copy(swapped, firstOffset)
        expect(() => PrivateKey.parseAll(swapped)).toThrow("do not match")

        const badPadding = Buffer.from(raw)
        badPadding[badPadding.length - 1] ^= 0xff
        expect(() => PrivateKey.parseAll(badPadding)).toThrow("Invalid padding byte")
    })

    test("rejects unsupported public-key families", () => {
        const { publicKey } = generateKeyPairSync("x25519")
        const pem = publicKey.export({ format: "pem", type: "spki" })
        expect(() => parseKey(pem)).toThrow("Unsupported public key type: X25519")
    })
})
