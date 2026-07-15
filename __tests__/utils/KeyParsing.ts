import { generateKeyPairSync } from "node:crypto"
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { execFile } from "node:child_process"
import { promisify } from "node:util"
import { parseKey, parseKeys } from "../../src/KeyParsing.js"
import PrivateKey from "../../src/utils/PrivateKey.js"
import PublicKey from "../../src/utils/PublicKey.js"
import {
    parseRFC4716PublicKey,
    parseRFC4716PublicKeyFile,
    serializeRFC4716PublicKey,
} from "../../src/utils/RFC4716.js"

const execFileAsync = promisify(execFile)

const rfc4716KeyLabel = ["SSH", "2 PUBLIC KEY"].join("")
const rfc4716RSA = `---- BEGIN ${rfc4716KeyLabel} ----
Comment: "1024-bit RSA, converted from OpenSSH by me@example.com"
x-command: /home/me/bin/lock-in-guest.sh
AAAAB3NzaC1yc2EAAAABIwAAAIEA1on8gxCGJJWSRT4uOrR13mUaUk0hRf4RzxSZ1zRb
YYFw8pfGesIFoEuVth4HKyF8k1y4mRUnYHP1XNMNMJl1JcEArC2asV8sHf6zSPVffozZ
5TT4SfsUu/iKy9lUcCfXzwre4WWZSXXcPff+EHtWshahu3WzBdnGxm5Xoi89zcE=
---- END ${rfc4716KeyLabel} ----
`

const rfc4716RSABody =
    "AAAAB3NzaC1yc2EAAAABIwAAAIEA1on8gxCGJJWSRT4uOrR13mUaUk0hRf4RzxSZ1zRb" +
    "YYFw8pfGesIFoEuVth4HKyF8k1y4mRUnYHP1XNMNMJl1JcEArC2asV8sHf6zSPVffozZ" +
    "5TT4SfsUu/iKy9lUcCfXzwre4WWZSXXcPff+EHtWshahu3WzBdnGxm5Xoi89zcE="
const rfc4716RSAWrappedBody = rfc4716RSABody.match(/.{1,72}/gu)!.join("\n")

describe("key parsing", () => {
    test("imports the fixed RFC 4716 RSA public-key example", () => {
        const parsed = parseKey(rfc4716RSA) as PublicKey

        expect(parsed).toBeInstanceOf(PublicKey)
        expect(parsed.data.alg).toBe("ssh-rsa")
        expect(parsed.data.comment).toBe("1024-bit RSA, converted from OpenSSH by me@example.com")
        expect(parsed.serialize().toString("base64")).toBe(rfc4716RSABody)
        expect(parsed.hash("md5")).toBe("MD5:49:d7:de:af:5d:45:84:56:f8:ae:a0:6a:0c:c7:5d:69")
        expect(
            (parseKey(Buffer.from(rfc4716RSA.replaceAll("\n", "\r"))) as PublicKey).equals(parsed),
        ).toBe(true)
        const continued = rfc4716RSA.replace(
            'Comment: "1024-bit RSA, converted from OpenSSH by me@example.com"\n',
            "cOmMeNt: This key is used on \\\nproduction servers\nSubject: example\n",
        )
        expect((parseKey(continued) as PublicKey).data.comment).toBe(
            "This key is used on production servers",
        )
        expect(() => parseKey(rfc4716RSA, "not-applicable")).toThrow("only valid for private keys")
    })

    test("preserves and serializes RFC 4716 headers within the physical line limit", () => {
        const parsed = parseRFC4716PublicKeyFile(rfc4716RSA)
        expect(parsed.headers).toEqual([
            {
                tag: "Comment",
                value: '"1024-bit RSA, converted from OpenSSH by me@example.com"',
            },
            { tag: "x-command", value: "/home/me/bin/lock-in-guest.sh" },
        ])
        expect(Object.isFrozen(parsed)).toBe(true)
        expect(Object.isFrozen(parsed.headers)).toBe(true)
        expect(Object.isFrozen(parsed.headers[0])).toBe(true)
        const canonical = serializeRFC4716PublicKey(parsed.publicKey, parsed.headers)
        expect(parseRFC4716PublicKeyFile(canonical).headers).toEqual(parsed.headers)
        expect(parseRFC4716PublicKey(canonical).equals(parsed.publicKey)).toBe(true)
        expect(canonical).toContain(rfc4716RSAWrappedBody)

        const headers = [
            { tag: "Subject", value: "δοκιμή@example.test" },
            { tag: "x-policy", value: `${"deploy/".repeat(20)}\\` },
        ]
        const serialized = serializeRFC4716PublicKey(parsed.publicKey, headers)
        expect(
            serialized
                .trimEnd()
                .split("\n")
                .every((line) => Buffer.byteLength(line, "utf8") <= 72),
        ).toBe(true)
        const reparsed = parseRFC4716PublicKeyFile(serialized)
        expect(reparsed.headers).toEqual(headers)
        expect(reparsed.publicKey.equals(parsed.publicKey)).toBe(true)

        expect(() => serializeRFC4716PublicKey({} as PublicKey)).toThrow("requires an SSH public")
        expect(() =>
            serializeRFC4716PublicKey(parsed.publicKey, [{ tag: "Comment", value: "bad\nvalue" }]),
        ).toThrow("line ending")
        expect(() =>
            serializeRFC4716PublicKey(parsed.publicKey, [
                { tag: "x".repeat(65), value: "too long" },
            ]),
        ).toThrow("tag exceeds 64 bytes")
    })

    test("strictly validates RFC 4716 framing, headers, text, and base64", () => {
        const wrap = (content: string) =>
            `---- BEGIN ${rfc4716KeyLabel} ----\n${content}\n---- END ${rfc4716KeyLabel} ----\n`
        const oversizedValue = [
            `Comment: ${"a".repeat(62)}\\`,
            ...Array<string>(13).fill(`${"a".repeat(71)}\\`),
            "a".repeat(40),
        ].join("\n")
        const invalidUTF8 = Buffer.concat([
            Buffer.from(`---- BEGIN ${rfc4716KeyLabel} ----\nComment: `, "ascii"),
            Buffer.from([0xff]),
            Buffer.from(`\n${rfc4716RSABody}\n---- END ${rfc4716KeyLabel} ----\n`, "ascii"),
        ])

        expect(() => parseRFC4716PublicKey(`${rfc4716RSA}trailing`)).toThrow("end marker")
        expect(() =>
            parseRFC4716PublicKey(wrap(`Comment: ${"a".repeat(64)}\n${rfc4716RSAWrappedBody}`)),
        ).toThrow("line exceeds 72 bytes")
        expect(() =>
            parseRFC4716PublicKey(wrap(`${"a".repeat(65)}: x\n${rfc4716RSAWrappedBody}`)),
        ).toThrow("tag exceeds 64 bytes")
        expect(() =>
            parseRFC4716PublicKey(wrap(`Cömment: value\n${rfc4716RSAWrappedBody}`)),
        ).toThrow("printable US-ASCII")
        expect(() =>
            parseRFC4716PublicKey(wrap(`Comment:value\n${rfc4716RSAWrappedBody}`)),
        ).toThrow("header field")
        expect(() => parseRFC4716PublicKey(wrap(oversizedValue))).toThrow(
            "value exceeds 1024 bytes",
        )
        expect(() => parseRFC4716PublicKey(wrap("Comment: dangling\\"))).toThrow(
            "dangling continuation",
        )
        expect(() => parseRFC4716PublicKey(wrap(`\n${rfc4716RSAWrappedBody}`))).toThrow(
            "blank line",
        )
        expect(() => parseRFC4716PublicKey(wrap(`${rfc4716RSAWrappedBody.slice(0, -1)}!`))).toThrow(
            "Invalid RFC 4716 public key base64",
        )
        expect(() => parseRFC4716PublicKey(wrap(rfc4716RSAWrappedBody.slice(0, -1)))).toThrow(
            "base64 length",
        )
        expect(() => parseRFC4716PublicKey(invalidUTF8)).toThrow("not valid UTF-8 text")
    })

    test("imports RFC 4716 public keys exchanged with ssh-keygen", async () => {
        const directory = await mkdtemp(join(tmpdir(), "modernssh-rfc4716-"))
        try {
            const keyPath = join(directory, "id_ed25519")
            const fixedPath = join(directory, "rfc-example.pub")
            const serializedPath = join(directory, "serialized.pub")
            await execFileAsync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", keyPath])
            const expected = PublicKey.parseString(await readFile(`${keyPath}.pub`, "utf8"))
            const { stdout: exported } = await execFileAsync("ssh-keygen", [
                "-e",
                "-m",
                "RFC4716",
                "-f",
                `${keyPath}.pub`,
            ])
            expect((parseKey(exported) as PublicKey).equals(expected)).toBe(true)

            await writeFile(fixedPath, rfc4716RSA)
            const { stdout: imported } = await execFileAsync("ssh-keygen", [
                "-i",
                "-m",
                "RFC4716",
                "-f",
                fixedPath,
            ])
            expect(PublicKey.parseString(imported).equals(parseKey(rfc4716RSA) as PublicKey)).toBe(
                true,
            )

            await writeFile(serializedPath, serializeRFC4716PublicKey(expected))
            const { stdout: importedSerialized } = await execFileAsync("ssh-keygen", [
                "-i",
                "-m",
                "RFC4716",
                "-f",
                serializedPath,
            ])
            expect(PublicKey.parseString(importedSerialized).equals(expected)).toBe(true)
        } finally {
            await rm(directory, { recursive: true, force: true })
        }
    })

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
        excessive.writeUInt32BE(1000, 35)
        expect(() => PrivateKey.parseAll(excessive)).toThrow("Invalid private key count")

        const tooMany = Buffer.from(raw)
        tooMany.writeUInt32BE(1025, 35)
        expect(() => PrivateKey.parseAll(tooMany)).toThrow("1024-key limit")
        expect(() => PrivateKey.serializeMany(Array(1025).fill(first))).toThrow("1024-key limit")

        const cipherOffset = raw.indexOf(Buffer.from("none"), 15)
        const kdfOffset = raw.indexOf(Buffer.from("none"), cipherOffset + 4)
        expect(cipherOffset).toBeGreaterThan(0)
        expect(kdfOffset).toBeGreaterThan(cipherOffset)
        const invalidCipherName = Buffer.from(raw)
        invalidCipherName[cipherOffset] = 0x80
        expect(() => PrivateKey.parseAll(invalidCipherName)).toThrow(
            "OpenSSH private key cipher must be US-ASCII",
        )
        const invalidKDFName = Buffer.from(raw)
        invalidKDFName[kdfOffset] = 0x80
        expect(() => PrivateKey.parseAll(invalidKDFName)).toThrow(
            "OpenSSH private key KDF must be US-ASCII",
        )

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

    test("strictly validates and bounds OpenSSH private-key armor", async () => {
        const key = await PrivateKey.generate("ssh-ed25519")
        const armored = key.toString()
        expect(
            PrivateKey.fromString(`${armored.replaceAll("\n", "\r\n")}\r\n`).data.publicKey.equals(
                key.data.publicKey,
            ),
        ).toBe(true)

        const lines = armored.split("\n")
        const invalidCharacter = [...lines]
        invalidCharacter[1] = `!${invalidCharacter[1]!.slice(1)}`
        expect(() => PrivateKey.fromString(invalidCharacter.join("\n"))).toThrow(
            "Invalid private key base64",
        )
        expect(() => PrivateKey.fromString([lines[0], "AB==", lines.at(-1)].join("\n"))).toThrow(
            "Non-canonical private key base64",
        )
        expect(() =>
            PrivateKey.fromString([lines[0], lines[1], "", ...lines.slice(2)].join("\n")),
        ).toThrow("contains a blank line")
        expect(() => PrivateKey.fromString(` ${armored}`)).toThrow("begin marker")
        expect(() => PrivateKey.fromString(armored.replace(lines[1]!, `é${lines[1]}`))).toThrow(
            "must contain ASCII text",
        )

        expect(() => PrivateKey.parseAll(Buffer.alloc(16 * 1024 * 1024 + 1))).toThrow(
            "exceeds 16777216 bytes",
        )
        const oversizedArmor = [lines[0], "A".repeat(24 * 1024 * 1024), lines.at(-1)].join("\n")
        expect(() => PrivateKey.fromString(oversizedArmor)).toThrow("exceeds 25165824 bytes")
    })

    test("rejects unsupported public-key families", () => {
        const { publicKey } = generateKeyPairSync("x25519")
        const pem = publicKey.export({ format: "pem", type: "spki" })
        expect(() => parseKey(pem)).toThrow("Unsupported public key type: X25519")
    })
})
