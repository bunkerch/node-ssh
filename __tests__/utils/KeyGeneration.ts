import { execFile } from "node:child_process"
import { mkdtemp, rm, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { promisify } from "node:util"
import { generateKeyPair, generateKeyPairSync } from "../../src/KeyGeneration.js"
import PrivateKey from "../../src/utils/PrivateKey.js"
import PublicKey from "../../src/utils/PublicKey.js"

const execFileAsync = promisify(execFile)

describe("SSH key-pair generation", () => {
    test.each([
        ["ed25519", undefined, "ssh-ed25519"],
        ["ed448", undefined, "ssh-ed448"],
        ["rsa", 1024, "ssh-rsa"],
        ["ecdsa", 256, "ecdsa-sha2-nistp256"],
        ["ecdsa", 384, "ecdsa-sha2-nistp384"],
        ["ecdsa", 521, "ecdsa-sha2-nistp521"],
    ] as const)("generates a synchronous %s key pair", (type, bits, algorithm) => {
        const pair = generateKeyPairSync(type, {
            bits,
            comment: "synchronous@example.test",
        })
        const message = Buffer.from(`synchronous-${type}`)

        expect(pair).not.toBeInstanceOf(Promise)
        expect(pair.publicKey.data.alg).toBe(algorithm)
        expect(pair.publicKey.data.comment).toBe("synchronous@example.test")
        expect(pair.publicKey.verifySignature(message, pair.privateKey.sign(message))).toBe(true)
        expect(
            PrivateKey.fromString(pair.privateKey.toString()).data.publicKey.equals(pair.publicKey),
        ).toBe(true)
    })

    test("generates fixed-size Ed448 keys", async () => {
        const pair = await generateKeyPair("ed448", { comment: "ed448@example.test" })
        const message = Buffer.from("generated-ed448")
        expect(pair.publicKey.data.alg).toBe("ssh-ed448")
        expect(pair.publicKey.data.comment).toBe("ed448@example.test")
        expect(pair.publicKey.verifySignature(message, pair.privateKey.sign(message))).toBe(true)
        expect(
            PrivateKey.fromString(pair.privateKey.toString()).data.publicKey.equals(pair.publicKey),
        ).toBe(true)
        await expect(generateKeyPair("ed448", { bits: 448 })).rejects.toThrow(
            "does not accept bits",
        )
    })

    test.each([
        ["ed25519", undefined, "ssh-ed25519", "ED25519"],
        ["rsa", 2048, "ssh-rsa", "RSA"],
        ["ecdsa", 256, "ecdsa-sha2-nistp256", "ECDSA"],
        ["ecdsa", 384, "ecdsa-sha2-nistp384", "ECDSA"],
        ["ecdsa", 521, "ecdsa-sha2-nistp521", "ECDSA"],
    ] as const)(
        "generates an OpenSSH-compatible %s key",
        async (type, bits, algorithm, keyLabel) => {
            const directory = await mkdtemp(join(tmpdir(), "modernssh-generated-key-"))
            const path = join(directory, "id_test")
            try {
                const pair = await generateKeyPair(type, {
                    bits,
                    comment: "generated@example.test",
                })
                expect(pair.publicKey.data.alg).toBe(algorithm)
                expect(pair.publicKey.data.comment).toBe("generated@example.test")
                expect(pair.privateKey.data.comment).toBe("generated@example.test")
                expect(pair.privateKey.data.publicKey).toBe(pair.publicKey)

                const message = Buffer.from(`generated-${type}-${bits ?? "default"}`)
                expect(pair.publicKey.verifySignature(message, pair.privateKey.sign(message))).toBe(
                    true,
                )
                expect(
                    PrivateKey.fromString(pair.privateKey.toString()).data.publicKey.equals(
                        pair.publicKey,
                    ),
                ).toBe(true)
                expect(
                    PublicKey.parseString(pair.publicKey.toString()).equals(pair.publicKey),
                ).toBe(true)

                await writeFile(path, `${pair.privateKey.toString()}\n`, { mode: 0o600 })
                const { stdout: derivedText } = await execFileAsync("ssh-keygen", [
                    "-y",
                    "-f",
                    path,
                ])
                expect(PublicKey.parseString(derivedText).equals(pair.publicKey)).toBe(true)
                const { stdout: fingerprint } = await execFileAsync("ssh-keygen", ["-lf", path])
                expect(fingerprint).toContain(` (${keyLabel})`)
                if (type === "rsa") expect(fingerprint.startsWith(`${bits} `)).toBe(true)
            } finally {
                await rm(directory, { recursive: true, force: true })
            }
        },
    )

    test("uses secure defaults and rejects ambiguous generation options", async () => {
        const rsa = await generateKeyPair("rsa")
        const directory = await mkdtemp(join(tmpdir(), "modernssh-default-rsa-"))
        const path = join(directory, "id_rsa")
        try {
            await writeFile(path, `${rsa.privateKey.toString()}\n`, { mode: 0o600 })
            const { stdout } = await execFileAsync("ssh-keygen", ["-lf", path])
            expect(stdout.startsWith("3072 ")).toBe(true)
        } finally {
            await rm(directory, { recursive: true, force: true })
        }

        await expect(generateKeyPair("ed25519", { bits: 256 })).rejects.toThrow(
            "does not accept bits",
        )
        await expect(generateKeyPair("ecdsa", { bits: 255 })).rejects.toThrow("256, 384, or 521")
        await expect(generateKeyPair("rsa", { bits: 1023 })).rejects.toThrow(
            "between 1024 and 16384",
        )
        await expect(generateKeyPair("rsa", { bits: 2048.5 })).rejects.toThrow("must be an integer")
        await expect(generateKeyPair("ed25519", { comment: "bad\ncomment" })).rejects.toThrow(
            "must not contain",
        )
        await expect(generateKeyPair("ed25519", { comment: "\ud800" })).rejects.toThrow(
            "SSH key comment is not valid UTF-8 text",
        )
        expect(() => generateKeyPairSync("rsa", { bits: 1023 })).toThrow("between 1024 and 16384")
        expect(() => generateKeyPairSync("ed448", { bits: 448 })).toThrow("does not accept bits")
        await expect(generateKeyPair("ed25519", null as never)).rejects.toThrow(
            "options must be an object",
        )
        expect(() => generateKeyPairSync("ed25519", [] as never)).toThrow(
            "options must be an object",
        )
        await expect(generateKeyPair("ed25519", { comment: 42 as never })).rejects.toThrow(
            "comment must be a string",
        )
    })

    test("owns asynchronous generation options before cryptographic work", async () => {
        const options = { comment: "original@example.test" }
        const generation = generateKeyPair("ed25519", options)
        options.comment = "mutated@example.test"

        const pair = await generation
        expect(pair.publicKey.data.comment).toBe("original@example.test")
        expect(pair.privateKey.data.comment).toBe("original@example.test")
    })
})
