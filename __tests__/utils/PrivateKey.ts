import { execFile } from "node:child_process"
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { promisify } from "node:util"
import DiskAgent from "../../src/publickey/DiskAgent.js"
import PrivateKey from "../../src/utils/PrivateKey.js"
import PublicKey from "../../src/utils/PublicKey.js"

const execFileAsync = promisify(execFile)
const passphrase = "correct horse battery staple"
const ciphers = [
    "3des-cbc",
    "aes128-cbc",
    "aes192-cbc",
    "aes256-cbc",
    "aes128-ctr",
    "aes192-ctr",
    "aes256-ctr",
    "aes128-gcm@openssh.com",
    "aes256-gcm@openssh.com",
    "chacha20-poly1305@openssh.com",
]

async function generateKey(
    directory: string,
    name: string,
    type: "ed25519" | "rsa",
    cipher = "aes256-ctr",
    keyPassphrase = passphrase,
): Promise<{ privateKey: string; publicKey: PublicKey }> {
    const keyPath = join(directory, name)
    await execFileAsync("ssh-keygen", [
        "-q",
        "-t",
        type,
        ...(type === "rsa" ? ["-b", "2048"] : []),
        "-N",
        keyPassphrase,
        "-C",
        name,
        "-a",
        "1",
        "-Z",
        cipher,
        "-f",
        keyPath,
    ])
    return {
        privateKey: await readFile(keyPath, "utf8"),
        publicKey: PublicKey.parseString(await readFile(`${keyPath}.pub`, "utf8")),
    }
}

function tamperWithAuthenticationTag(privateKey: string): string {
    const lines = privateKey.trim().split(/\r?\n/)
    const raw = Buffer.from(lines.slice(1, -1).join(""), "base64")
    raw[raw.length - 1] ^= 0x01
    const encoded = raw.toString("base64").match(/.{1,70}/g) ?? []
    return [lines[0], ...encoded, lines[lines.length - 1]].join("\n")
}

describe("OpenSSH private keys", () => {
    test("imports standard PEM private-key containers", async () => {
        const directory = await mkdtemp(join(tmpdir(), "modernssh-pem-import-"))
        const fixtures = [
            {
                name: "ed25519-pkcs8",
                algorithm: "ssh-ed25519",
                command: ["genpkey", "-algorithm", "ED25519"],
            },
            {
                name: "rsa-pkcs8",
                algorithm: "ssh-rsa",
                command: ["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"],
            },
            {
                name: "rsa-pkcs1",
                algorithm: "ssh-rsa",
                command: ["genrsa", "-traditional"],
            },
            {
                name: "ecdsa-sec1",
                algorithm: "ecdsa-sha2-nistp256",
                command: ["ecparam", "-name", "prime256v1", "-genkey", "-noout"],
            },
        ] as const
        try {
            for (const fixture of fixtures) {
                const path = join(directory, fixture.name)
                await execFileAsync("openssl", [...fixture.command, "-out", path])
                const parsed = PrivateKey.fromString(await readFile(path, "utf8"))
                const message = Buffer.from(`PEM import ${fixture.name}`)
                expect(parsed.data.alg).toBe(fixture.algorithm)
                expect(parsed.data.publicKey.verifySignature(message, parsed.sign(message))).toBe(
                    true,
                )

                const convertedPath = `${path}.openssh`
                await writeFile(convertedPath, `${parsed.toString()}\n`, { mode: 0o600 })
                const { stdout } = await execFileAsync("ssh-keygen", ["-y", "-f", convertedPath])
                expect(PublicKey.parseString(stdout).equals(parsed.data.publicKey)).toBe(true)
            }

            const source = join(directory, "ecdsa-sec1")
            const encrypted = join(directory, "ecdsa-encrypted-pkcs8")
            await execFileAsync("openssl", [
                "pkcs8",
                "-topk8",
                "-v2",
                "aes-256-cbc",
                "-in",
                source,
                "-passout",
                `pass:${passphrase}`,
                "-out",
                encrypted,
            ])
            const encryptedText = await readFile(encrypted, "utf8")
            expect(() => PrivateKey.fromString(encryptedText)).toThrow()
            expect(() => PrivateKey.fromString(encryptedText, "incorrect")).toThrow()
            const parsed = PrivateKey.fromString(encryptedText, Buffer.from(passphrase))
            expect(parsed.data.alg).toBe("ecdsa-sha2-nistp256")

            const unsupported = join(directory, "x25519-pkcs8")
            await execFileAsync("openssl", ["genpkey", "-algorithm", "X25519", "-out", unsupported])
            const unsupportedText = await readFile(unsupported, "utf8")
            expect(() => PrivateKey.fromString(unsupportedText)).toThrow(
                "Unsupported PEM private key type",
            )
        } finally {
            await rm(directory, { recursive: true, force: true })
        }
    }, 30_000)

    test("encrypts generated keys with every cipher accepted by OpenSSH", async () => {
        const directory = await mkdtemp(join(tmpdir(), "modernssh-encrypted-output-"))
        const privateKey = await PrivateKey.generate("ssh-ed25519")
        privateKey.data.comment = "encrypted-output"
        try {
            for (const cipher of ciphers) {
                const path = join(directory, cipher)
                const callerPassphrase = Buffer.from(passphrase)
                const encoded = privateKey.toString({
                    passphrase: callerPassphrase,
                    cipher,
                    rounds: 1,
                })
                expect(callerPassphrase.toString()).toBe(passphrase)
                await writeFile(path, `${encoded}\n`, { mode: 0o600 })
                const { stdout, stderr } = await execFileAsync("ssh-keygen", [
                    "-y",
                    "-P",
                    passphrase,
                    "-f",
                    path,
                ])
                expect(PublicKey.parseString(stdout).equals(privateKey.data.publicKey)).toBe(true)
                expect(stderr).toBe("")

                const parsed = PrivateKey.fromString(encoded, passphrase)
                const message = Buffer.from(`generated encryption ${cipher}`)
                expect(parsed.data.comment).toBe("encrypted-output")
                expect(parsed.data.publicKey.verifySignature(message, parsed.sign(message))).toBe(
                    true,
                )
            }

            const first = privateKey.toString({ passphrase, rounds: 1 })
            const second = privateKey.toString({ passphrase, rounds: 1 })
            expect(first).not.toBe(second)
            expect(() => PrivateKey.fromString(first, "incorrect")).toThrow(/integrity|passphrase/i)
            expect(() =>
                PrivateKey.fromString(tamperWithAuthenticationTag(first), passphrase),
            ).toThrow()
        } finally {
            await rm(directory, { recursive: true, force: true })
        }
    }, 30_000)

    test("rejects invalid private-key encryption options", async () => {
        const privateKey = await PrivateKey.generate("ssh-ed25519")
        expect(() => privateKey.toString({ passphrase: "" })).toThrow("requires a passphrase")
        expect(() => privateKey.toString({ passphrase, rounds: 0 })).toThrow("between 1")
        expect(() => privateKey.toString({ passphrase, rounds: 1.5 })).toThrow("must be an integer")
    })

    test("parses and signs every required OpenSSH ECDSA curve", async () => {
        const directory = await mkdtemp(join(tmpdir(), "modernssh-private-key-ecdsa-"))
        try {
            for (const bits of [256, 384, 521]) {
                const keyPath = join(directory, `id_ecdsa_${bits}`)
                await execFileAsync("ssh-keygen", [
                    "-q",
                    "-t",
                    "ecdsa",
                    "-b",
                    String(bits),
                    "-N",
                    "",
                    "-f",
                    keyPath,
                ])
                const privateKey = PrivateKey.fromString(await readFile(keyPath, "utf8"))
                const publicKey = PublicKey.parseString(await readFile(`${keyPath}.pub`, "utf8"))
                const data = Buffer.from(`OpenSSH ECDSA ${bits}`)

                expect(privateKey.data.publicKey.equals(publicKey)).toBe(true)
                expect(publicKey.verifySignature(data, privateKey.sign(data))).toBe(true)
            }
        } finally {
            await rm(directory, { recursive: true, force: true })
        }
    })

    test("continues to parse an unencrypted key generated by OpenSSH", async () => {
        const directory = await mkdtemp(join(tmpdir(), "modernssh-unencrypted-private-key-"))
        try {
            const fixture = await generateKey(directory, "id_ed25519", "ed25519", "aes256-ctr", "")
            const privateKey = PrivateKey.fromString(fixture.privateKey)
            const data = Buffer.from("signed using an unencrypted OpenSSH key")

            expect(privateKey.data.publicKey.equals(fixture.publicKey)).toBe(true)
            expect(fixture.publicKey.verifySignature(data, privateKey.sign(data))).toBe(true)
        } finally {
            await rm(directory, { recursive: true, force: true })
        }
    })

    test("decrypts and signs with every cipher accepted by OpenSSH", async () => {
        const directory = await mkdtemp(join(tmpdir(), "modernssh-private-key-ciphers-"))
        try {
            for (const cipher of ciphers) {
                const fixture = await generateKey(directory, cipher, "ed25519", cipher)
                const privateKey = PrivateKey.fromString(fixture.privateKey, passphrase)
                const data = Buffer.from(`signed using ${cipher}`)

                expect(privateKey.data.comment).toBe(cipher)
                expect(privateKey.data.publicKey.equals(fixture.publicKey)).toBe(true)
                expect(fixture.publicKey.verifySignature(data, privateKey.sign(data))).toBe(true)
            }
        } finally {
            await rm(directory, { recursive: true, force: true })
        }
    }, 30_000)

    test("decrypts and signs an OpenSSH RSA key", async () => {
        const directory = await mkdtemp(join(tmpdir(), "modernssh-private-key-rsa-"))
        try {
            const fixture = await generateKey(directory, "id_rsa", "rsa")
            const privateKey = PrivateKey.fromString(fixture.privateKey, Buffer.from(passphrase))
            const data = Buffer.from("signed using an encrypted OpenSSH RSA key")

            expect(privateKey.data.publicKey.equals(fixture.publicKey)).toBe(true)
            expect(fixture.publicKey.verifySignature(data, privateKey.sign(data))).toBe(true)
            for (const algorithm of ["rsa-sha2-256", "rsa-sha2-512"] as const) {
                const signature = privateKey.sign(data, algorithm)
                expect(signature.data.alg).toBe(algorithm)
                expect(fixture.publicKey.verifySignature(data, signature)).toBe(true)
            }
        } finally {
            await rm(directory, { recursive: true, force: true })
        }
    }, 15_000)

    test("rejects missing and incorrect passphrases", async () => {
        const directory = await mkdtemp(join(tmpdir(), "modernssh-private-key-passphrase-"))
        try {
            const fixture = await generateKey(directory, "id_ed25519", "ed25519")

            expect(() => PrivateKey.fromString(fixture.privateKey)).toThrow("requires a passphrase")
            expect(() => PrivateKey.fromString(fixture.privateKey, "incorrect")).toThrow(
                /integrity|passphrase/i,
            )
        } finally {
            await rm(directory, { recursive: true, force: true })
        }
    })

    test("rejects tampering with authenticated OpenSSH key data", async () => {
        const directory = await mkdtemp(join(tmpdir(), "modernssh-private-key-tamper-"))
        try {
            const fixture = await generateKey(
                directory,
                "id_ed25519",
                "ed25519",
                "aes256-gcm@openssh.com",
            )
            const tampered = tamperWithAuthenticationTag(fixture.privateKey)

            expect(() => PrivateKey.fromString(tampered, passphrase)).toThrow()
        } finally {
            await rm(directory, { recursive: true, force: true })
        }
    })

    test("lets DiskAgent resolve a passphrase for an encrypted key", async () => {
        const directory = await mkdtemp(join(tmpdir(), "modernssh-encrypted-disk-agent-"))
        try {
            const fixture = await generateKey(directory, "id_ed25519", "ed25519")
            const keyPath = join(directory, "id_ed25519")
            const publicKeyPath = `${keyPath}.pub`
            const [algorithm, blob, comment] = (await readFile(publicKeyPath, "utf8"))
                .trim()
                .split(/\s+/u)
            const multiwordComment = `${comment} deployment identity`
            await writeFile(publicKeyPath, `${algorithm}\t${blob}   ${multiwordComment}\n`)
            const invalidKeyPath = join(directory, "invalid")
            await writeFile(invalidKeyPath, "not a private key")
            await writeFile(`${invalidKeyPath}.pub`, "not a public key")
            const requestedPaths: string[] = []
            const invalidPublicKeys: string[] = []
            const agent = new DiskAgent(`${directory}/`, {
                passphrase(path) {
                    requestedPaths.push(path)
                    return passphrase
                },
                async onInvalidPublicKey(_error, path) {
                    await Promise.resolve()
                    invalidPublicKeys.push(path)
                },
            })
            const discovered = await agent.getPublicKeys()
            expect(discovered).toHaveLength(1)
            expect(discovered[0]?.[0]).toBe(keyPath)
            expect(discovered[0]?.[1].equals(fixture.publicKey)).toBe(true)
            expect(discovered[0]?.[1].data.comment).toBe(multiwordComment)
            expect(invalidPublicKeys).toEqual([`${invalidKeyPath}.pub`])
            const data = Buffer.from("signed using DiskAgent")
            const signature = await agent.sign(keyPath, data)

            expect(requestedPaths).toEqual([keyPath])
            expect(fixture.publicKey.verifySignature(data, signature)).toBe(true)
        } finally {
            await rm(directory, { recursive: true, force: true })
        }
    })

    test("DiskAgent owns signing data before awaited key loading", async () => {
        const directory = await mkdtemp(join(tmpdir(), "modernssh-disk-agent-ownership-"))
        try {
            const fixture = await generateKey(directory, "id_ed25519", "ed25519")
            const keyPath = join(directory, "id_ed25519")
            let releasePassphrase!: () => void
            const passphraseReleased = new Promise<void>((resolve) => {
                releasePassphrase = resolve
            })
            let reportPassphrase!: () => void
            const passphraseRequested = new Promise<void>((resolve) => {
                reportPassphrase = resolve
            })
            const agent = new DiskAgent(directory, {
                async passphrase() {
                    reportPassphrase()
                    await passphraseReleased
                    return passphrase
                },
            })
            const data = Buffer.from("original disk-agent message")
            const original = Buffer.from(data)
            const signing = agent.sign(keyPath, data)

            await passphraseRequested
            data.fill(0x78)
            releasePassphrase()
            const signature = await signing

            expect({
                original: fixture.publicKey.verifySignature(original, signature),
                mutated: fixture.publicKey.verifySignature(data, signature),
            }).toEqual({ original: true, mutated: false })
        } finally {
            await rm(directory, { recursive: true, force: true })
        }
    })

    test("DiskAgent owns fixed credential configuration", async () => {
        const directory = await mkdtemp(join(tmpdir(), "modernssh-disk-agent-credentials-"))
        try {
            const fixture = await generateKey(directory, "id_ed25519", "ed25519")
            const keyPath = join(directory, "id_ed25519")
            const configuredPassphrase = Buffer.from(passphrase)
            const options: { passphrase: string | Buffer } = {
                passphrase: configuredPassphrase,
            }
            const agent = new DiskAgent(directory, options)

            configuredPassphrase.fill(0)
            options.passphrase = "replaced after construction"
            const message = Buffer.from("owned disk-agent credentials")
            const signature = await agent.sign(keyPath, message)

            expect(fixture.publicKey.verifySignature(message, signature)).toBe(true)
            expect("options" in agent).toBe(false)
        } finally {
            await rm(directory, { recursive: true, force: true })
        }
    })
})
