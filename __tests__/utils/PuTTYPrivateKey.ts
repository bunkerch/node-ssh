import { execFile } from "node:child_process"
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { promisify } from "node:util"
import { parseKey } from "../../src/KeyParsing.js"
import PrivateKey from "../../src/utils/PrivateKey.js"
import PublicKey from "../../src/utils/PublicKey.js"

const execFileAsync = promisify(execFile)
const passphrase = "correct horse battery staple"
const rfc8032PublicKey = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
const rfc8032Signature =
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" +
    "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"

const fixedPPKv2 = `PuTTY-User-Key-File-2: ssh-ed25519
Encryption: none
Comment: RFC 8032 test vector 1
Public-Lines: 2
AAAAC3NzaC1lZDI1NTE5AAAAINdamAGCsQq31Uv+08lkBzoO4XLz2qYjJa8CGmj3
B1Ea
Private-Lines: 1
AAAAIJ1hsZ3v/VpguoRK9JLsLMREScVpezJpGXA7rAMcrn9g
Private-MAC: d2ed5f47c4983f2f9d5aaf645e0f3025fb0c4303
`

const fixedPPKv3 = `PuTTY-User-Key-File-3: ssh-ed25519
Encryption: none
Comment: RFC 8032 test vector 1
Public-Lines: 2
AAAAC3NzaC1lZDI1NTE5AAAAINdamAGCsQq31Uv+08lkBzoO4XLz2qYjJa8CGmj3
B1Ea
Private-Lines: 1
AAAAIJ1hsZ3v/VpguoRK9JLsLMREScVpezJpGXA7rAMcrn9g
Private-MAC: 9e1715f10736ef557b0249bd6019eca8290a648d97b1ff752ee6be08d03b7719
`

async function generatePPK(
    directory: string,
    name: string,
    type: "ed25519" | "ed448" | "ecdsa" | "rsa" | "dsa",
    bits: number | undefined,
    parameters: string,
    keyPassphrase: string,
): Promise<{ path: string; passphrasePath: string; encoded: Buffer; publicKey: PublicKey }> {
    const path = join(directory, `${name}.ppk`)
    const passphrasePath = join(directory, `${name}.passphrase`)
    await writeFile(passphrasePath, keyPassphrase, { mode: 0o600 })
    await execFileAsync("puttygen", [
        "-q",
        "-t",
        type,
        ...(bits === undefined ? [] : ["-b", String(bits)]),
        "-C",
        name,
        "--new-passphrase",
        passphrasePath,
        "--ppk-param",
        parameters,
        "-o",
        path,
    ])
    const encoded = await readFile(path)
    const { stdout } = await execFileAsync("puttygen", [
        path,
        "-L",
        "--old-passphrase",
        passphrasePath,
    ])
    return { path, passphrasePath, encoded, publicKey: PublicKey.parseString(stdout) }
}

describe("PuTTY private keys", () => {
    test.each([
        ["version 2", fixedPPKv2],
        ["version 3", fixedPPKv3],
    ])("imports the fixed RFC 8032 Ed25519 vector in %s form", async (_name, fixture) => {
        const parsed = parseKey(Buffer.from(fixture)) as PrivateKey

        expect(parsed).toBeInstanceOf(PrivateKey)
        expect(parsed.data.alg).toBe("ssh-ed25519")
        expect(parsed.data.comment).toBe("RFC 8032 test vector 1")
        expect(
            (
                parsed.data.publicKey.data.algorithm as { data: { publicKey: Buffer } }
            ).data.publicKey.toString("hex"),
        ).toBe(rfc8032PublicKey)
        expect(parsed.sign(Buffer.alloc(0)).data.data.toString("hex")).toBe(rfc8032Signature)
        expect(PrivateKey.fromString(fixture).data.publicKey.equals(parsed.data.publicKey)).toBe(
            true,
        )

        const directory = await mkdtemp(join(tmpdir(), "modernssh-fixed-ppk-"))
        try {
            const path = join(directory, "fixed.ppk")
            await writeFile(path, fixture, { mode: 0o600 })
            const { stdout } = await execFileAsync("puttygen", [path, "-L"])
            expect(PublicKey.parseString(stdout).equals(parsed.data.publicKey)).toBe(true)
        } finally {
            await rm(directory, { recursive: true, force: true })
        }
    })

    test("imports every key family produced by puttygen and exports it to OpenSSH", async () => {
        const directory = await mkdtemp(join(tmpdir(), "modernssh-ppk-families-"))
        const fixtures = [
            ["ed25519", "ed25519", undefined, "ssh-ed25519"],
            ["ed448", "ed448", undefined, "ssh-ed448"],
            ["ecdsa-256", "ecdsa", 256, "ecdsa-sha2-nistp256"],
            ["ecdsa-384", "ecdsa", 384, "ecdsa-sha2-nistp384"],
            ["ecdsa-521", "ecdsa", 521, "ecdsa-sha2-nistp521"],
            ["rsa", "rsa", 2048, "ssh-rsa"],
            ["dsa", "dsa", 1024, "ssh-dss"],
        ] as const
        try {
            for (const [name, type, bits, algorithm] of fixtures) {
                const fixture = await generatePPK(directory, name, type, bits, "version=3", "")
                const parsed = parseKey(fixture.encoded) as PrivateKey
                const message = Buffer.from(`PPK family ${name}`)

                expect(parsed.data.alg).toBe(algorithm)
                expect(parsed.data.comment).toBe(name)
                expect(parsed.data.publicKey.equals(fixture.publicKey)).toBe(true)
                expect(fixture.publicKey.verifySignature(message, parsed.sign(message))).toBe(true)

                if (algorithm !== "ssh-ed448") {
                    const converted = join(directory, `${name}.openssh`)
                    await writeFile(converted, `${parsed.toString()}\n`, { mode: 0o600 })
                    const { stdout } = await execFileAsync("ssh-keygen", ["-y", "-f", converted])
                    expect(PublicKey.parseString(stdout).equals(fixture.publicKey)).toBe(true)
                }
            }
        } finally {
            await rm(directory, { recursive: true, force: true })
        }
    }, 30_000)

    test("imports certified Ed25519, ECDSA, and RSA keys produced by puttygen", async () => {
        const directory = await mkdtemp(join(tmpdir(), "modernssh-ppk-certificates-"))
        const caPath = join(directory, "ca")
        const fixtures = [
            ["ed25519", "ed25519", undefined, "ssh-ed25519-cert-v01@openssh.com"],
            ["ecdsa", "ecdsa", 256, "ecdsa-sha2-nistp256-cert-v01@openssh.com"],
            ["rsa", "rsa", 2048, "ssh-rsa-cert-v01@openssh.com"],
        ] as const
        try {
            await execFileAsync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", caPath])
            for (const [name, type, bits, certificateAlgorithm] of fixtures) {
                const fixture = await generatePPK(directory, name, type, bits, "version=3", "")
                const publicPath = join(directory, `${name}.pub`)
                await writeFile(publicPath, `${fixture.publicKey.toString()}\n`)
                await execFileAsync("ssh-keygen", [
                    "-q",
                    "-s",
                    caPath,
                    "-I",
                    `${name}-certificate`,
                    "-n",
                    "certified-user",
                    "-V",
                    "-1m:+1h",
                    publicPath,
                ])
                const certificatePath = join(directory, `${name}-cert.pub`)
                const certifiedPath = join(directory, `${name}-cert.ppk`)
                await execFileAsync("puttygen", [
                    fixture.path,
                    "--certificate",
                    certificatePath,
                    "--old-passphrase",
                    fixture.passphrasePath,
                    "--new-passphrase",
                    fixture.passphrasePath,
                    "--ppk-param",
                    "version=3",
                    "-O",
                    "private",
                    "-o",
                    certifiedPath,
                ])

                const certified = PrivateKey.fromPuTTY(await readFile(certifiedPath))
                const message = Buffer.from(`certified PPK ${name}`)
                expect(certified.data.alg).toBe(certificateAlgorithm)
                expect(
                    certified.data.publicKey.equals(
                        PublicKey.parseString(await readFile(certificatePath, "utf8")),
                    ),
                ).toBe(true)
                expect(
                    certified.data.publicKey.verifySignature(message, certified.sign(message)),
                ).toBe(true)
            }
        } finally {
            await rm(directory, { recursive: true, force: true })
        }
    }, 30_000)

    test("decrypts version 2 and every version 3 Argon2 mode", async () => {
        const directory = await mkdtemp(join(tmpdir(), "modernssh-encrypted-ppk-"))
        const formats = [
            ["v2", "version=2"],
            ["argon2id", "version=3,kdf=argon2id,memory=32,passes=2,parallelism=1"],
            ["argon2i", "version=3,kdf=argon2i,memory=32,passes=2,parallelism=1"],
            ["argon2d", "version=3,kdf=argon2d,memory=32,passes=2,parallelism=1"],
        ] as const
        try {
            for (const [name, parameters] of formats) {
                const fixture = await generatePPK(
                    directory,
                    name,
                    "ed25519",
                    undefined,
                    parameters,
                    passphrase,
                )
                const callerPassphrase = Buffer.from(passphrase)
                const parsed = PrivateKey.fromPuTTY(fixture.encoded, callerPassphrase)
                expect(callerPassphrase.toString()).toBe(passphrase)
                expect(parsed.data.publicKey.equals(fixture.publicKey)).toBe(true)
                expect(() => PrivateKey.fromPuTTY(fixture.encoded)).toThrow("requires a passphrase")
                expect(() => PrivateKey.fromPuTTY(fixture.encoded, "incorrect")).toThrow(
                    /integrity|passphrase/,
                )
            }

            const encrypted = (
                await generatePPK(
                    directory,
                    "bounded",
                    "ed25519",
                    undefined,
                    formats[1][1],
                    passphrase,
                )
            ).encoded.toString("utf8")
            expect(() =>
                PrivateKey.fromPuTTY(
                    encrypted.replace("Argon2-Memory: 32", "Argon2-Memory: 262145"),
                    passphrase,
                ),
            ).toThrow("Argon2 memory exceeds")
            expect(() =>
                PrivateKey.fromPuTTY(
                    encrypted.replace("Key-Derivation: Argon2id", "Key-Derivation: unknown"),
                    passphrase,
                ),
            ).toThrow("Unsupported PuTTY key derivation")
        } finally {
            await rm(directory, { recursive: true, force: true })
        }
    }, 30_000)

    test("strictly validates framing, text, base64, counts, and integrity", () => {
        const invalidUTF8 = Buffer.from(fixedPPKv3)
        invalidUTF8[invalidUTF8.indexOf(Buffer.from("RFC"))] = 0xff

        expect(() => PrivateKey.fromPuTTY(fixedPPKv3.replace("File-3", "File-4"))).toThrow(
            "Unsupported PuTTY private key version",
        )
        expect(() =>
            PrivateKey.fromPuTTY(fixedPPKv3.replace("Encryption: none", "Encryption: unknown")),
        ).toThrow("Unsupported PuTTY private key encryption")
        expect(() =>
            PrivateKey.fromPuTTY(fixedPPKv3.replace("Public-Lines: 2", "Public-Lines: 3")),
        ).toThrow()
        expect(() => PrivateKey.fromPuTTY(fixedPPKv3.replace("B1Ea", "B1E!"))).toThrow("base64")
        expect(() =>
            PrivateKey.fromPuTTY(
                fixedPPKv3.replace(
                    "AAAAC3NzaC1lZDI1NTE5AAAAINdamAGCsQq31Uv+08lkBzoO4XLz2qYjJa8CGmj3\nB1Ea",
                    "AAAAC3NzaC1lZDI1NTE5AAAAINdamAGCsQq31Uv+08lkBzoO4XLz2qYjJa8CGmj\n3B1Ea",
                ),
            ),
        ).toThrow("base64 line length")
        expect(() =>
            PrivateKey.fromPuTTY(
                fixedPPKv3.replace(
                    "9e1715f10736ef557b0249bd6019eca8290a648d97b1ff752ee6be08d03b7719",
                    "0e1715f10736ef557b0249bd6019eca8290a648d97b1ff752ee6be08d03b7719",
                ),
            ),
        ).toThrow("integrity check failed")
        expect(() => PrivateKey.fromPuTTY(`${fixedPPKv3}trailing\n`)).toThrow("Unexpected data")
        expect(() => PrivateKey.fromPuTTY(invalidUTF8)).toThrow("not valid UTF-8 text")
    })
})
