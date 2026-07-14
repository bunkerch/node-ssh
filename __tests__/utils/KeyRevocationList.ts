import { execFile } from "node:child_process"
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { promisify } from "node:util"

import { generateKeyPairSync } from "../../src/KeyGeneration.js"
import KeyRevocationList from "../../src/KeyRevocationList.js"
import PublicKey from "../../src/utils/PublicKey.js"

const execFileAsync = promisify(execFile)

// Literal PROTOCOL.krl framing signed by the first two RFC 8032 Ed25519 test keys.
const fixedSignedKRL = Buffer.from(
    "5353484b524c0a00000000010000000000000007000000006553f100000000000000000000000000000000106669786564207369676e6564204b524c05000000240000002066402c9468c58941dd19ffd650bf2b42f9226f83d3bd06ad515d0e5104a7702004000000330000000b7373682d6564323535313900000020d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a000000530000000b7373682d65643235353139000000408f55d92be0f96b273e333825a05634741071c40057da9e7b4858b74d787cadd58ea7973b14f0894cfd77ac583bd153fac574f346dd58bb525d1a9a47a75be50604000000330000000b7373682d65643235353139000000203d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c000000530000000b7373682d6564323535313900000040e870d2b9996c52851dbf3701a8b3ac20368ba5bfd15c09f3605d06ec28f6dad797e0584b31721266276778a0ea1051b29027c6c56327b3ff8130ba062ec0390a",
    "hex",
)
const fixedRevokedKey = Buffer.from(
    "0000000b7373682d6564323535313900000020000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "hex",
)
const fixedKRLSigners = [
    Buffer.from(
        "0000000b7373682d6564323535313900000020d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "hex",
    ),
    Buffer.from(
        "0000000b7373682d65643235353139000000203d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "hex",
    ),
]

describe("key revocation lists", () => {
    test("recognizes an explicit key revoked by ssh-keygen", async () => {
        const directory = await mkdtemp(join(tmpdir(), "modernssh-krl-explicit-"))
        try {
            const revoked = generateKeyPairSync("ed25519").publicKey
            const allowed = generateKeyPairSync("ed25519").publicKey
            const keyPath = join(directory, "revoked.pub")
            const krlPath = join(directory, "revoked.krl")
            await writeFile(keyPath, `${revoked.toString()}\n`)
            await execFileAsync("ssh-keygen", ["-q", "-k", "-f", krlPath, keyPath])

            const krl = KeyRevocationList.parse(await readFile(krlPath))
            expect([krl.isRevoked(revoked), krl.isRevoked(allowed)]).toEqual([true, false])
        } finally {
            await rm(directory, { recursive: true, force: true })
        }
    })

    test("recognizes fixed SHA fingerprint sections", () => {
        const key = PublicKey.parseString(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINdamAGCsQq31Uv+08lkBzoO4XLz2qYjJa8CGmj3B1Ea",
        )
        const sha256Bytes = Buffer.from(
            "5353484b524c0a0000000001000000000000000000000000000000000000000000000000000000000000000d6669786564205348412d3235360500000024000000206db5e9b8a1bace1cdd9a7c6adb9e9396acc5073465d9fe8e3a0ef6d9c60d6d4f",
            "hex",
        )
        const sha256 = KeyRevocationList.parse(sha256Bytes)
        const sha1 = KeyRevocationList.parse(
            Buffer.from(
                "5353484b524c0a00000000010000000000000000000000000000000000000000000000000000000000000000030000001800000014e4c18926afa5dbfd10c0e06a60bac698e1fb2793",
                "hex",
            ),
        )
        sha256Bytes.fill(0)

        expect([sha1.isRevoked(key), sha256.isRevoked(key)]).toEqual([true, true])
        expect({
            version: sha256.version,
            generatedAt: sha256.generatedAt,
            comment: sha256.comment,
        }).toEqual({
            version: 0n,
            generatedAt: 0n,
            comment: "fixed SHA-256",
        })
    })

    test("verifies consecutive fixed signature sections and exposes signer trust", () => {
        const content = Buffer.from(fixedSignedKRL)
        const krl = KeyRevocationList.parse(content)
        content.fill(0)

        expect(krl.isRevoked(fixedRevokedKey)).toBe(true)
        expect(fixedKRLSigners.map((signer) => krl.isSignedBy(signer))).toEqual([true, true])
        expect(krl.isSignedBy(generateKeyPairSync("ed25519").publicKey)).toBe(false)
        expect({
            version: krl.version,
            generatedAt: krl.generatedAt,
            comment: krl.comment,
        }).toEqual({
            version: 7n,
            generatedAt: 1_700_000_000n,
            comment: "fixed signed KRL",
        })
    })

    test("rejects invalid or non-final KRL signatures", () => {
        const changedRecord = Buffer.from(fixedSignedKRL)
        changedRecord[69] ^= 1
        expect(() => KeyRevocationList.parse(changedRecord)).toThrow("signature")

        const changedSignature = Buffer.from(fixedSignedKRL)
        changedSignature[changedSignature.length - 1] ^= 1
        expect(() => KeyRevocationList.parse(changedSignature)).toThrow("signature")

        const sectionAfterSignature = Buffer.concat([fixedSignedKRL, Buffer.from([5, 0, 0, 0, 0])])
        expect(() => KeyRevocationList.parse(sectionAfterSignature)).toThrow(
            "signature sections must be final",
        )
    })

    test("recognizes a certificate serial revoked by its authority", async () => {
        const directory = await mkdtemp(join(tmpdir(), "modernssh-krl-certificate-"))
        try {
            const authorityPath = join(directory, "authority")
            const revokedPath = join(directory, "revoked")
            const allowedPath = join(directory, "allowed")
            const krlPath = join(directory, "revoked.krl")
            for (const path of [authorityPath, revokedPath, allowedPath]) {
                await execFileAsync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", path])
            }
            await execFileAsync("ssh-keygen", [
                "-q",
                "-s",
                authorityPath,
                "-I",
                "revoked-certificate",
                "-z",
                "42",
                `${revokedPath}.pub`,
            ])
            await execFileAsync("ssh-keygen", [
                "-q",
                "-s",
                authorityPath,
                "-I",
                "allowed-certificate",
                "-z",
                "43",
                `${allowedPath}.pub`,
            ])
            await execFileAsync("ssh-keygen", [
                "-q",
                "-k",
                "-f",
                krlPath,
                "-s",
                `${authorityPath}.pub`,
                `${revokedPath}-cert.pub`,
            ])

            const revoked = PublicKey.parseString(await readFile(`${revokedPath}-cert.pub`, "utf8"))
            const allowed = PublicKey.parseString(await readFile(`${allowedPath}-cert.pub`, "utf8"))
            const krl = await KeyRevocationList.load(krlPath)
            expect([krl.isRevoked(revoked), krl.isRevoked(allowed)]).toEqual([true, false])
        } finally {
            await rm(directory, { recursive: true, force: true })
        }
    })

    test("recognizes a revoked certificate serial range", async () => {
        const directory = await mkdtemp(join(tmpdir(), "modernssh-krl-range-"))
        try {
            const authorityPath = join(directory, "authority")
            const krlPath = join(directory, "revoked.krl")
            const specificationPath = join(directory, "revocations")
            await execFileAsync("ssh-keygen", [
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-f",
                authorityPath,
            ])
            const certificates: PublicKey[] = []
            for (const serial of [100, 150, 201]) {
                const identityPath = join(directory, `identity-${serial}`)
                await execFileAsync("ssh-keygen", [
                    "-q",
                    "-t",
                    "ed25519",
                    "-N",
                    "",
                    "-f",
                    identityPath,
                ])
                await execFileAsync("ssh-keygen", [
                    "-q",
                    "-s",
                    authorityPath,
                    "-I",
                    `identity-${serial}`,
                    "-z",
                    String(serial),
                    `${identityPath}.pub`,
                ])
                certificates.push(
                    PublicKey.parseString(await readFile(`${identityPath}-cert.pub`, "utf8")),
                )
            }
            await writeFile(specificationPath, "serial: 100-200\n")
            await execFileAsync("ssh-keygen", [
                "-q",
                "-k",
                "-f",
                krlPath,
                "-s",
                `${authorityPath}.pub`,
                specificationPath,
            ])

            const krl = await KeyRevocationList.load(krlPath)
            expect(certificates.map((certificate) => krl.isRevoked(certificate))).toEqual([
                true,
                true,
                false,
            ])
        } finally {
            await rm(directory, { recursive: true, force: true })
        }
    })

    test("recognizes a compact certificate serial bitmap", async () => {
        const directory = await mkdtemp(join(tmpdir(), "modernssh-krl-bitmap-"))
        try {
            const authorityPath = join(directory, "authority")
            const krlPath = join(directory, "revoked.krl")
            const specificationPath = join(directory, "revocations")
            await execFileAsync("ssh-keygen", [
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-f",
                authorityPath,
            ])
            const certificates: PublicKey[] = []
            for (const serial of [100, 101, 106]) {
                const identityPath = join(directory, `identity-${serial}`)
                await execFileAsync("ssh-keygen", [
                    "-q",
                    "-t",
                    "ed25519",
                    "-N",
                    "",
                    "-f",
                    identityPath,
                ])
                await execFileAsync("ssh-keygen", [
                    "-q",
                    "-s",
                    authorityPath,
                    "-I",
                    `identity-${serial}`,
                    "-z",
                    String(serial),
                    `${identityPath}.pub`,
                ])
                certificates.push(
                    PublicKey.parseString(await readFile(`${identityPath}-cert.pub`, "utf8")),
                )
            }
            await writeFile(
                specificationPath,
                "serial: 100\nserial: 102\nserial: 104\nserial: 106\n",
            )
            await execFileAsync("ssh-keygen", [
                "-q",
                "-k",
                "-f",
                krlPath,
                "-s",
                `${authorityPath}.pub`,
                specificationPath,
            ])

            const krl = await KeyRevocationList.load(krlPath)
            expect(certificates.map((certificate) => krl.isRevoked(certificate))).toEqual([
                true,
                false,
                true,
            ])
        } finally {
            await rm(directory, { recursive: true, force: true })
        }
    })

    test("recognizes a revoked certificate key identifier", async () => {
        const directory = await mkdtemp(join(tmpdir(), "modernssh-krl-identifier-"))
        try {
            const authorityPath = join(directory, "authority")
            const krlPath = join(directory, "revoked.krl")
            const specificationPath = join(directory, "revocations")
            await execFileAsync("ssh-keygen", [
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-f",
                authorityPath,
            ])
            const certificates: PublicKey[] = []
            for (const identifier of ["blocked-identity", "allowed-identity"]) {
                const identityPath = join(directory, identifier)
                await execFileAsync("ssh-keygen", [
                    "-q",
                    "-t",
                    "ed25519",
                    "-N",
                    "",
                    "-f",
                    identityPath,
                ])
                await execFileAsync("ssh-keygen", [
                    "-q",
                    "-s",
                    authorityPath,
                    "-I",
                    identifier,
                    `${identityPath}.pub`,
                ])
                certificates.push(
                    PublicKey.parseString(await readFile(`${identityPath}-cert.pub`, "utf8")),
                )
            }
            await writeFile(specificationPath, "id: blocked-identity\n")
            await execFileAsync("ssh-keygen", [
                "-q",
                "-k",
                "-f",
                krlPath,
                "-s",
                `${authorityPath}.pub`,
                specificationPath,
            ])

            const krl = await KeyRevocationList.load(krlPath)
            const wildcard = KeyRevocationList.parse(
                Buffer.from(
                    "5353484b524c0a0000000001000000000000000000000000000000000000000000000000000000000000000001000000210000000000000000230000001400000010626c6f636b65642d6964656e74697479",
                    "hex",
                ),
            )
            expect(certificates.map((certificate) => krl.isRevoked(certificate))).toEqual([
                true,
                false,
            ])
            expect(certificates.map((certificate) => wildcard.isRevoked(certificate))).toEqual([
                true,
                false,
            ])
        } finally {
            await rm(directory, { recursive: true, force: true })
        }
    })

    test("rejects certificate serial zero like ssh-keygen", async () => {
        const directory = await mkdtemp(join(tmpdir(), "modernssh-krl-zero-serial-"))
        try {
            const authorityPath = join(directory, "authority")
            const identityPath = join(directory, "identity")
            const krlPath = join(directory, "revoked.krl")
            const specificationPath = join(directory, "revocations")
            for (const path of [authorityPath, identityPath]) {
                await execFileAsync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", path])
            }
            await execFileAsync("ssh-keygen", [
                "-q",
                "-s",
                authorityPath,
                "-I",
                "unnumbered",
                `${identityPath}.pub`,
            ])
            await writeFile(specificationPath, "serial: 42\n")
            await execFileAsync("ssh-keygen", [
                "-q",
                "-k",
                "-f",
                krlPath,
                "-s",
                `${authorityPath}.pub`,
                specificationPath,
            ])
            const content = await readFile(krlPath)
            content.fill(0, content.length - 8)
            await writeFile(krlPath, content)
            await expect(
                execFileAsync("ssh-keygen", ["-Q", "-f", krlPath, `${identityPath}-cert.pub`]),
            ).rejects.toThrow()
            expect(() => KeyRevocationList.parse(content)).toThrow("serial zero")
        } finally {
            await rm(directory, { recursive: true, force: true })
        }
    })

    test("applies a plain-key revocation to a certificate's embedded key", async () => {
        const directory = await mkdtemp(join(tmpdir(), "modernssh-krl-certified-key-"))
        try {
            const authorityPath = join(directory, "authority")
            const identityPath = join(directory, "identity")
            const krlPath = join(directory, "revoked.krl")
            const specificationPath = join(directory, "revocations")
            for (const path of [authorityPath, identityPath]) {
                await execFileAsync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", path])
            }
            await execFileAsync("ssh-keygen", [
                "-q",
                "-s",
                authorityPath,
                "-I",
                "certified-key",
                `${identityPath}.pub`,
            ])
            const certificateText = await readFile(`${identityPath}-cert.pub`, "utf8")
            await writeFile(specificationPath, `key: ${certificateText}`)
            await execFileAsync("ssh-keygen", ["-q", "-k", "-f", krlPath, specificationPath])

            const krl = await KeyRevocationList.load(krlPath)
            expect(krl.isRevoked(PublicKey.parseString(certificateText))).toBe(true)
        } finally {
            await rm(directory, { recursive: true, force: true })
        }
    })

    test("applies a fingerprint directive to a certificate's plain key", async () => {
        const directory = await mkdtemp(join(tmpdir(), "modernssh-krl-certificate-hash-"))
        try {
            const authorityPath = join(directory, "authority")
            const identityPath = join(directory, "identity")
            const krlPath = join(directory, "revoked.krl")
            const specificationPath = join(directory, "revocations")
            for (const path of [authorityPath, identityPath]) {
                await execFileAsync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", path])
            }
            await execFileAsync("ssh-keygen", [
                "-q",
                "-s",
                authorityPath,
                "-I",
                "fingerprinted-certificate",
                `${identityPath}.pub`,
            ])
            const certificateText = await readFile(`${identityPath}-cert.pub`, "utf8")
            await writeFile(specificationPath, `sha256: ${certificateText}`)
            await execFileAsync("ssh-keygen", ["-q", "-k", "-f", krlPath, specificationPath])

            const krl = await KeyRevocationList.load(krlPath)
            expect(krl.isRevoked(PublicKey.parseString(certificateText))).toBe(true)
        } finally {
            await rm(directory, { recursive: true, force: true })
        }
    })

    test("revokes certificates signed by a revoked authority", async () => {
        const directory = await mkdtemp(join(tmpdir(), "modernssh-krl-authority-"))
        try {
            const authorityPath = join(directory, "authority")
            const identityPath = join(directory, "identity")
            const krlPath = join(directory, "revoked.krl")
            for (const path of [authorityPath, identityPath]) {
                await execFileAsync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", path])
            }
            await execFileAsync("ssh-keygen", [
                "-q",
                "-s",
                authorityPath,
                "-I",
                "revoked-authority",
                `${identityPath}.pub`,
            ])
            await execFileAsync("ssh-keygen", ["-q", "-k", "-f", krlPath, `${authorityPath}.pub`])

            const certificate = PublicKey.parseString(
                await readFile(`${identityPath}-cert.pub`, "utf8"),
            )
            const krl = await KeyRevocationList.load(krlPath)
            expect(krl.isRevoked(certificate)).toBe(true)
        } finally {
            await rm(directory, { recursive: true, force: true })
        }
    })

    test("ignores optional extensions and rejects critical extensions", () => {
        const allowed = generateKeyPairSync("ed25519").publicKey
        const optional = Buffer.from(
            "5353484b524c0a00000000010000000000000000000000000000000000000000000000000000000000000000ff0000002100000012667574757265406578616d706c652e636f6d00000000066f7061717565",
            "hex",
        )
        const critical = Buffer.from(
            "5353484b524c0a00000000010000000000000000000000000000000000000000000000000000000000000000ff0000002100000012667574757265406578616d706c652e636f6d01000000066f7061717565",
            "hex",
        )

        expect(KeyRevocationList.parse(optional).isRevoked(allowed)).toBe(false)
        expect(() => KeyRevocationList.parse(critical)).toThrow("critical extension")
    })

    test("applies extension criticality inside certificate sections", () => {
        const optional = Buffer.from(
            "5353484b524c0a0000000001000000000000000000000000000000000000000000000000000000000000000001000000330000000000000000390000002600000017636572742d667574757265406578616d706c652e636f6d00000000066f7061717565",
            "hex",
        )
        const critical = Buffer.from(
            "5353484b524c0a0000000001000000000000000000000000000000000000000000000000000000000000000001000000330000000000000000390000002600000017636572742d667574757265406578616d706c652e636f6d01000000066f7061717565",
            "hex",
        )

        expect(() => KeyRevocationList.parse(optional)).not.toThrow()
        expect(() => KeyRevocationList.parse(critical)).toThrow("critical extension")
    })

    test("rejects NUL in the header comment", () => {
        const invalid = Buffer.from(
            "5353484b524c0a0000000001000000000000000000000000000000000000000000000000000000000000000100",
            "hex",
        )

        expect(() => KeyRevocationList.parse(invalid)).toThrow("NUL")
    })

    test("rejects a certificate bitmap that wraps the serial space", () => {
        const invalid = Buffer.from(
            "5353484b524c0a00000000010000000000000000000000000000000000000000000000000000000000000000010000001a0000000000000000220000000dffffffffffffffff0000000102",
            "hex",
        )

        expect(() => KeyRevocationList.parse(invalid)).toThrow("wraps")
    })
})
