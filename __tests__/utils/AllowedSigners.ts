import { spawn } from "node:child_process"
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"

import { describe, expect, test } from "bun:test"

import AllowedSigners from "../../src/AllowedSigners.js"
import KeyRevocationList from "../../src/KeyRevocationList.js"
import SSHSignature from "../../src/SSHSignature.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

interface ProcessResult {
    readonly stdout: string
    readonly stderr: string
}

function runWithInput(
    executable: string,
    args: readonly string[],
    input: Buffer,
): Promise<ProcessResult> {
    return new Promise((resolve, reject) => {
        const child = spawn(executable, args, { stdio: "pipe" })
        const stdout: Buffer[] = []
        const stderr: Buffer[] = []
        child.stdout.on("data", (data: Buffer) => stdout.push(Buffer.from(data)))
        child.stderr.on("data", (data: Buffer) => stderr.push(Buffer.from(data)))
        child.once("error", reject)
        child.once("close", (code, signal) => {
            const result = {
                stdout: Buffer.concat(stdout).toString("utf8"),
                stderr: Buffer.concat(stderr).toString("utf8"),
            }
            if (code === 0) resolve(result)
            else reject(new Error(`${executable} exited with ${code ?? signal}: ${result.stderr}`))
        })
        child.stdin.end(input)
    })
}

describe("allowed signers", () => {
    test("combines principal, namespace, validity, and signature policy", () => {
        const privateKey = PrivateKey.generateSync("ssh-ed25519")
        const message = Buffer.from("authorized artifact")
        const signature = SSHSignature.sign(message, privateKey, { namespace: "artifact-release" })
        const allowed = AllowedSigners.parse(`
            # leading whitespace before comments is accepted
            *,!blocked@example.test namespaces="file,artifact-*",valid-after="20240101Z",valid-before="20300101Z" ${privateKey.data.publicKey}
        `)
        const at = Date.UTC(2026, 0, 1) / 1000

        expect(
            allowed.verify(message, signature, {
                principal: "alice@example.test",
                namespace: "artifact-release",
                at,
            }),
        ).toBeTrue()
        expect(
            allowed.verify(message, signature.toString(), {
                principal: "blocked@example.test",
                namespace: "artifact-release",
                at,
            }),
        ).toBeFalse()
        expect(
            allowed.verify(message, signature.serialize(), {
                principal: "alice@example.test",
                namespace: "other",
                at,
            }),
        ).toBeFalse()
        expect(
            allowed.verify(message, signature, {
                principal: "alice@example.test",
                namespace: "artifact-release",
                at: Date.UTC(2023, 11, 31) / 1000,
            }),
        ).toBeFalse()
        expect(
            allowed.verify(message, signature, {
                principal: "alice@example.test",
                namespace: "artifact-release",
                at: Date.UTC(2024, 0, 1) / 1000,
            }),
        ).toBeTrue()
        expect(
            allowed.verify(message, signature, {
                principal: "alice@example.test",
                namespace: "artifact-release",
                at: Date.UTC(2030, 0, 1) / 1000,
            }),
        ).toBeTrue()
        expect(
            allowed.verify(Buffer.from("tampered"), signature, {
                principal: "alice@example.test",
                namespace: "artifact-release",
                at,
            }),
        ).toBeFalse()
    })

    test("supports quoted namespace patterns containing spaces", () => {
        const privateKey = PrivateKey.generateSync("ssh-ed25519")
        const message = Buffer.from("space namespace")
        const signature = SSHSignature.sign(message, privateKey, { namespace: "release file" })
        const allowed = AllowedSigners.parse(
            `signer@example.test namespaces="release file" ${privateKey.data.publicKey}`,
        )

        expect(
            allowed.verify(message, signature, {
                principal: "signer@example.test",
                namespace: "release file",
            }),
        ).toBeTrue()
    })

    test("matches wildcard question marks against UTF-8 bytes", () => {
        const privateKey = PrivateKey.generateSync("ssh-ed25519")
        const message = Buffer.from("unicode principal")
        const signature = SSHSignature.sign(message, privateKey, { namespace: "file" })
        const oneByte = AllowedSigners.parse(`caf? ${privateKey.data.publicKey}`)
        const twoBytes = AllowedSigners.parse(`caf?? ${privateKey.data.publicKey}`)
        const both = AllowedSigners.parse(
            `caf? ${privateKey.data.publicKey}\ncaf?? ${privateKey.data.publicKey}`,
        )

        expect(
            oneByte.verify(message, signature, { principal: "café", namespace: "file" }),
        ).toBeFalse()
        expect(
            twoBytes.verify(message, signature, { principal: "café", namespace: "file" }),
        ).toBeTrue()
        expect(both.matchPrincipals("café")).toEqual(["caf??"])
    })

    test("finds principals for the first currently authorized signature key entry", () => {
        const privateKey = PrivateKey.generateSync("ssh-ed25519")
        const signature = SSHSignature.sign(Buffer.from("lookup"), privateKey, {
            namespace: "file",
        })
        const allowed = AllowedSigners.parse(`
            expired@example.test valid-before="20200101Z" ${privateKey.data.publicKey}
            release-*,admin@example.test valid-after="20200101Z" ${privateKey.data.publicKey}
            later@example.test ${privateKey.data.publicKey}
        `)

        expect(allowed.findPrincipals(signature, { at: Date.UTC(2026, 0, 1) / 1000 })).toEqual([
            "release-*",
            "admin@example.test",
        ])
        expect(allowed.findPrincipals(signature, { at: Date.UTC(2019, 0, 1) / 1000 })).toEqual([
            "expired@example.test",
        ])
        expect(() => allowed.findPrincipals(signature, null as never)).toThrow(
            "lookup options must be an object",
        )
    })

    test.each([
        ["missing key", "signer@example.test"],
        ["unknown option", "signer@example.test future-option ssh-ed25519 AAAA"],
        ["duplicate option", "signer@example.test cert-authority,cert-authority ssh-ed25519 AAAA"],
        ["unquoted option", "signer@example.test valid-after=20240101Z ssh-ed25519 AAAA"],
        ["bad timestamp", 'signer@example.test valid-after="20240230Z" ssh-ed25519 AAAA'],
        [
            "reversed validity",
            'signer@example.test valid-after="20300101Z",valid-before="20240101Z" ssh-ed25519 AAAA',
        ],
        ["empty principal", ",signer@example.test ssh-ed25519 AAAA"],
        ["unterminated quote", 'signer@example.test namespaces="file ssh-ed25519 AAAA'],
    ])("rejects a %s", (_name, content) => {
        expect(() => AllowedSigners.parse(content)).toThrow("Invalid allowed-signers line 1")
    })

    test("rejects invalid text and bounded input", () => {
        expect(() => AllowedSigners.parse(Buffer.from([0xff]))).toThrow("not valid UTF-8")
        expect(() => AllowedSigners.parse("signer\0 key")).toThrow("contains NUL")
        expect(() => AllowedSigners.parse("x".repeat(64 * 1024 + 1))).toThrow(
            "line 1 exceeds the maximum length",
        )
    })

    test("authorizes a command-line certificate through its CA and honors revocation", async () => {
        const directory = await mkdtemp(join(tmpdir(), "modernssh-allowed-signers-"))
        try {
            const caPath = join(directory, "ca")
            const subjectPath = join(directory, "subject")
            const messagePath = join(directory, "artifact")
            const allowedPath = join(directory, "allowed_signers")
            const revocationsPath = join(directory, "revocations.krl")
            const message = Buffer.from("certificate-backed artifact\n")
            await runWithInput(
                "ssh-keygen",
                ["-q", "-t", "ed25519", "-N", "", "-f", caPath],
                Buffer.alloc(0),
            )
            await runWithInput(
                "ssh-keygen",
                ["-q", "-t", "ed25519", "-N", "", "-f", subjectPath],
                Buffer.alloc(0),
            )
            await runWithInput(
                "ssh-keygen",
                [
                    "-q",
                    "-s",
                    caPath,
                    "-I",
                    "artifact-signer",
                    "-n",
                    "alice@example.test",
                    "-V",
                    "-1h:+1h",
                    `${subjectPath}.pub`,
                ],
                Buffer.alloc(0),
            )
            await writeFile(messagePath, message)
            await runWithInput(
                "ssh-keygen",
                ["-Y", "sign", "-f", `${subjectPath}-cert.pub`, "-n", "artifact", messagePath],
                Buffer.alloc(0),
            )
            const ca = (await readFile(`${caPath}.pub`, "utf8")).trim()
            await writeFile(allowedPath, `caf? ${ca}\ncaf?? ${ca}\n`)
            const unicodeMatch = await runWithInput(
                "ssh-keygen",
                ["-Y", "match-principals", "-f", allowedPath, "-I", "café"],
                Buffer.alloc(0),
            )
            expect(unicodeMatch.stdout.trim()).toBe("caf??")

            const allowedText = `*@example.test CERT-AUTHORITY,NAMESPACES="artifact" ${ca}\n`
            await writeFile(allowedPath, allowedText)
            const allowed = await AllowedSigners.load(allowedPath)
            const signature = SSHSignature.parse(await readFile(`${messagePath}.sig`))

            expect(allowed.matchPrincipals("alice@example.test")).toEqual(["*@example.test"])
            expect(allowed.findPrincipals(signature)).toEqual(["alice@example.test"])
            expect(
                allowed.verify(message, signature, {
                    principal: "alice@example.test",
                    namespace: "artifact",
                }),
            ).toBeTrue()
            expect(
                allowed.verify(message, signature, {
                    principal: "bob@example.test",
                    namespace: "artifact",
                }),
            ).toBeFalse()
            const system = await runWithInput(
                "ssh-keygen",
                [
                    "-Y",
                    "verify",
                    "-f",
                    allowedPath,
                    "-I",
                    "alice@example.test",
                    "-n",
                    "artifact",
                    "-s",
                    `${messagePath}.sig`,
                ],
                message,
            )
            expect(system.stdout).toContain('Good "artifact" signature')
            const systemPrincipals = await runWithInput(
                "ssh-keygen",
                ["-Y", "find-principals", "-f", allowedPath, "-s", `${messagePath}.sig`],
                Buffer.alloc(0),
            )
            expect(systemPrincipals.stdout.trim()).toBe(
                allowed.findPrincipals(signature).join("\n"),
            )

            await runWithInput(
                "ssh-keygen",
                ["-q", "-k", "-f", revocationsPath, `${subjectPath}-cert.pub`],
                Buffer.alloc(0),
            )
            const revocations = await KeyRevocationList.load(revocationsPath)
            expect(
                allowed.verify(message, signature, {
                    principal: "alice@example.test",
                    namespace: "artifact",
                    revocations,
                }),
            ).toBeFalse()
        } finally {
            await rm(directory, { recursive: true, force: true })
        }
    }, 20_000)
})
