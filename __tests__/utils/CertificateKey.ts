import { execFile } from "node:child_process"
import { mkdtemp, readFile, rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { promisify } from "node:util"
import { serializeBuffer } from "../../src/utils/Buffer.js"
import PublicKey, {
    parseCertificateOptions,
    SSHCertificatePublicKey,
} from "../../src/utils/PublicKey.js"

const execFileAsync = promisify(execFile)

describe("certificate public keys", () => {
    test("orders option names by their exact UTF-8 wire bytes", () => {
        const lower = Buffer.from("\ue000")
        const higher = Buffer.from("\u{10000}")
        const pair = (name: Buffer) =>
            Buffer.concat([serializeBuffer(name), serializeBuffer(Buffer.alloc(0))])
        const ordered = Buffer.concat([pair(lower), pair(higher)])

        expect(parseCertificateOptions(ordered).map(({ name }) => name)).toEqual([
            "\ue000",
            "\u{10000}",
        ])
        expect(() => parseCertificateOptions(Buffer.concat([pair(higher), pair(lower)]))).toThrow(
            "not sorted",
        )
    })

    test("rejects duplicate and malformed UTF-8 option names", () => {
        const pair = (name: Buffer) =>
            Buffer.concat([serializeBuffer(name), serializeBuffer(Buffer.alloc(0))])
        const name = Buffer.from("force-command")

        expect(() => parseCertificateOptions(Buffer.concat([pair(name), pair(name)]))).toThrow(
            "not sorted",
        )
        expect(() => parseCertificateOptions(pair(Buffer.from([0xff])))).toThrow("Invalid UTF-8")
    })

    test.each([
        ["ed25519", []],
        ["rsa", ["-b", "2048"]],
        ["ecdsa", ["-b", "256"]],
    ])("parses and verifies an OpenSSH %s certificate", async (type, keyOptions) => {
        const directory = await mkdtemp(join(tmpdir(), "modernssh-certificate-"))
        try {
            const ca = join(directory, "ca")
            const subject = join(directory, "subject")
            await execFileAsync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", ca])
            await execFileAsync("ssh-keygen", [
                "-q",
                "-t",
                type,
                ...keyOptions,
                "-N",
                "",
                "-f",
                subject,
            ])
            await execFileAsync("ssh-keygen", [
                "-q",
                "-s",
                ca,
                "-I",
                "integration@example.test",
                "-n",
                "alice,bob",
                "-V",
                "-1m:+1h",
                "-z",
                "18446744073709551615",
                `${subject}.pub`,
            ])

            const line = await readFile(`${subject}-cert.pub`, "utf8")
            const certificate = PublicKey.parseString(line)
            expect(certificate.toString()).toBe(line.trim())
            expect(certificate.data.algorithm).toBeInstanceOf(SSHCertificatePublicKey)
            const algorithm = certificate.data.algorithm as SSHCertificatePublicKey
            expect(algorithm.verifyCertificateSignature()).toBe(true)
            expect(algorithm.data.serial).toBe(0xffffffffffffffffn)
            expect(algorithm.data.role).toBe("user")
            expect(algorithm.data.identifier).toBe("integration@example.test")
            expect(algorithm.data.principals).toEqual(["alice", "bob"])
            expect(algorithm.data.signatureKey.data.alg).toBe("ssh-ed25519")
            expect(algorithm.publicKey.data.alg).toBe(
                type === "ed25519"
                    ? "ssh-ed25519"
                    : type === "rsa"
                      ? "ssh-rsa"
                      : "ecdsa-sha2-nistp256",
            )

            const tampered = Buffer.from(certificate.serialize())
            tampered[tampered.length - 1] ^= 1
            const tamperedCertificate = PublicKey.parse(tampered)
            expect(
                (
                    tamperedCertificate.data.algorithm as SSHCertificatePublicKey
                ).verifyCertificateSignature(),
            ).toBe(false)
        } finally {
            await rm(directory, { recursive: true, force: true })
        }
    })
})
