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

const publishedStandardCertificate = Buffer.from(
    `
    00000018 65636473612d736861322d6e697374703235362d63657274
    00000020 7ee0cb878240788b087e0a23f505182898e1510fb3a2fcf6408630f625b1aa19
    00000008 6e69737470323536
    00000041 04a57c7c0829b7ee3473138352b8afc1673c714529de5f0fa6994f086f588f96
             c9ad70d30b20a4e93558ffd3f85dddfa313d294b2b9f2862dd2b58313688065c52
    ab54a98ceb1f0ad2
    00000001
    00000013 6a6f7365662e6b406578616d706c652e6f7267
    0000001e 00000007 6a6f7365662e6b 0000000f 4558414d504c455c6a6f7365662e6b
    000000004d4a2972
    0000000082e90790
    00000020 0000000d 666f7263652d636f6d6d616e64 0000000b 00000007 65786563757465
    00000082
      00000015 7065726d69742d5831312d666f7277617264696e67 00000000
      00000017 7065726d69742d6167656e742d666f7277617264696e67 00000000
      00000016 7065726d69742d706f72742d666f7277617264696e67 00000000
      0000000a 7065726d69742d707479 00000000
      0000000e 7065726d69742d757365722d7263 00000000
    00000000
    00000033 0000000b 7373682d65643235353139 00000020
      d5258df8cb1bda81d79a2f6b4d1304d4970add67eb04b9d5de47d9cc0cd5ff50
    00000053 0000000b 7373682d65643235353139 00000040
      586429cc18fd8b1d19f3210ec11e43a9bde190e605058733d333e806538181b4
      d8476efa3889670630ea8117f2e525c46e6e23785e271c2576533af5ca9f0b05
    `.replaceAll(/\s/gu, ""),
    "hex",
)

describe("certificate public keys", () => {
    test("parses and verifies the working-group draft's published certificate", () => {
        const certificate = PublicKey.parse(publishedStandardCertificate)
        expect(certificate.data.alg).toBe("ecdsa-sha2-nistp256-cert")
        expect(certificate.serialize()).toEqual(publishedStandardCertificate)
        expect(certificate.data.algorithm).toBeInstanceOf(SSHCertificatePublicKey)

        const algorithm = certificate.data.algorithm as SSHCertificatePublicKey
        expect(algorithm.verifyCertificateSignature()).toBe(true)
        expect(algorithm.publicKey.data.alg).toBe("ecdsa-sha2-nistp256")
        expect(algorithm.data).toMatchObject({
            serial: 12_345_678_901_234_567_890n,
            role: "user",
            identifier: "josef.k@example.org",
            principals: ["josef.k", "EXAMPLE\\josef.k"],
            validAfter: 0x4d4a_2972n,
            validBefore: 0x82e9_0790n,
        })
        expect(algorithm.data.criticalOptions).toEqual([
            { name: "force-command", data: serializeBuffer(Buffer.from("execute")) },
        ])
        expect(algorithm.data.extensions.map(({ name }) => name)).toEqual([
            "permit-X11-forwarding",
            "permit-agent-forwarding",
            "permit-port-forwarding",
            "permit-pty",
            "permit-user-rc",
        ])
        expect(algorithm.data.signatureKey.data.alg).toBe("ssh-ed25519")
    })

    test("requires a principal in standard certificates while retaining legacy parsing", () => {
        const principalFieldOffset = 0x00b4
        const afterPrincipalField = 0x00d6
        const emptyStandard = Buffer.concat([
            publishedStandardCertificate.subarray(0, principalFieldOffset),
            Buffer.alloc(4),
            publishedStandardCertificate.subarray(afterPrincipalField),
        ])
        expect(() => PublicKey.parse(emptyStandard)).toThrow(
            "Standard certificate must contain a principal",
        )

        const standardAlgorithmLength = 4 + "ecdsa-sha2-nistp256-cert".length
        const legacyAlgorithm = serializeBuffer(
            Buffer.from("ecdsa-sha2-nistp256-cert-v01@openssh.com"),
        )
        const legacy = Buffer.concat([
            legacyAlgorithm,
            emptyStandard.subarray(standardAlgorithmLength),
        ])
        const certificate = PublicKey.parse(legacy)
        const algorithm = certificate.data.algorithm as SSHCertificatePublicKey
        expect(algorithm.data.principals).toEqual([])
    })

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
