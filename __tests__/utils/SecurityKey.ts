import { execFile } from "node:child_process"
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { promisify } from "node:util"
import EncodedSignature from "../../src/utils/Signature.js"
import PublicKey, {
    SSHCertificatePublicKey,
    SSHECDSASecurityKeyPublicKey,
    SSHED25519SecurityKeyPublicKey,
} from "../../src/utils/PublicKey.js"

const execFileAsync = promisify(execFile)

const message = Buffer.from("security-key-message")
const ed25519KeyBlob = Buffer.from(
    "0000001a736b2d7373682d65643235353139406f70656e7373682e636f6d" +
        "00000020d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a" +
        "000000087373683a74657374",
    "hex",
)
const ecdsaKeyBlob = Buffer.from(
    "00000022736b2d65636473612d736861322d6e69737470323536406f70656e7373682e636f6d" +
        "000000086e69737470323536" +
        "000000410460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6" +
        "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299" +
        "000000087373683a74657374",
    "hex",
)
const ed25519Signature = Buffer.from(
    "0000001a736b2d7373682d65643235353139406f70656e7373682e636f6d" +
        "00000040f2330a0e0f6b9da42b530f7e14a4bb4db0832754452a0bdb90c002f6c922508e" +
        "ad849b2fb57a5552fcd92d407616d7347dafb9335e1e46a806f01de7bcd2d10f" +
        "010000002a",
    "hex",
)
const ecdsaSignature = Buffer.from(
    "00000022736b2d65636473612d736861322d6e69737470323536406f70656e7373682e636f6d" +
        "00000049" +
        "0000002056bf7a71fa4cf1280a0d1d74a0086dc8d36b104ea8a07a9cbc419dfea63dccf3" +
        "0000002100bcad5f4b4f374d70e670cbd29ad2df5e9585520ff8fafeff4392855ce8646536" +
        "010000002a",
    "hex",
)
const webAuthnSignature = Buffer.from(
    "0000002b776562617574686e2d736b2d65636473612d736861322d6e69737470323536406f70656e7373682e636f6d" +
        "0000004a" +
        "0000002100edaba6336340aa67989b2fc689c3ecdadadcb3134126e385b44f3bf2dbe49ad0" +
        "000000210097f2f9f6cc7be5dfc388c07ff2f0aeb8df60be71bba070bc6afc2715696fedb5" +
        "010000002b" +
        "0000001468747470733a2f2f6578616d706c652e74657374" +
        "000000757b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a" +
        "226332566a64584a7064486b74613256354c57316c63334e685a3255222c226f726967696e223a" +
        "2268747470733a2f2f6578616d706c652e74657374222c2263726f73734f726967696e223a6661" +
        "6c73657d00000000",
    "hex",
)

describe("OpenSSH security-key identities", () => {
    test("parses and verifies fixed Ed25519 and ECDSA security-key values", () => {
        const ed25519 = PublicKey.parse(ed25519KeyBlob)
        const ecdsa = PublicKey.parse(ecdsaKeyBlob)
        expect(ed25519.data.algorithm).toBeInstanceOf(SSHED25519SecurityKeyPublicKey)
        expect(ecdsa.data.algorithm).toBeInstanceOf(SSHECDSASecurityKeyPublicKey)
        expect(ed25519.serialize()).toEqual(ed25519KeyBlob)
        expect(ecdsa.serialize()).toEqual(ecdsaKeyBlob)
        expect((ed25519.data.algorithm as SSHED25519SecurityKeyPublicKey).data.application).toBe(
            "ssh:test",
        )
        expect((ecdsa.data.algorithm as SSHECDSASecurityKeyPublicKey).data.application).toBe(
            "ssh:test",
        )

        const ed25519Encoded = EncodedSignature.parse(ed25519Signature)
        const ecdsaEncoded = EncodedSignature.parse(ecdsaSignature)
        expect(ed25519Encoded.data.securityKey).toEqual({ flags: 1, counter: 42 })
        expect(ecdsaEncoded.data.securityKey).toEqual({ flags: 1, counter: 42 })
        expect(ed25519Encoded.serialize()).toEqual(ed25519Signature)
        expect(ecdsaEncoded.serialize()).toEqual(ecdsaSignature)
        expect(ed25519.verifySignature(message, ed25519Encoded)).toBeTrue()
        expect(ecdsa.verifySignature(message, ecdsaEncoded)).toBeTrue()

        const tampered = new EncodedSignature({
            ...ed25519Encoded.data,
            securityKey: { flags: 1, counter: 43 },
        })
        expect(ed25519.verifySignature(message, tampered)).toBeFalse()
    })

    test("verifies a fixed WebAuthn ECDSA security-key signature", () => {
        const publicKey = PublicKey.parse(ecdsaKeyBlob)
        const signature = EncodedSignature.parse(webAuthnSignature)
        expect(signature.serialize()).toEqual(webAuthnSignature)
        expect(signature.data.securityKey).toEqual({
            flags: 1,
            counter: 43,
            webAuthn: {
                origin: "https://example.test",
                clientData: Buffer.from(
                    '{"type":"webauthn.get","challenge":"c2VjdXJpdHkta2V5LW1lc3NhZ2U","origin":"https://example.test","crossOrigin":false}',
                ),
                extensions: Buffer.alloc(0),
            },
        })
        expect(publicKey.supportsSignatureAlgorithm(signature.data.alg)).toBeTrue()
        expect(publicKey.verifySignature(message, signature)).toBeTrue()

        signature.data.securityKey!.webAuthn!.clientData[40] ^= 1
        expect(publicKey.verifySignature(message, signature)).toBeFalse()
    })

    test("rejects inconsistent WebAuthn origins, flags, and extensions", () => {
        const publicKey = PublicKey.parse(ecdsaKeyBlob)
        const original = EncodedSignature.parse(webAuthnSignature)
        const securityKey = original.data.securityKey!
        const webAuthn = securityKey.webAuthn!
        const variants = [
            { flags: 0x41, webAuthn },
            { flags: 0x81, webAuthn },
            { flags: 1, webAuthn: { ...webAuthn, extensions: Buffer.from([1]) } },
            { flags: 1, webAuthn: { ...webAuthn, origin: 'https://example.test"' } },
        ]

        for (const variant of variants) {
            const signature = new EncodedSignature({
                ...original.data,
                securityKey: { counter: securityKey.counter, ...variant },
            })
            expect(publicKey.verifySignature(message, signature)).toBeFalse()
        }
    })

    test("rejects malformed security-key wire values", () => {
        const invalidApplication = Buffer.from(ed25519KeyBlob)
        invalidApplication[invalidApplication.length - 1] = 0xff
        const emptyApplication = Buffer.concat([
            ed25519KeyBlob.subarray(0, ed25519KeyBlob.length - 12),
            Buffer.alloc(4),
        ])

        expect(() => PublicKey.parse(invalidApplication)).toThrow("not valid UTF-8")
        expect(() => PublicKey.parse(emptyApplication)).toThrow("must not be empty")
        expect(() => PublicKey.parse(Buffer.concat([ecdsaKeyBlob, Buffer.alloc(1)]))).toThrow(
            "Unexpected ECDSA security-key data",
        )
        expect(() => EncodedSignature.parse(ed25519Signature.subarray(0, -1))).toThrow()
        expect(() =>
            EncodedSignature.parse(Buffer.concat([ed25519Signature, Buffer.alloc(1)])),
        ).toThrow()
        expect(
            () =>
                new EncodedSignature({
                    alg: "ssh-ed25519",
                    data: Buffer.alloc(64),
                    securityKey: { flags: 1, counter: 1 },
                }),
        ).toThrow("requires a security-key algorithm")
    })

    test("copies inputs and revalidates mutable security-key data", () => {
        const parsed = PublicKey.parse(ecdsaKeyBlob)
        const parsedAlgorithm = parsed.data.algorithm as SSHECDSASecurityKeyPublicKey
        const point = Buffer.from(parsedAlgorithm.data.publicKey)
        const algorithm = new SSHECDSASecurityKeyPublicKey({
            publicKey: point,
            application: "ssh:test",
        })
        const serialized = algorithm.serialize()
        point.fill(0)
        expect(algorithm.serialize()).toEqual(serialized)

        algorithm.data.publicKey.fill(0)
        expect(() => algorithm.serialize()).toThrow("Invalid nistp256 public key")
        algorithm.data.publicKey.set(parsedAlgorithm.data.publicKey)
        algorithm.data.application = ""
        expect(() => algorithm.serialize()).toThrow("must not be empty")

        const data = Buffer.from([1, 2, 3])
        const clientData = Buffer.from("client data")
        const extensions = Buffer.from([4, 5])
        const signature = new EncodedSignature({
            alg: "webauthn-sk-ecdsa-sha2-nistp256@openssh.com",
            data,
            securityKey: {
                flags: 0x81,
                counter: 9,
                webAuthn: { origin: "https://example.test", clientData, extensions },
            },
        })
        const encoded = signature.serialize()
        data.fill(0)
        clientData.fill(0)
        extensions.fill(0)
        expect(signature.serialize()).toEqual(encoded)

        signature.data.securityKey!.flags = 0x100
        expect(() => signature.serialize()).toThrow()

        const fixedSignature = EncodedSignature.parse(ecdsaSignature)
        fixedSignature.data.securityKey!.flags = 0x101
        expect(PublicKey.parse(ecdsaKeyBlob).verifySignature(message, fixedSignature)).toBeFalse()
    })

    test.each([
        {
            name: "Ed25519",
            blob: ed25519KeyBlob,
            certificateAlgorithm: "sk-ssh-ed25519-cert-v01@openssh.com",
            keyClass: SSHED25519SecurityKeyPublicKey,
        },
        {
            name: "ECDSA",
            blob: ecdsaKeyBlob,
            certificateAlgorithm: "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
            keyClass: SSHECDSASecurityKeyPublicKey,
        },
    ])("parses a $name security-key certificate issued by ssh-keygen", async (fixture) => {
        const directory = await mkdtemp(join(tmpdir(), "modernssh-security-key-certificate-"))
        try {
            const ca = join(directory, "ca")
            const subject = join(directory, "subject.pub")
            await execFileAsync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", ca])
            await writeFile(subject, `${PublicKey.parse(fixture.blob).toString()}\n`)
            await execFileAsync("ssh-keygen", [
                "-q",
                "-s",
                ca,
                "-I",
                "security-key@example.test",
                "-n",
                "alice",
                "-V",
                "-1m:+1h",
                subject,
            ])

            const certificate = PublicKey.parseString(
                await readFile(join(directory, "subject-cert.pub"), "utf8"),
            )
            expect(certificate.data.alg).toBe(fixture.certificateAlgorithm)
            expect(certificate.data.algorithm).toBeInstanceOf(SSHCertificatePublicKey)
            const algorithm = certificate.data.algorithm as SSHCertificatePublicKey
            expect(algorithm.publicKey.data.algorithm).toBeInstanceOf(fixture.keyClass)
            expect(algorithm.verifyCertificateSignature()).toBeTrue()
            expect(certificate.signatureAlgorithmFor(certificate.data.alg)).toBe(
                algorithm.publicKey.data.alg,
            )
            if (fixture.name === "ECDSA") {
                expect(certificate.signatureAlgorithms).toEqual([
                    "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
                    "webauthn-sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
                ])
                expect(certificate.signatureAlgorithmFor(certificate.signatureAlgorithms[1])).toBe(
                    "webauthn-sk-ecdsa-sha2-nistp256@openssh.com",
                )
            }
        } finally {
            await rm(directory, { recursive: true, force: true })
        }
    })
})
