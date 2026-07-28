import { serializeBuffer } from "../../src/utils/Buffer.js"
import type {
    SSHCertificateData,
    SSHCertificateOption,
    SSHCertificatePublicKey,
} from "../../src/utils/PublicKey.js"
import EncodedSignature from "../../src/utils/Signature.js"
import {
    evaluateUserCertificateAuthorization,
    mergeUserCertificateAuthorization,
    userCertificateCriticalOptionsPermitted,
    userCertificateSignaturePermitted,
} from "../../src/UserCertificateAuthorization.js"

function option(name: string, data = Buffer.alloc(0)): SSHCertificateOption {
    return { name, data }
}

function certificate(
    criticalOptions: readonly SSHCertificateOption[] = [],
    extensions: readonly SSHCertificateOption[] = [],
    publicKeyAlgorithm = "ssh-ed25519",
): Pick<SSHCertificatePublicKey, "data"> {
    return {
        data: {
            publicKey: { data: { alg: publicKeyAlgorithm } },
            criticalOptions,
            extensions,
        } as SSHCertificateData,
    } as Pick<SSHCertificatePublicKey, "data">
}

function nested(value: string): Buffer {
    return serializeBuffer(Buffer.from(value))
}

describe("user certificate authorization", () => {
    test("derives deny-by-default feature permissions and ignores unknown extensions", () => {
        const authorization = evaluateUserCertificateAuthorization(
            certificate(
                [],
                [
                    option("permit-agent-forwarding"),
                    option("permit-pty"),
                    option("future@example.test", Buffer.from([1, 2, 3])),
                ],
            ),
            "192.0.2.10",
        )

        expect(authorization).toMatchObject({
            agentForwarding: true,
            portForwarding: false,
            pty: true,
            x11: false,
            requireUserPresence: false,
            requireUserVerification: false,
        })
        expect(
            evaluateUserCertificateAuthorization(
                certificate([], [option("permit-pty", Buffer.from([0]))]),
                "192.0.2.10",
            ),
        ).toBeUndefined()
    })

    test("parses force-command and validates source-address CIDRs and wildcards", () => {
        const constrained = certificate([
            option("force-command", nested("internal-sftp")),
            option("source-address", nested("192.0.2.0/24,198.51.100.*")),
        ])

        expect(evaluateUserCertificateAuthorization(constrained, "192.0.2.42")?.forceCommand).toBe(
            "internal-sftp",
        )
        expect(evaluateUserCertificateAuthorization(constrained, "198.51.100.9")).toBeDefined()
        expect(evaluateUserCertificateAuthorization(constrained, "203.0.113.1")).toBeUndefined()
        expect(
            evaluateUserCertificateAuthorization(
                certificate([option("source-address", nested("2001:db8::/32"))]),
                "2001:db8::1234",
            ),
        ).toBeDefined()
        expect(
            evaluateUserCertificateAuthorization(
                certificate([option("source-address", nested("192.0.2.0/99"))]),
                "192.0.2.1",
            ),
        ).toBeUndefined()
    })

    test("rejects unsupported or malformed critical options", () => {
        const vendor = evaluateUserCertificateAuthorization(
            certificate([option("future-critical@example.test")]),
            "192.0.2.1",
        )!
        expect(vendor.unhandledCriticalOptions).toEqual(["future-critical@example.test"])
        expect(userCertificateCriticalOptionsPermitted(vendor, undefined)).toBe(false)
        expect(
            userCertificateCriticalOptionsPermitted(vendor, ["future-critical@example.test"]),
        ).toBe(true)
        expect(
            evaluateUserCertificateAuthorization(
                certificate([option("force-command", Buffer.from([0, 0, 0, 2, 0xff, 0xff]))]),
                "192.0.2.1",
            ),
        ).toBeUndefined()
        expect(
            evaluateUserCertificateAuthorization(
                certificate([option("verify-required")]),
                "192.0.2.1",
            ),
        ).toBeUndefined()
    })

    test("enforces security-key presence and verification assertions", () => {
        const presence = evaluateUserCertificateAuthorization(
            certificate([], [], "sk-ssh-ed25519@openssh.com"),
            "192.0.2.1",
        )!
        const noTouch = evaluateUserCertificateAuthorization(
            certificate([], [option("no-touch-required")], "sk-ssh-ed25519@openssh.com"),
            "192.0.2.1",
        )!
        const verified = evaluateUserCertificateAuthorization(
            certificate([option("verify-required")], [], "sk-ssh-ed25519@openssh.com"),
            "192.0.2.1",
        )!
        const signature = (flags: number) =>
            new EncodedSignature({
                alg: "sk-ssh-ed25519@openssh.com",
                data: Buffer.alloc(64),
                securityKey: { flags, counter: 1 },
            })

        expect(userCertificateSignaturePermitted(presence, signature(0))).toBe(false)
        expect(userCertificateSignaturePermitted(presence, signature(0x01))).toBe(true)
        expect(userCertificateSignaturePermitted(noTouch, signature(0))).toBe(true)
        expect(userCertificateSignaturePermitted(verified, signature(0x01))).toBe(false)
        expect(userCertificateSignaturePermitted(verified, signature(0x05))).toBe(true)
    })

    test("intersects permissions and rejects conflicting forced commands", () => {
        const first = evaluateUserCertificateAuthorization(
            certificate(
                [option("force-command", nested("backup"))],
                [option("permit-pty"), option("permit-port-forwarding")],
            ),
            "192.0.2.1",
        )!
        const second = evaluateUserCertificateAuthorization(
            certificate(
                [option("force-command", nested("backup"))],
                [option("permit-port-forwarding")],
            ),
            "192.0.2.1",
        )!
        expect(mergeUserCertificateAuthorization(first, second)).toMatchObject({
            pty: false,
            portForwarding: true,
            forceCommand: "backup",
        })

        const conflicting = evaluateUserCertificateAuthorization(
            certificate([option("force-command", nested("shell"))]),
            "192.0.2.1",
        )!
        expect(mergeUserCertificateAuthorization(first, conflicting)).toBeUndefined()
    })
})
