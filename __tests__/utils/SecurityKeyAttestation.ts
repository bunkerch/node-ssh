import SecurityKeyAttestation from "../../src/SecurityKeyAttestation.js"

const version1 = Buffer.from(
    "000000117373682d736b2d6174746573742d76303100000004deadbeef0000000301020300000004a16178010102030400000002aabb",
    "hex",
)
const version0 = Buffer.from(
    "000000117373682d736b2d6174746573742d76303000000004cafebabe00000004112233440000000000000000",
    "hex",
)

describe("security-key attestation records", () => {
    test("parses and serializes the fixed v01 layout", () => {
        const input = Buffer.from(version1)
        const attestation = SecurityKeyAttestation.parse(input)
        input.fill(0)

        expect(attestation.format).toBe("ssh-sk-attest-v01")
        expect(attestation.certificate).toEqual(Buffer.from("deadbeef", "hex"))
        expect(attestation.enrollmentSignature).toEqual(Buffer.from("010203", "hex"))
        expect(attestation.authenticatorData).toEqual(Buffer.from("a1617801", "hex"))
        expect(attestation.flags).toBe(0x01020304)
        expect(attestation.reserved).toEqual(Buffer.from("aabb", "hex"))
        expect(attestation.serialize()).toEqual(version1)
    })

    test("parses the fixed historical v00 layout without inventing authenticator data", () => {
        const attestation = SecurityKeyAttestation.parse(version0)

        expect(attestation.format).toBe("ssh-sk-attest-v00")
        expect(attestation.certificate).toEqual(Buffer.from("cafebabe", "hex"))
        expect(attestation.enrollmentSignature).toEqual(Buffer.from("11223344", "hex"))
        expect(attestation.authenticatorData).toBeUndefined()
        expect(attestation.flags).toBe(0)
        expect(attestation.reserved).toEqual(Buffer.alloc(0))
        expect(attestation.serialize()).toEqual(version0)
    })

    test("returns defensive copies of every opaque field", () => {
        const attestation = SecurityKeyAttestation.parse(version1)
        attestation.certificate.fill(0)
        attestation.enrollmentSignature.fill(0)
        attestation.authenticatorData!.fill(0)
        attestation.reserved.fill(0)

        expect(attestation.serialize()).toEqual(version1)
    })

    test("rejects unknown, truncated, trailing, oversized, and non-buffer records", () => {
        const unknown = Buffer.from(version1)
        unknown[20] = 0x32
        expect(() => SecurityKeyAttestation.parse(unknown)).toThrow("format")
        expect(() => SecurityKeyAttestation.parse(version1.subarray(0, -1))).toThrow()
        expect(() =>
            SecurityKeyAttestation.parse(Buffer.concat([version0, Buffer.from([0])])),
        ).toThrow("trailing")
        expect(() => SecurityKeyAttestation.parse(Buffer.alloc(16 * 1024 * 1024 + 1))).toThrow(
            "maximum length",
        )
        expect(() => SecurityKeyAttestation.parse("not bytes" as never)).toThrow("buffer")
    })
})
