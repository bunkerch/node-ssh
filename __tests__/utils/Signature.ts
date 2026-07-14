import EncodedSignature from "../../src/utils/Signature.js"

const fixedSignature = Buffer.from("0000000b7373682d6564323535313900000003010203", "hex")

describe("SSH signature envelopes", () => {
    test("parses and serializes a fixed RFC 4253 signature", () => {
        const signature = EncodedSignature.parse(fixedSignature)

        expect(signature.data).toEqual({ alg: "ssh-ed25519", data: Buffer.from([1, 2, 3]) })
        expect(signature.serialize()).toEqual(fixedSignature)
    })

    test.each([
        ["empty", Buffer.alloc(0)],
        ["non-ASCII", Buffer.from([0xff])],
        ["comma-containing", Buffer.from("ssh,ed25519")],
        ["overlong", Buffer.alloc(65, 0x61)],
    ])("rejects a signature algorithm that is %s", (_name, algorithm) => {
        const malformed = Buffer.concat([
            Buffer.from([0, 0, 0, algorithm.length]),
            algorithm,
            Buffer.from([0, 0, 0, 0]),
        ])

        expect(() => EncodedSignature.parse(malformed)).toThrow("SSH signature algorithm")
    })

    test("copies caller-owned envelope data", () => {
        const input = { alg: "ssh-ed25519", data: Buffer.from([1, 2, 3]) }
        const signature = new EncodedSignature(input)
        input.alg = "ssh-rsa"
        input.data.fill(0xff)

        expect(signature.serialize()).toEqual(fixedSignature)
    })

    test("revalidates mutable algorithm metadata at serialization", () => {
        const signature = EncodedSignature.parse(fixedSignature)
        signature.data.alg = "ssh,ed25519"

        expect(() => signature.serialize()).toThrow("SSH signature algorithm")
    })

    test("rejects trailing signature fields", () => {
        expect(() =>
            EncodedSignature.parse(Buffer.concat([fixedSignature, Buffer.from([0])])),
        ).toThrow()
    })
})
