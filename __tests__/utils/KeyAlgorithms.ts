import PrivateKey from "../../src/utils/PrivateKey.js"
import PublicKey from "../../src/utils/PublicKey.js"

const ed25519Key = Buffer.from(
    "0000000b7373682d6564323535313900000020" +
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "hex",
)

describe("SSH key algorithm envelopes", () => {
    test.each([
        ["empty", Buffer.alloc(0)],
        ["non-ASCII", Buffer.from([0xff])],
        ["comma-containing", Buffer.from("ssh,ed25519")],
        ["overlong", Buffer.alloc(65, 0x61)],
    ])("rejects a public key algorithm that is %s", (_name, algorithm) => {
        const malformed = Buffer.concat([
            Buffer.from([0, 0, 0, algorithm.length]),
            algorithm,
            ed25519Key.subarray(15),
        ])

        expect(() => PublicKey.parse(malformed)).toThrow("SSH public key algorithm")
    })

    test("rejects a constructed public envelope that disagrees with its key data", () => {
        const parsed = PublicKey.parse(ed25519Key)
        expect(() => new PublicKey({ ...parsed.data, alg: "ssh-rsa" })).toThrow("does not match")
    })

    test("copies public envelope metadata before retaining it", () => {
        const parsed = PublicKey.parse(ed25519Key)
        const input = { ...parsed.data }
        const key = new PublicKey(input)
        input.alg = "ssh-rsa"

        expect(key.serialize()).toEqual(ed25519Key)
    })

    test("rejects private envelopes that disagree with their key or public identity", async () => {
        const key = await PrivateKey.generate("ssh-ed25519")

        expect(() => new PrivateKey({ ...key.data, alg: "ssh-rsa" })).toThrow(
            "does not match public key",
        )
        const other = await PrivateKey.generate("ssh-ed25519")
        expect(() => new PrivateKey({ ...key.data, publicKey: other.data.publicKey })).toThrow(
            "Private and public key data do not match",
        )
    })

    test("strictly decodes the inner private-container algorithm", async () => {
        const key = await PrivateKey.generate("ssh-ed25519")
        const encoded = key.serialize()
        const name = Buffer.from("ssh-ed25519")
        const outer = encoded.indexOf(name)
        const inner = encoded.indexOf(name, outer + name.length)
        expect(outer).toBeGreaterThanOrEqual(0)
        expect(inner).toBeGreaterThan(outer)
        encoded[inner] = 0x2c

        expect(() => PrivateKey.parse(encoded)).toThrow("SSH private key algorithm")
    })

    test.each(["bad\ncomment", "bad\0comment", "\ud800"])(
        "rejects an invalid constructed key comment",
        async (comment) => {
            const privateKey = await PrivateKey.generate("ssh-ed25519")
            expect(() => new PublicKey({ ...privateKey.data.publicKey.data, comment })).toThrow(
                "SSH key comment",
            )
            expect(() => new PrivateKey({ ...privateKey.data, comment })).toThrow("SSH key comment")
        },
    )

    test("fatally decodes a private-container comment", async () => {
        const generated = await PrivateKey.generate("ssh-ed25519")
        const key = new PrivateKey({ ...generated.data, comment: "wire-comment" })
        const encoded = key.serialize()
        const offset = encoded.indexOf("wire-comment")
        expect(offset).toBeGreaterThanOrEqual(0)
        encoded[offset] = 0xff

        expect(() => PrivateKey.parse(encoded)).toThrow("SSH key comment is not valid UTF-8 text")
    })

    test("revalidates mutable comments at serialization", async () => {
        const privateKey = await PrivateKey.generate("ssh-ed25519")
        privateKey.data.publicKey.data.comment = "bad\ncomment"
        privateKey.data.comment = "bad\ncomment"

        expect(() => privateKey.data.publicKey.toString()).toThrow("SSH key comment")
        expect(() => privateKey.serialize()).toThrow("SSH key comment")
    })
})
