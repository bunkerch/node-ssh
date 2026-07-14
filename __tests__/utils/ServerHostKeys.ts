import Server from "../../src/Server.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

describe("server host-key input normalization", () => {
    test("eagerly parses encoded and passphrase-protected private keys", async () => {
        const plain = await PrivateKey.generate("ssh-ed25519")
        const encrypted = await PrivateKey.generate("ecdsa-sha2-nistp256")
        const passphrase = Buffer.from("server-host-key-passphrase")
        const encodedPlain = plain.serialize()
        const encodedEncrypted = encrypted.serialize({ passphrase })
        const wrapped = { key: encodedEncrypted, passphrase }

        const server = new Server({ hostKeys: [encodedPlain, wrapped] })

        expect(server.options.hostKeys).toHaveLength(2)
        expect(server.options.hostKeys.every((key) => key instanceof PrivateKey)).toBe(true)
        expect(server.options.hostKeys[0].data.publicKey.equals(plain.data.publicKey)).toBe(true)
        expect(server.options.hostKeys[1].data.publicKey.equals(encrypted.data.publicKey)).toBe(
            true,
        )
        expect(server.options.hostKeys).not.toContain(encodedPlain)
        expect(server.options.hostKeys).not.toContain(encodedEncrypted)
        expect(server.options.hostKeys).not.toContain(wrapped)
    })

    test("rejects public keys, incorrect passphrases, and ambiguous object inputs", async () => {
        const key = await PrivateKey.generate("ssh-ed25519")
        const encrypted = key.serialize({ passphrase: "correct" })

        expect(() => new Server({ hostKeys: [key.data.publicKey.serialize()] })).toThrow(
            "must contain private keys",
        )
        expect(
            () => new Server({ hostKeys: [{ key: encrypted, passphrase: "incorrect" }] }),
        ).toThrow()
        expect(() => new Server({ hostKeys: [{ key, passphrase: "unnecessary" }] })).toThrow(
            "only valid for an encoded key",
        )
        expect(() => new Server({ hostKeys: [{} as never] })).toThrow()
    })
})
