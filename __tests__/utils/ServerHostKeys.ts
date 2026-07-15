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
        const plainSnapshot = Buffer.from(encodedPlain)
        const encryptedSnapshot = Buffer.from(encodedEncrypted)
        const passphraseSnapshot = Buffer.from(passphrase)

        const server = new Server({ hostKeys: [encodedPlain, wrapped] })

        expect("options" in server).toBe(false)
        expect(encodedPlain).toEqual(plainSnapshot)
        expect(encodedEncrypted).toEqual(encryptedSnapshot)
        expect(passphrase).toEqual(passphraseSnapshot)
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

    test("bounds advertised keys and rejects duplicate public identities", () => {
        const key = PrivateKey.generateSync("ssh-ed25519")
        expect(() => new Server({ hostKeys: [key, key] })).toThrow("duplicate keys")

        const hostKeys = Array.from({ length: 65 }, () => PrivateKey.generateSync("ssh-ed25519"))
        expect(() => new Server({ hostKeys })).toThrow("limited to 64 keys")
        expect(() => new Server({ hostKeys, sendAllHostKeys: false })).not.toThrow()
    })
})
