import Client from "../../src/Client.js"
import NoneAgent from "../../src/publickey/NoneAgent.js"
import PrivateKeyAgent, { PrivateKeyAgentError } from "../../src/publickey/PrivateKeyAgent.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

describe("in-memory private-key agent", () => {
    test("lists and signs with each private key", async () => {
        const ed25519 = await PrivateKey.generate("ssh-ed25519")
        const rsa = await PrivateKey.generate("ssh-rsa")
        const source = [ed25519, rsa]
        const agent = new PrivateKeyAgent(source)
        source.length = 0

        const keys = await agent.getPublicKeys()
        expect(keys.map(([id]) => id)).toEqual(["0", "1"])
        expect(keys[0][1].equals(ed25519.data.publicKey)).toBe(true)
        expect(keys[1][1].equals(rsa.data.publicKey)).toBe(true)
        const message = Buffer.from("in-memory agent signing")
        const edSignature = await agent.sign("0", message)
        const rsaSignature = await agent.sign("1", message, "rsa-sha2-512")
        expect(ed25519.data.publicKey.verifySignature(message, edSignature)).toBe(true)
        expect(rsa.data.publicKey.verifySignature(message, rsaSignature)).toBe(true)
        expect((await agent.getPublicKey("1")).equals(rsa.data.publicKey)).toBe(true)
    })

    test("rejects empty key sets and unknown identifiers", async () => {
        expect(() => new PrivateKeyAgent([])).toThrow(PrivateKeyAgentError)
        const agent = new PrivateKeyAgent(await PrivateKey.generate("ssh-ed25519"))
        await expect(agent.getPublicKey("-1")).rejects.toThrow("Unknown private key identifier")
        await expect(agent.getPublicKey("01")).rejects.toThrow("Unknown private key identifier")
        await expect(agent.getPublicKey("1")).rejects.toThrow("Unknown private key identifier")
    })
})

describe("client private-key option", () => {
    test("loads encrypted text without retaining encoded secrets in client options", async () => {
        const privateKey = await PrivateKey.generate("ssh-ed25519")
        const encoded = privateKey.toString({ passphrase: "key-secret", rounds: 1 })
        const configured = { privateKey: encoded, passphrase: "key-secret" }
        const client = new Client(configured)

        expect(client.options.agent).toBeInstanceOf(PrivateKeyAgent)
        expect(client.options.privateKey).toBeUndefined()
        expect(client.options.passphrase).toBeUndefined()
        expect(configured).toEqual({ privateKey: encoded, passphrase: "key-secret" })
        const [[id, publicKey]] = await client.options.agent.getPublicKeys()
        expect(publicKey.equals(privateKey.data.publicKey)).toBe(true)
        const message = Buffer.from("client private key")
        expect(
            publicKey.verifySignature(message, await client.options.agent.sign(id, message)),
        ).toBe(true)
    })

    test("accepts objects and raw containers and rejects ambiguous options", async () => {
        const privateKey = await PrivateKey.generate("ssh-ed25519")
        expect(new Client({ privateKey }).options.agent).toBeInstanceOf(PrivateKeyAgent)
        expect(new Client({ privateKey: privateKey.serialize() }).options.agent).toBeInstanceOf(
            PrivateKeyAgent,
        )
        expect(
            () =>
                new Client({
                    privateKey,
                    agent: new NoneAgent(),
                }),
        ).toThrow("mutually exclusive")
        expect(() => new Client({ passphrase: "unused" })).toThrow("requires privateKey")
        expect(() => new Client({ privateKey, passphrase: "unused" })).toThrow(
            "only valid for an encoded privateKey",
        )
        expect(() => new Client({ privateKey: privateKey.data.publicKey.toString() })).toThrow(
            "must contain a private key",
        )
        expect(
            () =>
                new Client({
                    privateKey: privateKey.toString({ passphrase: "right", rounds: 1 }),
                    passphrase: "wrong",
                }),
        ).toThrow()
    })
})
