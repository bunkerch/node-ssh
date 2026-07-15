import { AddressInfo } from "node:net"
import { once } from "node:events"
import { generateKeyPairSync } from "node:crypto"
import RSA2048SHA256, {
    computeRSAKeyExchangeHash,
    consumeRSAKeyExchangePlaintext,
} from "../../src/algorithms/kex/rsa2048-sha256.js"
import { default_algorithm_names, kex_algorithms } from "../../src/algorithms.js"
import Client from "../../src/Client.js"
import { SSHAuthenticationMethods } from "../../src/constants.js"
import KexRSADone from "../../src/packets/KexRSADone.js"
import KexRSAPublicKey from "../../src/packets/KexRSAPublicKey.js"
import KexRSASecret from "../../src/packets/KexRSASecret.js"
import Server from "../../src/Server.js"
import type ServerClient from "../../src/ServerClient.js"
import PrivateKey from "../../src/utils/PrivateKey.js"
import PublicKey from "../../src/utils/PublicKey.js"

describe("RFC 4432 RSA SHA-256 key exchange", () => {
    test("is supported explicitly but excluded from modern defaults", () => {
        expect(kex_algorithms.has("rsa2048-sha256")).toBe(true)
        expect(default_algorithm_names.kex).not.toContain("rsa2048-sha256")
    })

    test("parses and serializes literal message frames", () => {
        const publicKeyFrame = Buffer.from("1e00000004686f7374000000097472616e7369656e74", "hex")
        const secretFrame = Buffer.from("1f00000004deadbeef", "hex")
        const doneFrame = Buffer.from("2000000003736967", "hex")

        expect(KexRSAPublicKey.parse(publicKeyFrame).data).toEqual({
            hostKey: Buffer.from("host"),
            transientKey: Buffer.from("transient"),
        })
        expect(KexRSAPublicKey.parse(publicKeyFrame).serialize()).toEqual(publicKeyFrame)
        expect(KexRSASecret.parse(secretFrame).data.encryptedSecret).toEqual(
            Buffer.from("deadbeef", "hex"),
        )
        expect(KexRSASecret.parse(secretFrame).serialize()).toEqual(secretFrame)
        expect(KexRSADone.parse(doneFrame).data.signature).toEqual(Buffer.from("sig"))
        expect(KexRSADone.parse(doneFrame).serialize()).toEqual(doneFrame)

        expect(() =>
            KexRSAPublicKey.parse(Buffer.concat([publicKeyFrame, Buffer.alloc(1)])),
        ).toThrow()
        expect(() => KexRSASecret.parse(secretFrame.subarray(0, -1))).toThrow()
        expect(() => KexRSADone.parse(Buffer.concat([doneFrame, Buffer.alloc(1)]))).toThrow()
    })

    test("rejects a transient RSA key below the RFC minimum", () => {
        const { publicKey } = generateKeyPairSync("rsa", { modulusLength: 1024 })
        const transient = PublicKey.fromPEM(
            publicKey.export({ format: "pem", type: "spki" }),
        ).serialize()
        expect(() => new RSA2048SHA256().setServerKeys(Buffer.from("host"), transient)).toThrow(
            "transient RSA modulus is too small",
        )
    })

    test("rejects invalid OAEP ciphertext and discards the transient private key", async () => {
        const exchange = new RSA2048SHA256()
        await exchange.generateTransientKey()
        expect(() => exchange.decryptSecret(Buffer.alloc(256))).toThrow(
            "Unable to decrypt RFC 4432 shared secret",
        )
        expect(() => exchange.decryptSecret(Buffer.alloc(256))).toThrow(
            "Transient RSA private key is unavailable",
        )
    })

    test("matches an independently encoded exchange-hash vector", () => {
        expect(
            computeRSAKeyExchangeHash({
                clientVersion: "SSH-2.0-client",
                serverVersion: "SSH-2.0-server",
                clientKexInit: Buffer.from("140102", "hex"),
                serverKexInit: Buffer.from("140304", "hex"),
                hostKey: Buffer.from("host-key"),
                transientKey: Buffer.from("transient-key"),
                encryptedSecret: Buffer.from("deadbeef", "hex"),
                sharedSecret: Buffer.from("0080", "hex"),
            }).toString("hex"),
        ).toBe("311e408c1c999ce1b887df606cb0ec21316e71a4d620cea9f2b9e20a9f474b47")
    })

    test("consumes and erases decrypted shared-secret plaintexts", () => {
        const plaintext = Buffer.from("000000020080", "hex")
        const secret = consumeRSAKeyExchangePlaintext(plaintext, 8)

        expect(secret).toEqual(Buffer.from("0080", "hex"))
        expect(plaintext).toEqual(Buffer.alloc(plaintext.length))

        const malformed = Buffer.from("000000010100", "hex")
        expect(() => consumeRSAKeyExchangePlaintext(malformed, 8)).toThrow(
            "Invalid RFC 4432 shared-secret mpint",
        )
        expect(malformed).toEqual(Buffer.alloc(malformed.length))

        const oversized = Buffer.from("000000020100", "hex")
        expect(() => consumeRSAKeyExchangePlaintext(oversized, 8)).toThrow(
            "outside the permitted range",
        )
        expect(oversized).toEqual(Buffer.alloc(oversized.length))
    })

    test("exchanges fresh encrypted secrets across rekey in both directions", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({
            hostKeys: [hostKey],
            sendAllHostKeys: false,
            algorithms: { kex: ["rsa2048-sha256"] },
        })
        server.hooker.hook("noneAuthentication", (_hook, _context, decision) => {
            decision.allowLogin = true
        })
        let connection: ServerClient | undefined
        server.on("connection", (peer) => {
            connection = peer
        })
        server.listen({ host: "127.0.0.1", port: 0 })
        await new Promise<void>((resolve) => server.server!.once("listening", resolve))
        const client = new Client({
            hostname: "127.0.0.1",
            port: (server.server!.address() as AddressInfo).port,
            algorithms: { kex: ["rsa2048-sha256"] },
            authenticationMethodsOrder: [SSHAuthenticationMethods.None],
        })
        client.hooker.hook("hostKey", (_hook, decision, key) => {
            decision.allowHostKey = key.equals(hostKey.data.publicKey)
        })
        const clientHandshakes: string[] = []
        client.on("handshake", ({ kex }) => clientHandshakes.push(kex))
        try {
            await client.connect()
            expect(client.keyExchangeAlgorithm).toBe("rsa2048-sha256")
            await client.rekey()
            const clientRekey = once(client, "rekey")
            await connection!.rekey()
            await clientRekey
            expect(clientHandshakes).toEqual(["rsa2048-sha256", "rsa2048-sha256", "rsa2048-sha256"])
            expect(client.isConnected).toBe(true)
        } finally {
            client.destroy()
            for (const peer of server.clients) peer.terminate()
            await new Promise<void>((resolve, reject) => {
                server.server!.close((error) => (error ? reject(error) : resolve()))
            })
        }
    }, 20_000)
})
