import { createHash } from "node:crypto"

import { MLKEM1024SHA384, MLKEM512SHA256, MLKEM768SHA256 } from "../../src/algorithms/kex/mlkem.js"

// NIST ACVP Server FIPS 203 keyGen internalProjection case 1 (d || z).
const mlkem512Seed = Buffer.from(
    "47b893474672ba92e4b12ee44fb32953af8e8503b5fb471d1614fb8a021a660a" +
        "1f8cb39e9e30bc458a0dc5408884b1187fb217018df760fa57317703b844a0a9",
    "hex",
)
const mlkem768Seed = Buffer.from(
    "e582b7d75e6c80b05ae392a1fc9f7153b12390fd99930368cc67a768baebc8a0" +
        "1cdacb8740c0b87c4a379575f187b367cbfa3b300bf591b109f79816e9cbe8f0",
    "hex",
)
const mlkem1024Seed = Buffer.from(
    "f3a706faf090c03db506863ab0b20bd8a1627956318e88c67eb875e8e7266009" +
        "35d2bc43dd1cc879f765bf2a0c5e297889dde910e57e2bb0eae417b90ab7a275",
    "hex",
)

function withDeterministicEntropy<T extends new () => InstanceType<T>>(
    Exchange: T,
    ...entropy: Buffer[]
): InstanceType<T> {
    return new (class extends Exchange {
        readonly #entropy = entropy.map((value) => Buffer.from(value))

        protected generateRandomBytes(length: number): Buffer {
            const value = this.#entropy.shift()
            if (value === undefined || value.length !== length) {
                throw new Error(`Expected ${length} bytes of deterministic entropy`)
            }
            return value
        }
    })()
}

describe("registered standalone ML-KEM key exchanges", () => {
    test("matches the NIST ML-KEM-512 encapsulation-key vector", () => {
        const exchange = withDeterministicEntropy(MLKEM512SHA256, mlkem512Seed)
        exchange.generateKeyPair("client")

        const publicKey = exchange.getPublicKey()
        expect(publicKey).toHaveLength(800)
        expect(createHash("sha256").update(publicKey).digest("hex")).toBe(
            "7e4a2b716a684c1ad33c43c808782da9e1a72f14ccda82723f712d49f53a9f28",
        )
    })

    test("matches the NIST ML-KEM-768 encapsulation-key vector", () => {
        const exchange = withDeterministicEntropy(MLKEM768SHA256, mlkem768Seed)
        exchange.generateKeyPair("client")

        const publicKey = exchange.getPublicKey()
        expect(publicKey).toHaveLength(1184)
        expect(createHash("sha256").update(publicKey).digest("hex")).toBe(
            "4158f6afb5e516c99f1da07da8c651348422b17c1f4e9a08ad73fb1f91249b3e",
        )
    })

    test("matches the NIST ML-KEM-1024 encapsulation-key vector", () => {
        const exchange = withDeterministicEntropy(MLKEM1024SHA384, mlkem1024Seed)
        exchange.generateKeyPair("client")

        const publicKey = exchange.getPublicKey()
        expect(publicKey).toHaveLength(1568)
        expect(createHash("sha256").update(publicKey).digest("hex")).toBe(
            "b78619e4fceeeb86dee3fedb945eca6da61dae312771ef8fa871951d391bd7b6",
        )
    })

    test.each([
        ["mlkem512-sha256", MLKEM512SHA256, 800, 768],
        ["mlkem768-sha256", MLKEM768SHA256, 1184, 1088],
        ["mlkem1024-sha384", MLKEM1024SHA384, 1568, 1568],
    ])(
        "exchanges exact role-specific values with %s",
        (_name, Exchange, publicKeyBytes, ciphertextBytes) => {
            const client = new Exchange()
            const server = new Exchange()
            client.generateKeyPair("client")
            server.generateKeyPair("server")

            const clientPublicKey = client.getPublicKey()
            expect(clientPublicKey).toHaveLength(publicKeyBytes)
            server.computeSharedSecret(clientPublicKey)
            const serverCiphertext = server.getPublicKey()
            expect(serverCiphertext).toHaveLength(ciphertextBytes)
            client.computeSharedSecret(serverCiphertext)
            expect(client.getSharedSecret()).toEqual(server.getSharedSecret())
            expect(client.getSharedSecret()).toHaveLength(32)
        },
    )

    test("hashes the ML-KEM shared secret as an SSH string", () => {
        const clientPublicKex = Buffer.from("140102", "hex")
        const serverPublicKex = Buffer.from("140304", "hex")
        const hostKey = Buffer.from("host-key")
        const client = withDeterministicEntropy(MLKEM512SHA256, mlkem512Seed)
        const server = withDeterministicEntropy(MLKEM512SHA256, Buffer.alloc(32, 0xa5))
        client.generateKeyPair("client")
        server.generateKeyPair("server")
        const clientPublicKey = client.getPublicKey()
        server.computeSharedSecret(clientPublicKey)
        const serverCiphertext = server.getPublicKey()
        client.computeSharedSecret(serverCiphertext)
        const sharedSecret = client.getSharedSecret()
        expect(sharedSecret[0] & 0x80).not.toBe(0)

        const actual = client.computeExchangeHash({
            clientVersion: "SSH-2.0-client",
            serverVersion: "SSH-2.0-server",
            clientKexInit: clientPublicKex,
            serverKexInit: serverPublicKex,
            serverHostKey: hostKey,
            clientExchangeValue: clientPublicKey,
            serverExchangeValue: serverCiphertext,
        })

        const encodedFields = [
            Buffer.from("SSH-2.0-client"),
            Buffer.from("SSH-2.0-server"),
            clientPublicKex,
            serverPublicKex,
            hostKey,
            clientPublicKey,
            serverCiphertext,
            sharedSecret,
        ].map((field) => {
            const length = Buffer.alloc(4)
            length.writeUInt32BE(field.length)
            return Buffer.concat([length, field])
        })
        const expected = createHash("sha256").update(Buffer.concat(encodedFields)).digest()
        expect(actual).toEqual(expected)
    })

    test("derives transport keys from the ML-KEM secret as an mpint", () => {
        const client = withDeterministicEntropy(MLKEM512SHA256, mlkem512Seed)
        const server = withDeterministicEntropy(MLKEM512SHA256, Buffer.alloc(32, 0xa5))
        client.generateKeyPair("client")
        server.generateKeyPair("server")
        server.computeSharedSecret(client.getPublicKey())
        client.computeSharedSecret(server.getPublicKey())

        const sharedSecret = client.getSharedSecret()
        expect(sharedSecret[0] & 0x80).not.toBe(0)
        const exchangeHash = Buffer.alloc(32, 0x3c)
        const sessionId = Buffer.alloc(32, 0x5a)
        const keys = client.deriveTransportKeys(exchangeHash, sessionId, {
            clientIV: 16,
            serverIV: 16,
            clientEncryption: 16,
            serverEncryption: 16,
            clientIntegrity: 32,
            serverIntegrity: 32,
        })

        const positiveMpint = Buffer.concat([Buffer.from([0]), sharedSecret])
        const length = Buffer.alloc(4)
        length.writeUInt32BE(positiveMpint.length)
        const encodedSecret = Buffer.concat([length, positiveMpint])
        const expected = Array.from({ length: 6 }, (_, index) =>
            createHash("sha256")
                .update(encodedSecret)
                .update(exchangeHash)
                .update(Buffer.from([0x41 + index]))
                .update(sessionId)
                .digest(),
        )
        expect(keys.clientIV).toEqual(expected[0]!.subarray(0, 16))
        expect(keys.serverIV).toEqual(expected[1]!.subarray(0, 16))
        expect(keys.clientEncryption).toEqual(expected[2]!.subarray(0, 16))
        expect(keys.serverEncryption).toEqual(expected[3]!.subarray(0, 16))
        expect(keys.clientIntegrity).toEqual(expected[4])
        expect(keys.serverIntegrity).toEqual(expected[5])
    })

    test("rejects malformed role values and invalid encapsulation keys", () => {
        const client = new MLKEM512SHA256({ mlkemSeed: mlkem512Seed })
        const server = new MLKEM512SHA256()
        client.generateKeyPair("client")
        server.generateKeyPair("server")
        expect(() => server.computeSharedSecret(Buffer.alloc(799))).toThrow(
            "client public keys must be 800 bytes",
        )
        expect(() => client.computeSharedSecret(Buffer.alloc(767))).toThrow(
            "server ciphertexts must be 768 bytes",
        )

        const malformed = client.getPublicKey()
        malformed[0] = 0xff
        malformed[1] = 0x0f
        expect(() => server.computeSharedSecret(malformed)).toThrow(
            "Invalid ML-KEM encapsulation public key",
        )
    })

    test("implicitly rejects a modified ciphertext", () => {
        const client = withDeterministicEntropy(MLKEM512SHA256, mlkem512Seed)
        const modifiedClient = withDeterministicEntropy(MLKEM512SHA256, mlkem512Seed)
        const server = withDeterministicEntropy(MLKEM512SHA256, Buffer.alloc(32, 0x17))
        client.generateKeyPair("client")
        modifiedClient.generateKeyPair("client")
        server.generateKeyPair("server")
        const clientPublicKey = client.getPublicKey()
        expect(modifiedClient.getPublicKey()).toEqual(clientPublicKey)
        server.computeSharedSecret(clientPublicKey)

        const serverCiphertext = server.getPublicKey()
        client.computeSharedSecret(serverCiphertext)
        const modifiedCiphertext = Buffer.from(serverCiphertext)
        modifiedCiphertext[0] ^= 1
        modifiedClient.computeSharedSecret(modifiedCiphertext)

        expect(client.getSharedSecret()).toEqual(server.getSharedSecret())
        expect(modifiedClient.getSharedSecret()).not.toEqual(server.getSharedSecret())
    })

    test("returns defensive copies of protocol values", () => {
        const client = withDeterministicEntropy(MLKEM512SHA256, mlkem512Seed)
        client.generateKeyPair("client")

        const firstPublicKey = client.getPublicKey()
        expect(createHash("sha256").update(firstPublicKey).digest("hex")).toBe(
            "7e4a2b716a684c1ad33c43c808782da9e1a72f14ccda82723f712d49f53a9f28",
        )
        firstPublicKey.fill(0)
        expect(client.getPublicKey()).not.toEqual(firstPublicKey)

        const server = withDeterministicEntropy(MLKEM512SHA256, Buffer.alloc(32, 0x42))
        server.generateKeyPair("server")
        server.computeSharedSecret(client.getPublicKey())
        const firstCiphertext = server.getPublicKey()
        firstCiphertext.fill(0)
        expect(server.getPublicKey()).not.toEqual(firstCiphertext)
    })

    test("validates role ordering", () => {
        const exchange = new MLKEM512SHA256()
        expect(() => exchange.generateKeyPair()).toThrow("explicit client or server role")
        expect(() => exchange.getPublicKey()).toThrow("server reply is not available yet")
        expect(() => exchange.computeSharedSecret(Buffer.alloc(800))).toThrow("role is unavailable")
    })
})
