import { ECDH, createHash } from "node:crypto"

import {
    MLKEM1024NISTP384SHA384,
    MLKEM768NISTP256SHA256,
    MLKEM768X25519SHA256,
    combineMLKEMHybridSecrets,
} from "../../src/algorithms/kex/mlkem-hybrid.js"

// NIST ACVP Server FIPS 203 keyGen internalProjection cases 26 and 51 (d || z).
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

describe("registered ML-KEM hybrid key exchanges", () => {
    test("matches NIST ACVP ML-KEM public-key digests", () => {
        const cases = [
            {
                exchange: new MLKEM768X25519SHA256({
                    classicalPrivateKey: Buffer.alloc(32, 0x42),
                    mlkemSeed: mlkem768Seed,
                }),
                publicKeyBytes: 1184,
                digest: "4158f6afb5e516c99f1da07da8c651348422b17c1f4e9a08ad73fb1f91249b3e",
            },
            {
                exchange: new MLKEM1024NISTP384SHA384({
                    classicalPrivateKey: Buffer.alloc(48, 0x24),
                    mlkemSeed: mlkem1024Seed,
                }),
                publicKeyBytes: 1568,
                digest: "b78619e4fceeeb86dee3fedb945eca6da61dae312771ef8fa871951d391bd7b6",
            },
        ]

        for (const { exchange, publicKeyBytes, digest } of cases) {
            exchange.generateKeyPair("client")
            const publicKey = exchange.getPublicKey().subarray(0, publicKeyBytes)
            expect(createHash("sha256").update(publicKey).digest("hex")).toBe(digest)
        }
    })

    test("copies deterministic inputs and returned public values", () => {
        const classicalPrivateKey = Buffer.alloc(32, 0x42)
        const seed = Buffer.from(mlkem768Seed)
        const exchange = new MLKEM768X25519SHA256({
            classicalPrivateKey,
            mlkemSeed: seed,
        })
        classicalPrivateKey.fill(0)
        seed.fill(0)
        exchange.generateKeyPair("client")

        const publicKey = exchange.getPublicKey()
        expect(createHash("sha256").update(publicKey.subarray(0, 1184)).digest("hex")).toBe(
            "4158f6afb5e516c99f1da07da8c651348422b17c1f4e9a08ad73fb1f91249b3e",
        )
        publicKey.fill(0)
        expect(exchange.getPublicKey()).not.toEqual(publicKey)
    })

    test.each([
        ["sha256", 32, "cbd3aabe6d5a9125f0e086ced756cff43bcf46c307d73ec8c6bc5382c5640689"],
        [
            "sha384",
            48,
            "b4c86aabd04a182fc0f98980eaade488a6f8bf334baa108095378bcc4fe890c16172e8c8104adf3ae61eee60e4882ba1",
        ],
    ] as const)("combines fixed %s secrets in PQ-then-classical order", (hash, bytes, expected) => {
        const postQuantum = Buffer.from(Array.from({ length: 32 }, (_, index) => index))
        const classical = Buffer.from(Array.from({ length: bytes }, (_, index) => 255 - index))

        expect(combineMLKEMHybridSecrets(hash, postQuantum, classical)).toEqual(
            Buffer.from(expected, "hex"),
        )
    })

    test.each([
        ["mlkem768nistp256-sha256", MLKEM768NISTP256SHA256, 1249, 1153],
        ["mlkem1024nistp384-sha384", MLKEM1024NISTP384SHA384, 1665, 1665],
        ["mlkem768x25519-sha256", MLKEM768X25519SHA256, 1216, 1120],
    ])(
        "exchanges exact role-specific public values with %s",
        (_name, Exchange, clientBytes, serverBytes) => {
            const client = new Exchange()
            const server = new Exchange()
            client.generateKeyPair("client")
            server.generateKeyPair("server")

            const clientPublicKey = client.getPublicKey()
            expect(clientPublicKey).toHaveLength(clientBytes)
            server.computeSharedSecret(clientPublicKey)
            const serverPublicKey = server.getPublicKey()
            expect(serverPublicKey).toHaveLength(serverBytes)
            client.computeSharedSecret(serverPublicKey)
            expect(client.getSharedSecret()).toEqual(server.getSharedSecret())
        },
    )

    test.each([
        ["mlkem768nistp256-sha256", MLKEM768NISTP256SHA256, "prime256v1", 1184, 1088],
        ["mlkem1024nistp384-sha384", MLKEM1024NISTP384SHA384, "secp384r1", 1568, 1568],
    ])(
        "accepts compressed NIST public points with %s",
        (_name, Exchange, curve, publicKeyBytes, ciphertextBytes) => {
            const client = new Exchange()
            const server = new Exchange()
            client.generateKeyPair("client")
            server.generateKeyPair("server")

            const clientPublicKey = client.getPublicKey()
            const compressedClientPoint = ECDH.convertKey(
                clientPublicKey.subarray(publicKeyBytes),
                curve,
                undefined,
                undefined,
                "compressed",
            )
            server.computeSharedSecret(
                Buffer.concat([clientPublicKey.subarray(0, publicKeyBytes), compressedClientPoint]),
            )

            const serverPublicKey = server.getPublicKey()
            const compressedServerPoint = ECDH.convertKey(
                serverPublicKey.subarray(ciphertextBytes),
                curve,
                undefined,
                undefined,
                "compressed",
            )
            client.computeSharedSecret(
                Buffer.concat([
                    serverPublicKey.subarray(0, ciphertextBytes),
                    compressedServerPoint,
                ]),
            )
            expect(client.getSharedSecret()).toEqual(server.getSharedSecret())
        },
    )

    test("rejects malformed role-specific public values", () => {
        for (const Exchange of [
            MLKEM768NISTP256SHA256,
            MLKEM1024NISTP384SHA384,
            MLKEM768X25519SHA256,
        ]) {
            const client = new Exchange()
            const server = new Exchange()
            client.generateKeyPair("client")
            server.generateKeyPair("server")
            expect(() => server.computeSharedSecret(Buffer.alloc(31))).toThrow(
                "Hybrid client public keys",
            )
            expect(() => client.computeSharedSecret(Buffer.alloc(31))).toThrow(
                "Hybrid server public keys",
            )
        }
    })

    test("rejects invalid ML-KEM and classical public values", () => {
        const malformedMLKEMClient = new MLKEM768NISTP256SHA256({
            mlkemSeed: mlkem768Seed,
        })
        malformedMLKEMClient.generateKeyPair("client")
        const malformedMLKEMPublicKey = malformedMLKEMClient.getPublicKey()
        malformedMLKEMPublicKey[0] = 0xff
        malformedMLKEMPublicKey[1] = 0x0f
        const mlkemServer = new MLKEM768NISTP256SHA256()
        mlkemServer.generateKeyPair("server")
        expect(() => mlkemServer.computeSharedSecret(malformedMLKEMPublicKey)).toThrow(
            "Invalid ML-KEM encapsulation public key",
        )

        const p256Client = new MLKEM768NISTP256SHA256()
        const p256Server = new MLKEM768NISTP256SHA256()
        p256Client.generateKeyPair("client")
        p256Server.generateKeyPair("server")
        const invalidP256 = p256Client.getPublicKey()
        invalidP256.fill(0, 1184)
        expect(() => p256Server.computeSharedSecret(invalidP256)).toThrow(
            "Invalid hybrid prime256v1 ECDH public key",
        )

        const x25519Client = new MLKEM768X25519SHA256()
        x25519Client.generateKeyPair("client")
        const invalidX25519 = x25519Client.getPublicKey()
        invalidX25519.fill(0, 1184)
        const x25519Server = new MLKEM768X25519SHA256()
        x25519Server.generateKeyPair("server")
        expect(() => x25519Server.computeSharedSecret(invalidX25519)).toThrow(
            "must not be all zero",
        )
    })

    test("implicitly rejects a modified ML-KEM ciphertext", () => {
        const options = {
            classicalPrivateKey: Buffer.alloc(32, 0x42),
            mlkemSeed: mlkem768Seed,
        }
        const client = new MLKEM768X25519SHA256(options)
        const modifiedClient = new MLKEM768X25519SHA256(options)
        const server = new MLKEM768X25519SHA256({
            classicalPrivateKey: Buffer.alloc(32, 0x24),
            encapsulationSeed: Buffer.alloc(32, 0x17),
        })
        client.generateKeyPair("client")
        modifiedClient.generateKeyPair("client")
        server.generateKeyPair("server")
        const clientPublicKey = client.getPublicKey()
        expect(modifiedClient.getPublicKey()).toEqual(clientPublicKey)
        server.computeSharedSecret(clientPublicKey)

        const serverPublicKey = server.getPublicKey()
        client.computeSharedSecret(serverPublicKey)
        const modifiedServerPublicKey = Buffer.from(serverPublicKey)
        modifiedServerPublicKey[0] ^= 1
        modifiedClient.computeSharedSecret(modifiedServerPublicKey)

        expect(client.getSharedSecret()).toEqual(server.getSharedSecret())
        expect(modifiedClient.getSharedSecret()).not.toEqual(server.getSharedSecret())
    })
})
