import {
    combineSNTRUP761X25519Secrets,
    default as SNTRUP761X25519SHA512,
} from "../../src/algorithms/kex/sntrup761x25519-sha512.js"
import {
    decapsulateSNTRUP761,
    encapsulateSNTRUP761,
    generateSNTRUP761KeyPair,
    SNTRUP761_CIPHERTEXT_BYTES,
    SNTRUP761_PUBLIC_KEY_BYTES,
    SNTRUP761_SECRET_KEY_BYTES,
    SNTRUP761_SHARED_SECRET_BYTES,
} from "../../src/utils/SNTRUP761.js"

describe("RFC 9941 hybrid Streamlined NTRU Prime key exchange", () => {
    test("combines the published KEM and X25519 secrets into the exact SSH string", () => {
        const kemSharedSecret = Buffer.from(
            "2c0c5a36e67770b4d8ab389a92963acd1082383640be2d660802b817cfebb9be",
            "hex",
        )
        const x25519SharedSecret = Buffer.from(
            "9b737d41d6cfbb1256c58cad0a6ae2c9bf84a90a7291eb52e4c181c8d2447b56",
            "hex",
        )
        const expected = Buffer.from(
            "425458446f22756304ded75a1f23fef9b18b36ebe0e6e260c3001263b0183f42" +
                "4907e6d822b3b76c6c3837b5b41fb0d07635c757e65efbefcb5bc38a1a15a96d",
            "hex",
        )

        const sharedSecret = combineSNTRUP761X25519Secrets(kemSharedSecret, x25519SharedSecret)
        expect(sharedSecret).toEqual(expected)
        const encoded = Buffer.alloc(4 + sharedSecret.length)
        encoded.writeUInt32BE(sharedSecret.length)
        sharedSecret.copy(encoded, 4)
        expect(encoded).toEqual(
            Buffer.from(
                "00000040425458446f22756304ded75a1f23fef9b18b36ebe0e6e260c3001263" +
                    "b0183f424907e6d822b3b76c6c3837b5b41fb0d07635c757e65efbefcb5bc38a1a15a96d",
                "hex",
            ),
        )
    })

    test("encapsulates, decapsulates, and implicitly rejects modified ciphertext", () => {
        const keyPair = generateSNTRUP761KeyPair()
        const encapsulation = encapsulateSNTRUP761(keyPair.publicKey)
        expect(keyPair.publicKey).toHaveLength(SNTRUP761_PUBLIC_KEY_BYTES)
        expect(keyPair.secretKey).toHaveLength(SNTRUP761_SECRET_KEY_BYTES)
        expect(encapsulation.ciphertext).toHaveLength(SNTRUP761_CIPHERTEXT_BYTES)
        expect(encapsulation.sharedSecret).toHaveLength(SNTRUP761_SHARED_SECRET_BYTES)
        expect(decapsulateSNTRUP761(encapsulation.ciphertext, keyPair.secretKey)).toEqual(
            encapsulation.sharedSecret,
        )

        const modified = Buffer.from(encapsulation.ciphertext)
        modified[0] ^= 1
        const rejectedSecret = decapsulateSNTRUP761(modified, keyPair.secretKey)
        expect(rejectedSecret).not.toEqual(encapsulation.sharedSecret)
        expect(decapsulateSNTRUP761(modified, keyPair.secretKey)).toEqual(rejectedSecret)
    })

    test("enforces fixed KEM and role-specific hybrid public-key lengths", () => {
        expect(() => encapsulateSNTRUP761(Buffer.alloc(SNTRUP761_PUBLIC_KEY_BYTES - 1))).toThrow(
            "public keys must be 1158 bytes",
        )
        expect(() =>
            decapsulateSNTRUP761(
                Buffer.alloc(SNTRUP761_CIPHERTEXT_BYTES - 1),
                Buffer.alloc(SNTRUP761_SECRET_KEY_BYTES),
            ),
        ).toThrow("ciphertexts must be 1039 bytes")
        expect(() =>
            decapsulateSNTRUP761(
                Buffer.alloc(SNTRUP761_CIPHERTEXT_BYTES),
                Buffer.alloc(SNTRUP761_SECRET_KEY_BYTES - 1),
            ),
        ).toThrow("secret keys must be 1763 bytes")

        const client = new SNTRUP761X25519SHA512(Buffer.alloc(32, 7))
        client.generateKeyPair("client")
        const publicKey = client.getPublicKey()
        expect(publicKey).toHaveLength(1190)
        publicKey.fill(0)
        expect(client.getPublicKey()).not.toEqual(publicKey)
        expect(() => client.computeSharedSecret(Buffer.alloc(1070))).toThrow(
            "Hybrid server public keys must be 1071 bytes",
        )

        const server = new SNTRUP761X25519SHA512(Buffer.alloc(32, 9))
        server.generateKeyPair("server")
        expect(() => server.getPublicKey()).toThrow("Hybrid server public key is not available yet")
        expect(() => server.computeSharedSecret(Buffer.alloc(1071))).toThrow(
            "Hybrid client public keys must be 1190 bytes",
        )
    })
})
