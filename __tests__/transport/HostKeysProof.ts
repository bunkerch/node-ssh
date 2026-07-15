import PrivateKey from "../../src/utils/PrivateKey.js"
import PublicKey from "../../src/utils/PublicKey.js"
import { serializeBuffer } from "../../src/utils/Buffer.js"
import {
    createHostKeysProofMessage,
    HOST_KEYS_PROOF_DOMAIN,
    LEGACY_HOST_KEYS_PROOF_REQUEST,
    parseHostKeysProofResponse,
} from "../../src/utils/HostKeysProof.js"

const fixedPublicKey = PublicKey.parse(
    Buffer.from(
        "0000000b7373682d6564323535313900000020" +
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "hex",
    ),
)

const fixedLegacyProofMessage = Buffer.from(
    "0000001d686f73746b6579732d70726f76652d3030406f70656e7373682e636f6d" +
        "00000003010203" +
        "000000330000000b7373682d6564323535313900000020" +
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "hex",
)

const fixedStandardProofMessage = Buffer.from(
    "00000010686f73746b6579732d70726f76652d30" +
        "00000003010203" +
        "000000330000000b7373682d6564323535313900000020" +
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "hex",
)

describe("authenticated host-key announcements", () => {
    test("builds independently written standard and legacy proof preimages", () => {
        expect(
            createHostKeysProofMessage(
                HOST_KEYS_PROOF_DOMAIN,
                Buffer.from([1, 2, 3]),
                fixedPublicKey,
            ),
        ).toEqual(fixedStandardProofMessage)
        expect(
            createHostKeysProofMessage(
                LEGACY_HOST_KEYS_PROOF_REQUEST,
                Buffer.from([1, 2, 3]),
                fixedPublicKey,
            ),
        ).toEqual(fixedLegacyProofMessage)
    })

    test("separates the standard request name from its versioned proof domain", () => {
        expect(HOST_KEYS_PROOF_DOMAIN).toBe("hostkeys-prove-0")
        expect(HOST_KEYS_PROOF_DOMAIN).not.toBe("hostkeys-prove")
    })

    test("accepts only cryptographically valid proof signatures", async () => {
        const privateKey = await PrivateKey.generate("ssh-ed25519")
        const publicKey = privateKey.data.publicKey
        const sessionId = Buffer.from("fixed-session-identifier", "ascii")
        const signature = privateKey.sign(
            createHostKeysProofMessage(HOST_KEYS_PROOF_DOMAIN, sessionId, publicKey),
        )
        const response = serializeBuffer(signature.serialize())

        expect(
            parseHostKeysProofResponse(sessionId, [publicKey], response, HOST_KEYS_PROOF_DOMAIN),
        ).toEqual([publicKey])

        const modified = Buffer.from(response)
        modified[modified.length - 1] ^= 1
        expect(
            parseHostKeysProofResponse(sessionId, [publicKey], modified, HOST_KEYS_PROOF_DOMAIN),
        ).toEqual([])
        expect(() =>
            parseHostKeysProofResponse(
                sessionId,
                [publicKey],
                Buffer.concat([response, response]),
                HOST_KEYS_PROOF_DOMAIN,
            ),
        ).toThrow("extra signatures")
        expect(() =>
            parseHostKeysProofResponse(
                sessionId,
                [publicKey],
                response.subarray(0, -1),
                HOST_KEYS_PROOF_DOMAIN,
            ),
        ).toThrow()
    })

    test("rejects RSA-SHA1 and enforces the initially negotiated RSA-SHA2 algorithm", async () => {
        const privateKey = await PrivateKey.generate("ssh-rsa")
        const publicKey = privateKey.data.publicKey
        const sessionId = Buffer.from("rsa-proof-session", "ascii")
        const message = createHostKeysProofMessage(HOST_KEYS_PROOF_DOMAIN, sessionId, publicKey)
        const response = (algorithm: "ssh-rsa" | "rsa-sha2-256" | "rsa-sha2-512") =>
            serializeBuffer(privateKey.sign(message, algorithm).serialize())

        expect(
            parseHostKeysProofResponse(
                sessionId,
                [publicKey],
                response("ssh-rsa"),
                HOST_KEYS_PROOF_DOMAIN,
            ),
        ).toEqual([])
        expect(
            parseHostKeysProofResponse(
                sessionId,
                [publicKey],
                response("rsa-sha2-512"),
                HOST_KEYS_PROOF_DOMAIN,
            ),
        ).toEqual([publicKey])
        expect(
            parseHostKeysProofResponse(
                sessionId,
                [publicKey],
                response("rsa-sha2-512"),
                HOST_KEYS_PROOF_DOMAIN,
                "rsa-sha2-256",
            ),
        ).toEqual([])
        expect(
            parseHostKeysProofResponse(
                sessionId,
                [publicKey],
                response("rsa-sha2-256"),
                HOST_KEYS_PROOF_DOMAIN,
                "rsa-sha2-256",
            ),
        ).toEqual([publicKey])
    })
})
