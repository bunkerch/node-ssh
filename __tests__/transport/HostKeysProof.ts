import PrivateKey from "../../src/utils/PrivateKey.js"
import PublicKey from "../../src/utils/PublicKey.js"
import { serializeBuffer } from "../../src/utils/Buffer.js"
import {
    createHostKeysProofMessage,
    parseHostKeysProofResponse,
} from "../../src/utils/HostKeysProof.js"

const fixedPublicKey = PublicKey.parse(
    Buffer.from(
        "0000000b7373682d6564323535313900000020" +
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "hex",
    ),
)

const fixedProofMessage = Buffer.from(
    "0000001d686f73746b6579732d70726f76652d3030406f70656e7373682e636f6d" +
        "00000003010203" +
        "000000330000000b7373682d6564323535313900000020" +
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "hex",
)

describe("authenticated host-key announcements", () => {
    test("builds the independently written proof preimage", () => {
        expect(createHostKeysProofMessage(Buffer.from([1, 2, 3]), fixedPublicKey)).toEqual(
            fixedProofMessage,
        )
    })

    test("accepts only cryptographically valid proof signatures", async () => {
        const privateKey = await PrivateKey.generate("ssh-ed25519")
        const publicKey = privateKey.data.publicKey
        const sessionId = Buffer.from("fixed-session-identifier", "ascii")
        const signature = privateKey.sign(createHostKeysProofMessage(sessionId, publicKey))
        const response = serializeBuffer(signature.serialize())

        expect(parseHostKeysProofResponse(sessionId, [publicKey], response)).toEqual([publicKey])

        const modified = Buffer.from(response)
        modified[modified.length - 1] ^= 1
        expect(parseHostKeysProofResponse(sessionId, [publicKey], modified)).toEqual([])
        expect(() =>
            parseHostKeysProofResponse(sessionId, [publicKey], Buffer.concat([response, response])),
        ).toThrow("extra signatures")
        expect(() =>
            parseHostKeysProofResponse(sessionId, [publicKey], response.subarray(0, -1)),
        ).toThrow()
    })
})
