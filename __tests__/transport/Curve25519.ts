import Curve25519SHA256 from "../../src/algorithms/kex/curve25519-sha256.js"
import KexDHInit from "../../src/packets/KexDHInit.js"
import KexDHReply from "../../src/packets/KexDHReply.js"

const alicePrivate = Buffer.from(
    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
    "hex",
)
const alicePublic = Buffer.from(
    "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
    "hex",
)
const bobPrivate = Buffer.from(
    "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
    "hex",
)
const bobPublic = Buffer.from(
    "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
    "hex",
)
const sharedSecret = Buffer.from(
    "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
    "hex",
)

describe("RFC 8731 Curve25519 key exchange", () => {
    test("matches both sides of the RFC 7748 Diffie-Hellman vector", () => {
        const alice = new Curve25519SHA256(alicePrivate)
        alice.generateKeyPair()
        expect(alice.getPublicKey()).toEqual(alicePublic)
        expect(alice.computeSharedSecret(bobPublic)).toEqual(sharedSecret)

        const bob = new Curve25519SHA256(bobPrivate)
        bob.generateKeyPair()
        expect(bob.getPublicKey()).toEqual(bobPublic)
        expect(bob.computeSharedSecret(alicePublic)).toEqual(sharedSecret)
    })

    test("rejects incorrectly sized points and all-zero shared secrets", () => {
        const shortPoint = new Curve25519SHA256(alicePrivate)
        shortPoint.generateKeyPair()
        expect(() => shortPoint.computeSharedSecret(Buffer.alloc(31))).toThrow(
            "Curve25519 public keys must be 32 bytes",
        )

        const lowOrderPoint = new Curve25519SHA256(alicePrivate)
        lowOrderPoint.generateKeyPair()
        expect(() => lowOrderPoint.computeSharedSecret(Buffer.alloc(32))).toThrow(
            "Curve25519 shared secret must not be all zero",
        )
    })

    test("preserves raw high-bit Curve25519 points in ECDH messages 30 and 31", () => {
        const initVector = Buffer.from(
            "1e000000208520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
            "hex",
        )
        const replyVector = Buffer.from(
            "1f000000036b657900000020de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f00000003736967",
            "hex",
        )

        expect(KexDHInit.parse(initVector).data.e).toEqual(alicePublic)
        expect(new KexDHInit({ e: alicePublic, encoding: "string" }).serialize()).toEqual(
            initVector,
        )

        const reply = KexDHReply.parse(replyVector)
        expect(reply.data).toMatchObject({ K_S: Buffer.from("key"), f: bobPublic })
        expect(
            new KexDHReply({
                K_S: Buffer.from("key"),
                f: bobPublic,
                H_sig: Buffer.from("sig"),
                encoding: "string",
            }).serialize(),
        ).toEqual(replyVector)
    })

    test("key-exchange packets own constructor and parsed wire values", () => {
        const initPoint = Buffer.from(alicePublic)
        const init = new KexDHInit({ e: initPoint, encoding: "string" })
        initPoint.fill(0xff)
        expect(init.data.e).toEqual(alicePublic)

        const hostKey = Buffer.from("key")
        const replyPoint = Buffer.from(bobPublic)
        const signature = Buffer.from("sig")
        const reply = new KexDHReply({
            K_S: hostKey,
            f: replyPoint,
            H_sig: signature,
            encoding: "string",
        })
        hostKey.fill(0xff)
        replyPoint.fill(0xff)
        signature.fill(0xff)
        expect(reply.data).toMatchObject({
            K_S: Buffer.from("key"),
            f: bobPublic,
            H_sig: Buffer.from("sig"),
        })

        const initFrame = Buffer.from(
            "1e000000208520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
            "hex",
        )
        const replyFrame = Buffer.from(
            "1f000000036b657900000020de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f00000003736967",
            "hex",
        )
        const parsedInit = KexDHInit.parse(initFrame)
        const parsedReply = KexDHReply.parse(replyFrame)
        initFrame.fill(0xff)
        replyFrame.fill(0xff)

        expect(parsedInit.data.e).toEqual(alicePublic)
        expect(parsedReply.data).toMatchObject({
            K_S: Buffer.from("key"),
            f: bobPublic,
            H_sig: Buffer.from("sig"),
        })
    })
})
