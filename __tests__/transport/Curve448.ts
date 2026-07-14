import Curve448SHA512 from "../../src/algorithms/kex/curve448-sha512.js"
import KexDHInit from "../../src/packets/KexDHInit.js"

function hex(value: string): Buffer {
    return Buffer.from(value.replaceAll(/\s/gu, ""), "hex")
}

const alicePrivate = hex(`
    9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28d
    d9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b
`)
const alicePublic = hex(`
    9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c
    22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0
`)
const bobPrivate = hex(`
    1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d
    6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d
`)
const bobPublic = hex(`
    3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b430
    27d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609
`)
const sharedSecret = hex(`
    07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282b
    b60c0b56fd2464c335543936521c24403085d59a449a5037514a879d
`)

class InspectableCurve448 extends Curve448SHA512 {
    get secret(): Buffer | undefined {
        return this.sharedSecret
    }
}

describe("RFC 8731 Curve448 key exchange", () => {
    test("matches both sides of the RFC 7748 Diffie-Hellman vector", () => {
        const alice = new Curve448SHA512(alicePrivate)
        alice.generateKeyPair()
        expect(alice.getPublicKey()).toEqual(alicePublic)
        expect(alice.computeSharedSecret(bobPublic)).toEqual(sharedSecret)

        const bob = new Curve448SHA512(bobPrivate)
        bob.generateKeyPair()
        expect(bob.getPublicKey()).toEqual(bobPublic)
        expect(bob.computeSharedSecret(alicePublic)).toEqual(sharedSecret)
    })

    test("copies configured and returned key-exchange state", () => {
        const configured = Buffer.from(alicePrivate)
        const algorithm = new InspectableCurve448(configured)
        configured.fill(0xff)
        algorithm.generateKeyPair()

        const publicKey = algorithm.getPublicKey()
        publicKey.fill(0xff)
        expect(algorithm.getPublicKey()).toEqual(alicePublic)

        const result = algorithm.computeSharedSecret(bobPublic)
        result.fill(0xff)
        expect(algorithm.secret).toEqual(sharedSecret)

        algorithm.generateKeyPair()
        expect(algorithm.secret).toBeUndefined()
    })

    test("accepts non-canonical coordinates and rejects invalid peers", () => {
        // RFC 7748 requires p + 5 to be reduced to Curve448's base coordinate 5.
        const nonCanonicalBasePoint = Buffer.from(
            "04000000000000000000000000000000000000000000000000000000" +
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "hex",
        )
        const nonCanonical = new Curve448SHA512(alicePrivate)
        nonCanonical.generateKeyPair()
        expect(nonCanonical.computeSharedSecret(nonCanonicalBasePoint)).toEqual(alicePublic)

        const shortPoint = new Curve448SHA512(alicePrivate)
        shortPoint.generateKeyPair()
        expect(() => shortPoint.computeSharedSecret(Buffer.alloc(55))).toThrow(
            "Curve448 public keys must be 56 bytes",
        )

        const lowOrderPoint = new Curve448SHA512(alicePrivate)
        lowOrderPoint.generateKeyPair()
        expect(() => lowOrderPoint.computeSharedSecret(Buffer.alloc(56))).toThrow(
            "Curve448 shared secret must not be all zero",
        )
        expect(() => lowOrderPoint.computeSharedSecret(bobPublic)).toThrow(
            "key pair has not been generated",
        )
    })

    test("uses an exact 56-byte SSH string for its ephemeral public value", () => {
        const frame = hex(`
            1e00000038
            9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c
            22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0
        `)
        expect(KexDHInit.parse(frame).data.e).toEqual(alicePublic)
        expect(new KexDHInit({ e: alicePublic, encoding: "string" }).serialize()).toEqual(frame)
    })
})
