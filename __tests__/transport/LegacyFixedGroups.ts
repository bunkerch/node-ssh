import { createDiffieHellmanGroup, createHash } from "node:crypto"

import DiffieHellmanGroup1SHA1 from "../../src/algorithms/kex/diffie-hellman-group1-sha1.js"
import DiffieHellmanGroup14SHA1 from "../../src/algorithms/kex/diffie-hellman-group14-sha1.js"
import type DiffieHellmanGroupN from "../../src/algorithms/kex/diffie-hellman-groupN.js"
import { decodeBigIntBE, encodeBigIntBE } from "../../src/utils/BigInt.js"
import { serializeMpintBufferToBuffer } from "../../src/utils/mpint.js"

const vectors = [
    {
        name: "diffie-hellman-group1-sha1",
        group: "modp2",
        bits: 1_024,
        primeSHA256: "3f35a3f5f6c4376a744acad409bb22f8d897f949d2311d885adaa890981b67a0",
        prime: Buffer.from(
            "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd1" +
                "29024e088a67cc74020bbea63b139b22514a08798e3404dd" +
                "ef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245" +
                "e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed" +
                "ee386bfb5a899fa5ae9f24117c4b1fe649286651ece65381" +
                "ffffffffffffffff",
            "hex",
        ),
        create: (privateKey?: Buffer) => new DiffieHellmanGroup1SHA1(privateKey),
    },
    {
        name: "diffie-hellman-group14-sha1",
        group: "modp14",
        bits: 2_048,
        primeSHA256: "d66436f79bbd6b2e38c0ffbd079be904d2641415e2e67140e09448be9a60890e",
        prime: createDiffieHellmanGroup("modp14").getPrime(),
        create: (privateKey?: Buffer) => new DiffieHellmanGroup14SHA1(privateKey),
    },
] as const

describe("RFC 4253 legacy fixed-group key exchange", () => {
    test.each(vectors)("uses the published group for $name", (vector) => {
        expect(vector.prime.length * 8).toBe(vector.bits)
        expect(createHash("sha256").update(vector.prime).digest("hex")).toBe(vector.primeSHA256)
        expect(vector.create().groupName).toBe(vector.group)
    })

    test.each(vectors)("matches a fixed SHA-1 exchange for $name", (vector) => {
        const privateKey = Buffer.from([2])
        const algorithm = vector.create(privateKey)
        privateKey.fill(0xff)
        algorithm.generateKeyPair()

        expect(algorithm.getPublicKey()).toEqual(Buffer.from([4]))
        expect(
            serializeMpintBufferToBuffer(algorithm.computeSharedSecret(Buffer.from([8]))),
        ).toEqual(Buffer.from([64]))
        expect(
            algorithm
                .computeExchangeHash({
                    clientVersion: "SSH-2.0-fixed-client",
                    serverVersion: "SSH-2.0-fixed-server",
                    clientKexInit: Buffer.from("14010203", "hex"),
                    serverKexInit: Buffer.from("14040506", "hex"),
                    serverHostKey: Buffer.from("0000000b7373682d65643235353139", "hex"),
                    clientExchangeValue: Buffer.from([4]),
                    serverExchangeValue: Buffer.from([8]),
                })
                .toString("hex"),
        ).toBe("21d1ba3db0819210d180c04d0095efcf645c6f89")
    })

    test.each(vectors)("rejects invalid public values for $name", (vector) => {
        const algorithm: DiffieHellmanGroupN = vector.create(Buffer.from([2]))
        const prime = decodeBigIntBE(vector.prime)
        algorithm.generateKeyPair()

        for (const endpoint of [1n, prime - 1n]) {
            expect(() =>
                algorithm.computeSharedSecret(
                    serializeMpintBufferToBuffer(encodeBigIntBE(endpoint)),
                ),
            ).toThrow("outside (1, p-1)")
        }
        expect(() => algorithm.computeSharedSecret(Buffer.alloc(0))).toThrow("positive mpint")
        expect(() => algorithm.computeSharedSecret(Buffer.from([0, 2]))).toThrow(
            "not canonically encoded",
        )
        expect(() => algorithm.computeSharedSecret(Buffer.from([0x80]))).toThrow("positive mpint")
    })
})
