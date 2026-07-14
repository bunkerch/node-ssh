import { createDiffieHellmanGroup, createHash } from "node:crypto"

import DiffieHellmanGroup14SHA256 from "../../src/algorithms/kex/diffie-hellman-group14-sha256.js"
import DiffieHellmanGroup15SHA512 from "../../src/algorithms/kex/diffie-hellman-group15-sha512.js"
import DiffieHellmanGroup16SHA512 from "../../src/algorithms/kex/diffie-hellman-group16-sha512.js"
import DiffieHellmanGroup17SHA512 from "../../src/algorithms/kex/diffie-hellman-group17-sha512.js"
import DiffieHellmanGroup18SHA512 from "../../src/algorithms/kex/diffie-hellman-group18-sha512.js"
import type DiffieHellmanGroupN from "../../src/algorithms/kex/diffie-hellman-groupN.js"
import { decodeBigIntBE, encodeBigIntBE } from "../../src/utils/BigInt.js"
import { serializeMpintBufferToBuffer } from "../../src/utils/mpint.js"

const vectors = [
    {
        name: "group14-sha256",
        group: "modp14",
        bits: 2048,
        primeSHA256: "d66436f79bbd6b2e38c0ffbd079be904d2641415e2e67140e09448be9a60890e",
        create: (privateKey?: Buffer) => new DiffieHellmanGroup14SHA256(privateKey),
    },
    {
        name: "group15-sha512",
        group: "modp15",
        bits: 3072,
        primeSHA256: "48cf8b092fbce4359d9871abf74f98e25b6163379eaa15cd9087e800c6d1c55c",
        create: (privateKey?: Buffer) => new DiffieHellmanGroup15SHA512(privateKey),
    },
    {
        name: "group16-sha512",
        group: "modp16",
        bits: 4096,
        primeSHA256: "4ee95187682bcb230ad26a95205f6920e84708f6251b3894329b09ec23919e33",
        create: (privateKey?: Buffer) => new DiffieHellmanGroup16SHA512(privateKey),
    },
    {
        name: "group17-sha512",
        group: "modp17",
        bits: 6144,
        primeSHA256: "d1bfe6d0925ce7e4da262b62861514a7755e35831e429f343e7b864848657efd",
        create: (privateKey?: Buffer) => new DiffieHellmanGroup17SHA512(privateKey),
    },
    {
        name: "group18-sha512",
        group: "modp18",
        bits: 8192,
        primeSHA256: "39ab4feab950a3128fb71accb9fc3965d857012e081998a85996e3ea8b3c3bcf",
        create: (privateKey?: Buffer) => new DiffieHellmanGroup18SHA512(privateKey),
    },
] as const

describe("RFC 8268 fixed-group Diffie-Hellman", () => {
    test.each(vectors)("uses the published RFC 3526 $name group", (vector) => {
        const parameters = createDiffieHellmanGroup(vector.group)
        expect(parameters.getPrime().length * 8).toBe(vector.bits)
        expect(parameters.getGenerator()).toEqual(Buffer.from([2]))
        expect(createHash("sha256").update(parameters.getPrime()).digest("hex")).toBe(
            vector.primeSHA256,
        )
        expect(vector.create().groupName).toBe(vector.group)
    })

    test.each(vectors)("matches a pure modular-arithmetic $name value", (vector) => {
        const algorithm = vector.create(Buffer.from([2]))
        const prime = decodeBigIntBE(createDiffieHellmanGroup(vector.group).getPrime())
        algorithm.generateKeyPair()

        expect(algorithm.getPublicKey()).toEqual(Buffer.from([4]))
        expect(
            serializeMpintBufferToBuffer(
                algorithm.computeSharedSecret(
                    serializeMpintBufferToBuffer(encodeBigIntBE(prime - 2n)),
                ),
            ),
        ).toEqual(Buffer.from([4]))
    })

    test.each(vectors)("enforces the RFC 8268 open public-value interval for $name", (vector) => {
        const algorithm: DiffieHellmanGroupN = vector.create(Buffer.from([2]))
        const prime = decodeBigIntBE(createDiffieHellmanGroup(vector.group).getPrime())
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
