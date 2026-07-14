import { createDiffieHellmanGroup } from "node:crypto"
import { kex_algorithms } from "../../src/algorithms.js"
import {
    computeGroupExchangeHash,
    defaultGroupExchangeRequest,
    DiffieHellmanGroupExchange,
} from "../../src/algorithms/kex/diffie-hellman-group-exchange.js"
import { decodeBigIntBE } from "../../src/utils/BigInt.js"
import { serializeMpintBufferToBuffer } from "../../src/utils/mpint.js"

class InspectableGroupExchange extends DiffieHellmanGroupExchange {
    constructor() {
        super("sha256")
    }

    get secret(): Buffer | undefined {
        return this.sharedSecret
    }
}

describe("RFC 4419 Diffie-Hellman group exchange", () => {
    test("matches independently calculated new and legacy exchange hashes", () => {
        const common = {
            clientVersion: "SSH-2.0-client",
            serverVersion: "SSH-2.0-server",
            clientKexInit: Buffer.from("1401", "hex"),
            serverKexInit: Buffer.from("1402", "hex"),
            hostKey: Buffer.from("key"),
            prime: Buffer.from("008001", "hex"),
            generator: Buffer.from([2]),
            clientPublicKey: Buffer.from([3]),
            serverPublicKey: Buffer.from([4]),
            sharedSecret: Buffer.from([5]),
        }
        expect(
            computeGroupExchangeHash({
                ...common,
                hashName: "sha256",
                request: defaultGroupExchangeRequest,
            }).toString("hex"),
        ).toBe("3164412942827ef74fd0ae510be509b9992574d9f6dbf26717ebc81103c9e944")
        expect(
            computeGroupExchangeHash({
                ...common,
                hashName: "sha1",
                request: { preferred: 3072 },
            }).toString("hex"),
        ).toBe("04d96fc86a1f27263a411a3832fd86be4d624277")
    })

    test("prefers SHA-256 and leaves SHA-1 as the final compatibility method", () => {
        const names = [...kex_algorithms.keys()]
        expect(names.indexOf("diffie-hellman-group-exchange-sha256")).toBeLessThan(
            names.indexOf("diffie-hellman-group14-sha256"),
        )
        expect(names.at(-1)).toBe("diffie-hellman-group-exchange-sha1")
    })

    test("selects the RFC 8270 preferred group and computes the same shared secret", () => {
        const server = new InspectableGroupExchange()
        server.setRequest(defaultGroupExchangeRequest)
        const group = server.selectServerGroup()
        expect(decodeBigIntBE(group.p).toString(2).length).toBe(3072)
        expect(group.g).toEqual(Buffer.from([2]))

        const client = new InspectableGroupExchange()
        client.setRequest(defaultGroupExchangeRequest)
        client.acceptServerGroup(group.p, group.g)
        server.generateKeyPair()
        client.generateKeyPair()
        server.computeSharedSecret(serializeMpintBufferToBuffer(client.getPublicKey()))
        client.computeSharedSecret(serializeMpintBufferToBuffer(server.getPublicKey()))
        expect(client.secret).toEqual(server.secret)
        expect(client.secret?.length).toBeGreaterThanOrEqual(256)

        const retainedSecret = client.secret!
        client.dispose()
        expect(retainedSecret).toEqual(Buffer.alloc(retainedSecret.length))
        expect(client.secret).toBeUndefined()
    })

    test("chooses only a known safe group inside the requested range", () => {
        const exchange = new InspectableGroupExchange()
        exchange.setRequest({ min: 4000, preferred: 5000, max: 7000 })
        expect(decodeBigIntBE(exchange.selectServerGroup().p).toString(2).length).toBe(6144)

        const unavailable = new InspectableGroupExchange()
        unavailable.setRequest({ min: 5000, preferred: 5500, max: 6000 })
        expect(() => unavailable.selectServerGroup()).toThrow("No supported Diffie-Hellman group")
    })

    test("bounds the legacy preferred-size request", () => {
        const exchange = new InspectableGroupExchange()
        exchange.setOldRequest(3072)
        expect(decodeBigIntBE(exchange.selectServerGroup().p).toString(2).length).toBe(3072)
        expect(() => exchange.setOldRequest(1024)).toThrow("between 2048 and 8192")
        expect(() => exchange.setOldRequest(8193)).toThrow("between 2048 and 8192")
    })

    test("rejects unsafe requests, groups, and peer public values", () => {
        const exchange = new InspectableGroupExchange()
        for (const request of [
            { min: 1024, preferred: 3072, max: 8192 },
            { min: 4096, preferred: 3072, max: 8192 },
            { min: 2048, preferred: 9000, max: 8192 },
        ]) {
            expect(() => exchange.setRequest(request)).toThrow("2048 <= min")
        }

        exchange.setRequest(defaultGroupExchangeRequest)
        const composite = Buffer.concat([Buffer.from([0]), Buffer.alloc(256, 0xff)])
        expect(() => exchange.acceptServerGroup(composite, Buffer.from([2]))).toThrow("safe-prime")

        const group14 = createDiffieHellmanGroup("modp14")
        exchange.acceptServerGroup(
            serializeMpintBufferToBuffer(group14.getPrime()),
            group14.getGenerator(),
        )
        exchange.generateKeyPair()
        expect(() => exchange.computeSharedSecret(Buffer.alloc(0))).toThrow("positive mpint")
        expect(() => exchange.computeSharedSecret(Buffer.from([0]))).toThrow("must be positive")
        expect(() => exchange.computeSharedSecret(Buffer.from([0, 1]))).toThrow(
            "not canonically encoded",
        )
        expect(() =>
            exchange.computeSharedSecret(serializeMpintBufferToBuffer(group14.getPrime())),
        ).toThrow("outside (1, p-1)")
        expect(() => exchange.computeSharedSecret(Buffer.from([1]))).toThrow("outside (1, p-1)")
        const prime = decodeBigIntBE(group14.getPrime())
        expect(() =>
            exchange.computeSharedSecret(
                serializeMpintBufferToBuffer(Buffer.from((prime - 1n).toString(16), "hex")),
            ),
        ).toThrow("outside (1, p-1)")
    })

    test("matches a normalized exchange-hash context after key agreement", () => {
        const server = new InspectableGroupExchange()
        server.setRequest(defaultGroupExchangeRequest)
        const group = server.selectServerGroup()
        server.generateKeyPair()

        const client = new InspectableGroupExchange()
        client.setRequest(defaultGroupExchangeRequest)
        client.acceptServerGroup(group.p, group.g)
        client.generateKeyPair()

        const hostKey = Buffer.from("host key")
        const peerPublicKey = serializeMpintBufferToBuffer(server.getPublicKey())
        const retainedPeerPublicKey = Buffer.from(peerPublicKey)
        client.computeSharedSecret(peerPublicKey)

        const serverKexInit = Buffer.from("1402", "hex")
        const expected = computeGroupExchangeHash({
            hashName: "sha256",
            clientVersion: "SSH-2.0-client",
            serverVersion: "SSH-2.0-server",
            clientKexInit: Buffer.from("1401", "hex"),
            serverKexInit,
            hostKey: Buffer.from(hostKey),
            request: defaultGroupExchangeRequest,
            prime: group.p,
            generator: group.g,
            clientPublicKey: serializeMpintBufferToBuffer(client.getPublicKey()),
            serverPublicKey: retainedPeerPublicKey,
            sharedSecret: client.secret!,
        })

        hostKey.fill(0xff)
        peerPublicKey.fill(0xff)

        expect(
            client.computeExchangeHash({
                clientVersion: "SSH-2.0-client",
                serverVersion: "SSH-2.0-server",
                clientKexInit: Buffer.from("1401", "hex"),
                serverKexInit,
                serverHostKey: Buffer.from("host key"),
                clientExchangeValue: client.getPublicKey(),
                serverExchangeValue: retainedPeerPublicKey,
            }),
        ).toEqual(expected)
    })
})
