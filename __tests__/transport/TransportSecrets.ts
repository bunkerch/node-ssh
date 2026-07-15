import {
    BinaryPacketDecoder,
    BinaryPacketEncoder,
    type InboundPacketProtection,
    type OutboundPacketProtection,
} from "../../src/BinaryPacket.js"
import {
    EncryptionAlgorithm,
    encryption_algorithms,
    instantiateEncryptionAlgorithm,
    instantiateMACAlgorithm,
    instantiateTransportAlgorithms,
    mac_algorithms,
    type DerivedTransportKeys,
} from "../../src/algorithms.js"

describe("transport protection secret lifecycle", () => {
    test.each([...encryption_algorithms])(
        "%s validates its declared material and becomes unusable after disposal",
        (name, algorithm) => {
            const key = Buffer.alloc(algorithm.key_length, 0x41)
            const iv = Buffer.alloc(algorithm.iv_length, 0x42)
            const cipher = instantiateEncryptionAlgorithm(algorithm, key, iv)
            expect(typeof cipher.dispose).toBe("function")
            cipher.dispose!()
            cipher.dispose!()

            if (algorithm.aead) {
                expect(() => cipher.encryptPacket!(0, Buffer.alloc(16))).toThrow(/disposed/iu)
            } else {
                expect(() => cipher.encrypt(Buffer.alloc(algorithm.block_size))).toThrow(
                    /disposed/iu,
                )
            }
            expect(() =>
                instantiateEncryptionAlgorithm(
                    algorithm,
                    Buffer.alloc(algorithm.key_length + 1),
                    iv,
                ),
            ).toThrow(`${name} cipher key must be ${algorithm.key_length} bytes`)
            expect(() =>
                instantiateEncryptionAlgorithm(
                    algorithm,
                    key,
                    Buffer.alloc(algorithm.iv_length + 1),
                ),
            ).toThrow(`${name} cipher IV must be ${algorithm.iv_length} bytes`)
        },
    )

    test.each([...mac_algorithms])("%s becomes unusable after disposal", (_name, algorithm) => {
        const mac = instantiateMACAlgorithm(algorithm, Buffer.alloc(algorithm.key_length, 0x43))
        expect(typeof mac.dispose).toBe("function")
        mac.dispose!()
        mac.dispose!()
        expect(() => mac.computeMAC(0, Buffer.from("packet"))).toThrow(/disposed/iu)
    })

    test("disposes partial construction when a later transport algorithm fails", () => {
        let disposals = 0
        const first = {
            alg_name: "first-cipher@example.test",
            key_length: 1,
            iv_length: 1,
            block_size: 8,
            instantiate: () =>
                ({
                    encrypt: (value: Buffer) => value,
                    decrypt: (value: Buffer) => value,
                    dispose: () => disposals++,
                }) as EncryptionAlgorithm,
        } as unknown as typeof EncryptionAlgorithm
        const failing = {
            alg_name: "failing-cipher@example.test",
            key_length: 1,
            iv_length: 1,
            block_size: 8,
            instantiate: () => {
                throw new Error("cipher construction failed")
            },
        } as unknown as typeof EncryptionAlgorithm
        const keys: DerivedTransportKeys = {
            clientIV: Buffer.alloc(1),
            serverIV: Buffer.alloc(1),
            clientEncryption: Buffer.alloc(1),
            serverEncryption: Buffer.alloc(1),
            clientIntegrity: Buffer.alloc(0),
            serverIntegrity: Buffer.alloc(0),
        }

        expect(() =>
            instantiateTransportAlgorithms(
                {
                    clientEncryption: first,
                    serverEncryption: failing,
                    clientMac: undefined,
                    serverMac: undefined,
                },
                keys,
            ),
        ).toThrow("cipher construction failed")
        expect(disposals).toBe(1)
    })

    test("packet codecs dispose replaced protection exactly once and reject later use", () => {
        const outboundDisposals = [0, 0]
        const inboundDisposals = [0, 0]
        const outbound = outboundDisposals.map<OutboundPacketProtection>((_value, index) => ({
            cipher: { encrypt: (value) => value },
            mac: { computeMAC: () => Buffer.alloc(0) },
            blockSize: 8,
            macLength: 0,
            dispose: () => outboundDisposals[index]++,
        }))
        const inbound = inboundDisposals.map<InboundPacketProtection>((_value, index) => ({
            cipher: { decrypt: (value) => value },
            mac: { computeMAC: () => Buffer.alloc(0) },
            blockSize: 8,
            macLength: 0,
            dispose: () => inboundDisposals[index]++,
        }))
        const encoder = new BinaryPacketEncoder()
        const decoder = new BinaryPacketDecoder()

        encoder.setProtection(outbound[0])
        encoder.setProtection(outbound[1])
        encoder.setProtection(outbound[1])
        decoder.setProtection(inbound[0])
        decoder.setProtection(inbound[1])
        decoder.setProtection(inbound[1])
        expect(outboundDisposals).toEqual([1, 0])
        expect(inboundDisposals).toEqual([1, 0])

        encoder.dispose()
        encoder.dispose()
        decoder.dispose()
        decoder.dispose()
        expect(outboundDisposals).toEqual([1, 1])
        expect(inboundDisposals).toEqual([1, 1])
        expect(() => encoder.encode(Buffer.from([1]))).toThrow("encoder is disposed")
        expect(() => decoder.push(Buffer.from([1]))).toThrow("decoder is disposed")
    })
})
