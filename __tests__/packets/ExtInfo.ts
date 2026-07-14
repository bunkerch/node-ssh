import ExtInfo from "../../src/packets/ExtInfo.js"

const serverSignatureAlgorithms = Buffer.from(
    "07000000010000000f7365727665722d7369672d616c6773" +
        "000000187273612d736861322d3531322c7373682d65643235353139",
    "hex",
)
const agentForwarding = Buffer.from("07000000010000000d6167656e742d666f72776172640000000130", "hex")

describe("RFC 8308 extension information vectors", () => {
    test("parses and serializes a fixed server-sig-algs message", () => {
        const packet = ExtInfo.parse(serverSignatureAlgorithms)

        expect(packet.data.extensions).toEqual([
            {
                name: "server-sig-algs",
                value: Buffer.from("rsa-sha2-512,ssh-ed25519", "ascii"),
            },
        ])
        expect(packet.serialize()).toEqual(serverSignatureAlgorithms)
    })

    test("rejects duplicate extension names", () => {
        expect(
            () =>
                new ExtInfo({
                    extensions: [
                        { name: "duplicate@example.test", value: Buffer.from("one") },
                        { name: "duplicate@example.test", value: Buffer.from("two") },
                    ],
                }),
        ).toThrow("Duplicate SSH extension")
    })

    test("parses and serializes the fixed RFC 9987 agent-forward advertisement", () => {
        const packet = ExtInfo.parse(agentForwarding)

        expect(packet.data.extensions).toEqual([
            { name: "agent-forward", value: Buffer.from("0", "ascii") },
        ])
        expect(packet.serialize()).toEqual(agentForwarding)
    })

    test("copies opaque extension values supplied by the caller", () => {
        const value = Buffer.from([0x00, 0xff, 0x41])
        const packet = new ExtInfo({
            extensions: [{ name: "binary@example.test", value }],
        })
        value.fill(0)
        expect(packet.data.extensions).toEqual([
            { name: "binary@example.test", value: Buffer.from([0x00, 0xff, 0x41]) },
        ])
    })
})
