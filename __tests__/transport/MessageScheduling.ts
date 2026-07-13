import { BinaryPacketEncoder } from "../../src/BinaryPacket.js"
import Client from "../../src/Client.js"
import Ignore from "../../src/packets/Ignore.js"

const deterministicPadding = (size: number): Buffer => Buffer.alloc(size, 0xa5)

describe("transport message scheduling", () => {
    test("yields after identification before processing coalesced binary data", async () => {
        const client = new Client({ hostname: "unused.invalid" })
        const events: string[] = []
        client.on("serverProtocolVersion", () => events.push("identification"))
        client.on("packet", () => events.push("packet"))

        const packet = new BinaryPacketEncoder({ randomBytes: deterministicPadding }).encode(
            new Ignore({ data: Buffer.from("coalesced") }).serialize(),
        ).data
        client.onMessage(Buffer.concat([Buffer.from("SSH-2.0-test_server\r\n"), packet]))

        expect(events).toEqual(["identification"])
        await Promise.resolve()
        expect(events).toEqual(["identification", "packet"])
    })

    test("yields between complete packets from one TCP read", async () => {
        const client = new Client({ hostname: "unused.invalid" })
        client.onMessage(Buffer.from("SSH-2.0-test_server\r\n"))

        const received: string[] = []
        client.on("packet", (packet) => {
            if (packet instanceof Ignore) received.push(packet.data.data.toString())
        })
        const encoder = new BinaryPacketEncoder({ randomBytes: deterministicPadding })
        const first = encoder.encode(new Ignore({ data: Buffer.from("first") }).serialize()).data
        const second = encoder.encode(new Ignore({ data: Buffer.from("second") }).serialize()).data

        client.onMessage(Buffer.concat([first, second]))
        expect(received).toEqual(["first"])
        await Promise.resolve()
        expect(received).toEqual(["first", "second"])
    })
})
