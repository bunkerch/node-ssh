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

    test("emits a complete fixed server greeting before identification", () => {
        const client = new Client({ hostname: "unused.invalid" })
        const greetings: string[] = []
        const wrapperLines: string[] = []
        client.on("greeting", (greeting) => greetings.push(greeting))
        client.on("tcpWrapperLog", (line) => wrapperLines.push(line))

        client.onMessage(Buffer.from("Authorized access only\r\nMaintenance at 02:00\n"))
        expect(greetings).toEqual([])
        client.onMessage(Buffer.from("SSH-2.0-OpenSSH_9.2\r\n"))

        expect(greetings).toEqual(["Authorized access only\r\nMaintenance at 02:00\n"])
        expect(wrapperLines).toEqual(["Authorized access only", "Maintenance at 02:00"])
    })

    test("yields between complete packets from one TCP read", async () => {
        const client = new Client({ hostname: "unused.invalid" })
        client.onMessage(Buffer.from("SSH-2.0-test_server\r\n"))

        const received: number[] = []
        client.on("packet", (metadata) => {
            if (metadata.name === "SSH_MSG_IGNORE") received.push(metadata.sequenceNumber)
        })
        const encoder = new BinaryPacketEncoder({ randomBytes: deterministicPadding })
        const first = encoder.encode(new Ignore({ data: Buffer.from("first") }).serialize()).data
        const second = encoder.encode(new Ignore({ data: Buffer.from("second") }).serialize()).data

        client.onMessage(Buffer.concat([first, second]))
        expect(received).toEqual([0])
        await Promise.resolve()
        expect(received).toEqual([0, 1])
    })
})
