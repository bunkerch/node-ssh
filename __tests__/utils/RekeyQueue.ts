import type Packet from "../../src/packet.js"
import {
    deferApplicationTraffic,
    discardApplicationTrafficPause,
    MAX_REKEY_QUEUED_BYTES,
    MAX_REKEY_QUEUED_PACKETS,
    OutboundRekeyQueue,
    pauseApplicationTraffic,
    resumeApplicationTraffic,
} from "../../src/utils/RekeyQueue.js"

class FixedPacket implements Packet {
    static type = 200

    constructor(readonly source: Buffer) {}

    serialize(): Buffer {
        return Buffer.from(this.source)
    }
}

describe("outbound rekey queue", () => {
    test("snapshots queued payloads and drains them in order", () => {
        const queue = new OutboundRekeyQueue()
        const first = new FixedPacket(Buffer.from("first"))
        const second = new FixedPacket(Buffer.from("second"))
        queue.enqueue(first)
        queue.enqueue(second)
        first.source.fill(0)
        second.source.fill(0)

        const written: Buffer[] = []
        queue.drain((_packet, payload) => written.push(Buffer.from(payload)))

        expect(written).toEqual([Buffer.from("first"), Buffer.from("second")])
    })

    test("bounds retained packet count and bytes", () => {
        const packets = new OutboundRekeyQueue()
        for (let index = 0; index < MAX_REKEY_QUEUED_PACKETS; index++) {
            packets.enqueue(new FixedPacket(Buffer.from([index & 0xff])))
        }
        expect(() => packets.enqueue(new FixedPacket(Buffer.from([0])))).toThrow(
            "SSH outbound rekey queue exceeds",
        )

        const bytes = new OutboundRekeyQueue()
        bytes.enqueue(new FixedPacket(Buffer.alloc(MAX_REKEY_QUEUED_BYTES)))
        expect(() => bytes.enqueue(new FixedPacket(Buffer.from([0])))).toThrow(
            "SSH outbound rekey queue exceeds",
        )
    })

    test("resumes deferred traffic only after queued packets are flushed", () => {
        const transport = {}
        const order: string[] = []
        const resume = () => order.push("traffic")
        pauseApplicationTraffic(transport)
        expect(deferApplicationTraffic(transport, resume)).toBe(true)
        expect(deferApplicationTraffic(transport, resume)).toBe(true)

        resumeApplicationTraffic(transport, () => order.push("queue"))

        expect(order).toEqual(["queue", "traffic"])
        expect(deferApplicationTraffic(transport, resume)).toBe(false)
        discardApplicationTrafficPause(transport)
    })
})
