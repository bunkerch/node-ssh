import { EventEmitter } from "node:events"
import { expect, test } from "bun:test"
import Ignore from "../../src/packets/Ignore.js"
import { emitPacketEvent, waitForMatchingPacket } from "../../src/utils/PacketEventQueue.js"

test("unbounded packet waits ignore unrelated packets and clean up after a match", async () => {
    const source = new EventEmitter()
    const unrelated = new Ignore({ data: Buffer.from("unrelated") })
    const expected = new Ignore({ data: Buffer.from("expected") })
    const waiting = waitForMatchingPacket(
        source,
        (packet) => packet === expected,
        () => new Error("closed"),
    )

    emitPacketEvent(source, unrelated)
    emitPacketEvent(source, expected)

    expect(await waiting).toBe(expected)
    expect(source.listenerCount("error")).toBe(0)
    expect(source.listenerCount("close")).toBe(0)
})

test("unbounded packet waits still reject and clean up when the connection closes", async () => {
    const source = new EventEmitter()
    const waiting = waitForMatchingPacket(
        source,
        () => false,
        () => new Error("connection closed"),
    )

    source.emit("close")

    await expect(waiting).rejects.toThrow("connection closed")
    expect(source.listenerCount("error")).toBe(0)
    expect(source.listenerCount("close")).toBe(0)
})

test("bounded packet waits reject and clean up after their deadline", async () => {
    const source = new EventEmitter()
    const waiting = waitForMatchingPacket(
        source,
        () => false,
        () => new Error("connection closed"),
        { milliseconds: 10, error: () => new Error("packet deadline expired") },
    )

    await expect(waiting).rejects.toThrow("packet deadline expired")
    expect(source.listenerCount("error")).toBe(0)
    expect(source.listenerCount("close")).toBe(0)
})
