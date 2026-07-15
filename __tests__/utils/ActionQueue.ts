import { expect, test } from "bun:test"
import { ActionQueue, ActionQueueCapacityError } from "../../src/utils/ActionQueue.js"

function deferred(): { promise: Promise<void>; resolve: () => void } {
    let resolve!: () => void
    const promise = new Promise<void>((done) => {
        resolve = done
    })
    return { promise, resolve }
}

test("ActionQueue bounds waiting work while allowing independent keys to run", async () => {
    const queue = new ActionQueue(1)
    const first = deferred()
    const events: string[] = []
    const active = queue.queueAction("shared", async () => {
        events.push("active")
        await first.promise
    })
    const waiting = queue.queueAction("shared", async () => {
        events.push("waiting")
    })
    const independent = queue.queueAction("independent", async () => {
        events.push("independent")
    })

    await expect(
        queue.queueAction("shared", async () => {
            events.push("overflow")
        }),
    ).rejects.toBeInstanceOf(ActionQueueCapacityError)
    await independent
    expect(queue.queuedActions).toBe(1)
    expect(events).toEqual(["active", "independent"])

    first.resolve()
    await Promise.all([active, waiting])
    expect(queue.queuedActions).toBe(0)
    expect(events).toEqual(["active", "independent", "waiting"])
})

test("ActionQueue close rejects waiting and future work without abandoning Promises", async () => {
    const queue = new ActionQueue(2)
    const first = deferred()
    const active = queue.queueAction("shared", async () => first.promise)
    const waiting = queue.queueAction("shared", async () => undefined)
    const failure = new Error("connection closed")

    queue.close(failure)
    await expect(waiting).rejects.toBe(failure)
    await expect(queue.queueAction("other", async () => undefined)).rejects.toBe(failure)
    expect(queue.queuedActions).toBe(0)

    first.resolve()
    await active
})

test("ActionQueue validates its waiting-operation bound", () => {
    for (const maximum of [
        -1,
        0.5,
        Number.NaN,
        Number.POSITIVE_INFINITY,
        Number.MAX_SAFE_INTEGER + 1,
    ]) {
        expect(() => new ActionQueue(maximum)).toThrow(
            "Maximum queued actions must be a non-negative safe integer",
        )
    }
})
