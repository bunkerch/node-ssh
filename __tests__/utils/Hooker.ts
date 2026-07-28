import { expect, test } from "bun:test"
import { Hooker } from "../../src/utils/Hooker.js"

test("Hooker reports non-Error rejections as typed Error values", async () => {
    const hooker = new Hooker<{ policy: [] }>()
    let reportedEvent: string | undefined
    let reportedError: Error | undefined

    hooker.on("uncaughtException", (event, error) => {
        reportedEvent = event
        reportedError = error
    })
    hooker.hook("policy", async () => {
        throw "policy backend failed"
    })

    expect(await hooker.triggerHookChecked("policy")).toBe(false)
    expect(reportedEvent).toBe("policy")
    expect(reportedError).toBeInstanceOf(Error)
    expect(reportedError?.message).toBe("policy backend failed")
})

test("Hooker identifies fallback diagnostics as modernssh", async () => {
    const hooker = new Hooker<{ policy: [] }>()
    const warnings: unknown[][] = []
    const originalWarn = console.warn
    console.warn = (...values: unknown[]) => warnings.push(values)
    hooker.hook("policy", () => {
        throw new Error("policy backend failed")
    })

    try {
        expect(await hooker.triggerHookChecked("policy")).toBe(false)
    } finally {
        console.warn = originalWarn
    }

    expect(warnings).toHaveLength(1)
    expect(warnings[0]?.[0]).toBe("[modernssh] Uncaught exception in hook for event policy:")
    expect(warnings[0]?.[1]).toBeInstanceOf(Error)
})
