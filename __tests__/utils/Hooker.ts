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
