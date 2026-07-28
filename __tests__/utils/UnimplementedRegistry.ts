import { expect, test } from "bun:test"
import {
    registerUnimplementedRejection,
    rejectUnimplementedPacket,
} from "../../src/utils/UnimplementedRegistry.js"

test("unimplemented registrations preserve send order across sequence resets", () => {
    const owner = {}
    const rejected: string[] = []
    registerUnimplementedRejection(owner, 0, () => rejected.push("before-reset"))
    registerUnimplementedRejection(owner, 0, () => rejected.push("after-reset"))

    expect(rejectUnimplementedPacket(owner, 0)).toBe(true)
    expect(rejected).toEqual(["before-reset"])
    expect(rejectUnimplementedPacket(owner, 0)).toBe(true)
    expect(rejected).toEqual(["before-reset", "after-reset"])
    expect(rejectUnimplementedPacket(owner, 0)).toBe(false)
})

test("unregistering one operation leaves another matching sequence intact", () => {
    const owner = {}
    const rejected: string[] = []
    const unregister = registerUnimplementedRejection(owner, 7, () => rejected.push("cancelled"))
    registerUnimplementedRejection(owner, 7, () => rejected.push("pending"))

    unregister()
    unregister()
    expect(rejectUnimplementedPacket(owner, 7)).toBe(true)
    expect(rejected).toEqual(["pending"])
    expect(rejectUnimplementedPacket(owner, 7)).toBe(false)
})
