import {
    MAXIMUM_TIMER_DELAY,
    normalizeOptionalTimeout,
    normalizeTimeout,
} from "../../src/utils/Timeout.js"

describe("timer normalization", () => {
    test("accepts only timer delays which Node preserves", () => {
        expect(normalizeTimeout(undefined, 30_000, "Operation timeout")).toBe(30_000)
        expect(normalizeTimeout(1, 30_000, "Operation timeout")).toBe(1)
        expect(normalizeTimeout(MAXIMUM_TIMER_DELAY, 30_000, "Operation timeout")).toBe(
            MAXIMUM_TIMER_DELAY,
        )
        expect(normalizeOptionalTimeout(0, "Optional timeout")).toBe(0)
        expect(normalizeOptionalTimeout(MAXIMUM_TIMER_DELAY, "Optional timeout")).toBe(
            MAXIMUM_TIMER_DELAY,
        )

        for (const timeout of [
            -1,
            0,
            1.5,
            MAXIMUM_TIMER_DELAY + 1,
            Number.NaN,
            Number.POSITIVE_INFINITY,
        ]) {
            expect(() => normalizeTimeout(timeout, 30_000, "Operation timeout")).toThrow(
                "Operation timeout must be an integer between 1 and 2147483647",
            )
        }
        for (const timeout of [
            -1,
            1.5,
            MAXIMUM_TIMER_DELAY + 1,
            Number.NaN,
            Number.POSITIVE_INFINITY,
        ]) {
            expect(() => normalizeOptionalTimeout(timeout, "Optional timeout")).toThrow(
                "Optional timeout must be an integer between 0 and 2147483647",
            )
        }
    })
})
