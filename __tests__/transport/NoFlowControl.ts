import {
    findNoFlowControlValue,
    negotiateNoFlowControl,
    noFlowControlExtension,
    normalizeNoFlowControlPreference,
} from "../../src/NoFlowControl.js"

describe("RFC 8308 no-flow-control negotiation", () => {
    test("uses the exact registered extension values", () => {
        expect(noFlowControlExtension("preferred")).toEqual({
            name: "no-flow-control",
            value: Buffer.from("p", "ascii"),
        })
        expect(noFlowControlExtension("supported")).toEqual({
            name: "no-flow-control",
            value: Buffer.from("s", "ascii"),
        })
        expect(noFlowControlExtension(false)).toBeUndefined()
    })

    test.each([
        ["p", "p", true],
        ["p", "s", true],
        ["s", "p", true],
        ["s", "s", false],
    ] as const)("negotiates local %s with peer %s as %s", (local, peer, expected) => {
        expect(
            negotiateNoFlowControl(local, [
                { name: "no-flow-control", value: Buffer.from(peer, "ascii") },
            ]),
        ).toBe(expected)
    })

    test("requires bilateral advertisement and validates recognized values", () => {
        expect(negotiateNoFlowControl("p", [])).toBe(false)
        expect(
            negotiateNoFlowControl(undefined, [
                { name: "no-flow-control", value: Buffer.from("p", "ascii") },
            ]),
        ).toBe(false)
        expect(() =>
            findNoFlowControlValue([
                { name: "no-flow-control", value: Buffer.from("preferred", "ascii") },
            ]),
        ).toThrow('must be "p" or "s"')
    })

    test("rejects ambiguous public configuration", () => {
        expect(normalizeNoFlowControlPreference(undefined)).toBe(false)
        expect(() => normalizeNoFlowControlPreference(true as never)).toThrow(
            'must be false, "supported", or "preferred"',
        )
    })
})
