import {
    elevationExtension,
    findElevationRequest,
    normalizeElevationPreference,
} from "../../src/Elevation.js"
import Client from "../../src/Client.js"
import ExtInfo from "../../src/packets/ExtInfo.js"
import GlobalRequest from "../../src/packets/GlobalRequest.js"

describe("RFC 8308 elevation negotiation", () => {
    test("serializes the exact registered extension values", () => {
        const expected = {
            elevated: Buffer.from("070000000100000009656c65766174696f6e0000000179", "hex"),
            unelevated: Buffer.from("070000000100000009656c65766174696f6e000000016e", "hex"),
            default: Buffer.from("070000000100000009656c65766174696f6e0000000164", "hex"),
        }

        for (const [preference, bytes] of Object.entries(expected)) {
            expect(
                new ExtInfo({
                    extensions: [elevationExtension(preference as keyof typeof expected)!],
                }).serialize(),
            ).toEqual(bytes)
        }
        expect(elevationExtension(false)).toBeUndefined()
    })

    test.each([
        ["y", "elevated"],
        ["n", "unelevated"],
        ["d", "default"],
    ] as const)("parses registered value %s as %s", (value, expected) => {
        expect(
            findElevationRequest([{ name: "elevation", value: Buffer.from(value, "ascii") }]),
        ).toBe(expected)
    })

    test("uses the exact post-authentication global request layout", () => {
        const bytes = Buffer.from("5000000009656c65766174696f6e0001", "hex")
        const request = GlobalRequest.parse(bytes)

        expect(request.data).toEqual({
            request_name: "elevation",
            want_reply: false,
            args: Buffer.from([1]),
        })
        expect(request.serialize()).toEqual(bytes)
    })

    test("rejects invalid wire values and public configuration", () => {
        expect(() =>
            findElevationRequest([{ name: "elevation", value: Buffer.from("yes", "ascii") }]),
        ).toThrow('must be "y", "n", or "d"')
        expect(normalizeElevationPreference(undefined)).toBe(false)
        expect(() => normalizeElevationPreference(true as never)).toThrow(
            'must be false, "default", "elevated", or "unelevated"',
        )
        expect(() => new Client({ elevation: true as never })).toThrow(
            'must be false, "default", "elevated", or "unelevated"',
        )
    })
})
