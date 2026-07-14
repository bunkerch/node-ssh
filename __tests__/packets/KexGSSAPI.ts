import {
    KexGSSAPIComplete,
    KexGSSAPIContinue,
    KexGSSAPIError,
    KexGSSAPIHostKey,
    KexGSSAPIInit,
} from "../../src/packets/KexGSSAPI.js"

describe("RFC 4462 and RFC 8732 GSS-API key-exchange packets", () => {
    test("matches fixed ECDH init and continuation packets", () => {
        const init = new KexGSSAPIInit(
            Buffer.from("010203", "hex"),
            Buffer.from("0405", "hex"),
            "string",
        )
        expect(init.serialize().toString("hex")).toBe("1e00000003010203000000020405")
        expect(KexGSSAPIInit.parse(init.serialize(), "string")).toEqual(init)

        const continuation = new KexGSSAPIContinue(Buffer.from([0xaa]))
        expect(continuation.serialize().toString("hex")).toBe("1f00000001aa")
        expect(KexGSSAPIContinue.parse(continuation.serialize())).toEqual(continuation)
    })

    test("matches fixed DH init and completion packets", () => {
        const init = new KexGSSAPIInit(Buffer.from([1]), Buffer.from([0, 0x80]), "mpint")
        expect(init.serialize().toString("hex")).toBe("1e0000000101000000020080")
        expect(KexGSSAPIInit.parse(init.serialize(), "mpint")).toEqual(init)

        const complete = new KexGSSAPIComplete(
            Buffer.from([4]),
            Buffer.from("aabb", "hex"),
            Buffer.from([0xcc]),
            "string",
        )
        expect(complete.serialize().toString("hex")).toBe("20000000010400000002aabb0100000001cc")
        expect(KexGSSAPIComplete.parse(complete.serialize(), "string")).toEqual(complete)

        const withoutToken = new KexGSSAPIComplete(
            Buffer.from([4]),
            Buffer.from([5]),
            undefined,
            "string",
        )
        expect(withoutToken.serialize().toString("hex")).toBe("200000000104000000010500")
        expect(KexGSSAPIComplete.parse(withoutToken.serialize(), "string")).toEqual(withoutToken)
    })

    test("matches fixed host-key and diagnostic packets", () => {
        const hostKey = new KexGSSAPIHostKey(Buffer.from("key"))
        expect(hostKey.serialize().toString("hex")).toBe("21000000036b6579")
        expect(KexGSSAPIHostKey.parse(hostKey.serialize())).toEqual(hostKey)

        const error = new KexGSSAPIError({
            majorStatus: 1,
            minorStatus: 2,
            message: "bad",
            languageTag: "en",
        })
        expect(error.serialize().toString("hex")).toBe(
            "2200000001000000020000000362616400000002656e",
        )
        expect(KexGSSAPIError.parse(error.serialize())).toEqual(error)
    })

    test("rejects empty, non-canonical, and trailing fields", () => {
        expect(() => new KexGSSAPIContinue(Buffer.alloc(0))).toThrow("non-empty buffer")
        expect(() =>
            KexGSSAPIInit.parse(Buffer.from("1e0000000101000000020002", "hex"), "mpint"),
        ).toThrow("Non-canonical mpint")
        const valid = new KexGSSAPIComplete(
            Buffer.from([4]),
            Buffer.from([5]),
            undefined,
            "string",
        ).serialize()
        expect(() =>
            KexGSSAPIComplete.parse(Buffer.concat([valid, Buffer.from([0])]), "string"),
        ).toThrow("Unexpected GSS-API key-exchange completion data")
    })
})
