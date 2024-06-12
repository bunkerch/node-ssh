import { readNextNameList, serializeNameList } from "../../src/utils/NameList"

describe("NameList Utils", () => {
    test("Should be parseable", () => {
        expect(readNextNameList(Buffer.from("00000005612c622c63deadbeef", "hex"))).toEqual([
            ["a", "b", "c"],
            Buffer.from("deadbeef", "hex"),
        ])
    })

    test("Should serialize", () => {
        expect(serializeNameList(["a", "b", "c"]).toString("hex")).toEqual("00000005612c622c63")
    })
})
