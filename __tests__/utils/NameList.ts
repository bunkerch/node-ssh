import { readNextNameList, serializeNameList } from "../../src/utils/NameList.js"

describe("Utils", () => {
    describe("NameList", () => {
        test("should be parseable", () => {
            expect(readNextNameList(Buffer.from("00000005612c622c63deadbeef", "hex"))).toEqual([
                ["a", "b", "c"],
                Buffer.from("deadbeef", "hex"),
            ])
        })

        test("should serialize", () => {
            expect(serializeNameList(["a", "b", "c"]).toString("hex")).toEqual("00000005612c622c63")
        })
    })
})
