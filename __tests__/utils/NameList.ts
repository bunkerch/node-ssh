import { readNextNameList, serializeNameList } from "../../src/utils/NameList.js"
import { decodeSSHName, encodeSSHName, validateSSHName } from "../../src/utils/SSHName.js"

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

        test("enforces RFC 4250 name boundaries and extension domains", () => {
            const longest = "a".repeat(64)
            expect(encodeSSHName(longest)).toEqual(Buffer.from(longest, "ascii"))
            expect(decodeSSHName(Buffer.from("feature@example.com"))).toBe("feature@example.com")
            expect(() => validateSSHName("")).toThrow("1 to 64")
            expect(() => validateSSHName("a".repeat(65))).toThrow("1 to 64")
            expect(() => validateSSHName("two,names")).toThrow("comma")
            expect(() => validateSSHName("white space")).toThrow("printable")
            expect(() => validateSSHName("méthod")).toThrow("printable")
            expect(() => validateSSHName("a@b@example.com")).toThrow("at-sign")
            expect(() => validateSSHName("feature@-example.com")).toThrow("domain")
            expect(() => decodeSSHName(Buffer.from([0xff]))).toThrow("US-ASCII")
        })

        test("rejects empty, duplicate, and malformed name-list entries", () => {
            expect(() => readNextNameList(Buffer.from("00000003612c61", "hex"))).toThrow(
                "duplicate",
            )
            expect(() => readNextNameList(Buffer.from("00000002612c", "hex"))).toThrow("1 to 64")
            expect(() => serializeNameList(["a", "a"])).toThrow("duplicate")
            expect(() => serializeNameList(["invalid name"])).toThrow("printable")
        })
    })
})
