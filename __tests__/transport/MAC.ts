import HMACSHA2512 from "../../src/algorithms/mac/hmac-sha2-512.js"
import HMACSHA196 from "../../src/algorithms/mac/hmac-sha1-96.js"
import HMACSHA196ETM from "../../src/algorithms/mac/hmac-sha1-96-etm.js"

describe("SSH MAC algorithms", () => {
    test("hmac-sha2-512 matches the RFC 4231 test case", () => {
        const key = Buffer.alloc(20, 0x0b)
        const expected = Buffer.from(
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
            "hex",
        )

        // RFC 4253 authenticates uint32(sequence_number) || packet. Together these fixed inputs
        // form the RFC 4231 message "Hi There" without bypassing the SSH MAC implementation.
        expect(new HMACSHA2512(key).computeMAC(0x4869_2054, Buffer.from("here"))).toEqual(expected)
    })

    test("hmac-sha1-96 truncates the RFC 2202 HMAC-SHA1 vector to 96 bits", () => {
        const key = Buffer.alloc(20, 0x0b)
        const expected = Buffer.from("b617318655057264e28bc0b6", "hex")

        // uint32(sequence_number) || packet forms RFC 2202's fixed message "Hi There".
        expect(new HMACSHA196(key).computeMAC(0x4869_2054, Buffer.from("here"))).toEqual(expected)
        expect(HMACSHA196.digest_length).toBe(12)
        expect(HMACSHA196ETM.digest_length).toBe(12)
        expect(HMACSHA196ETM.encrypt_then_mac).toBe(true)
    })
})
