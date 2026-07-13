import HMACSHA2512 from "../../src/algorithms/mac/hmac-sha2-512.js"

describe("RFC 6668 SSH MACs", () => {
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
})
