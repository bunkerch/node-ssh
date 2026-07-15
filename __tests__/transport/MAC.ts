import HMACSHA2256 from "../../src/algorithms/mac/hmac-sha2-256.js"
import HMACSHA2512 from "../../src/algorithms/mac/hmac-sha2-512.js"
import HMACSHA225696 from "../../src/algorithms/mac/hmac-sha2-256-96.js"
import HMACSHA251296 from "../../src/algorithms/mac/hmac-sha2-512-96.js"
import HMACSHA196 from "../../src/algorithms/mac/hmac-sha1-96.js"
import HMACSHA196ETM from "../../src/algorithms/mac/hmac-sha1-96-etm.js"
import HMACMD5 from "../../src/algorithms/mac/hmac-md5.js"
import HMACMD596 from "../../src/algorithms/mac/hmac-md5-96.js"
import HMACMD5ETM from "../../src/algorithms/mac/hmac-md5-etm.js"
import HMACMD596ETM from "../../src/algorithms/mac/hmac-md5-96-etm.js"
import HMACRIPEMD160 from "../../src/algorithms/mac/hmac-ripemd160.js"
import {
    UMAC128ETMOpenSSH,
    UMAC128OpenSSH,
    UMAC64ETMOpenSSH,
    UMAC64OpenSSH,
} from "../../src/algorithms/mac/umac.js"
import { UMAC } from "../../src/utils/UMAC.js"

describe("SSH MAC algorithms", () => {
    test.each([
        [Buffer.alloc(0), "6e155fad26900be1"],
        [Buffer.alloc(3, 0x61), "44b5cb542f220104"],
        [Buffer.alloc(1 << 10, 0x61), "26bf2f5d60118bd9"],
        [Buffer.alloc(1 << 15, 0x61), "27f8ef643b0d118d"],
        [Buffer.alloc(1 << 20, 0x61), "a4477e87e9f55853"],
        // RFC 4418 erratum 3507 corrects the published 32 MiB vector.
        [Buffer.alloc(1 << 25, 0x61), "faca46f856e9b45f"],
        [Buffer.from("abc".repeat(500)), "d4cf26ddefd5c01a"],
    ])("UMAC-64 matches an RFC 4418 vector", (message, expected) => {
        const umac = new UMAC(Buffer.from("abcdefghijklmnop"), 8)
        expect(umac.compute(message, Buffer.from("bcdefghi")).toString("hex")).toBe(expected)
    })

    test("UMAC output iterations match the RFC 4418 32- and 96-bit vectors", () => {
        const key = Buffer.from("abcdefghijklmnop")
        const nonce = Buffer.from("bcdefghi")
        const message = Buffer.from("abc".repeat(500))
        expect(new UMAC(key, 4).compute(message, nonce).toString("hex")).toBe("abeb3c8b")
        expect(new UMAC(key, 12).compute(message, nonce).toString("hex")).toBe(
            "8824a260c53c66a36c9260a6",
        )
    })

    test("SSH UMAC variants use uint64 sequence nonces and declared tag modes", () => {
        const key = Buffer.from("abcdefghijklmnop")
        const packet = Buffer.from("fixed SSH packet")
        const nonce = Buffer.from("0000000012345678", "hex")
        const expected64 = new UMAC(key, 8).compute(packet, nonce)
        const expected128 = new UMAC(key, 16).compute(packet, nonce)

        const ssh64 = new UMAC64OpenSSH(key)
        expect(ssh64.computeMAC(0x12345678, packet)).toEqual(expected64)
        expect(() => ssh64.computeMAC(0x12345678, packet)).toThrow("requires rekeying")
        expect(new UMAC128OpenSSH(key).computeMAC(0x12345678, packet)).toEqual(expected128)
        expect(UMAC64OpenSSH.digest_length).toBe(8)
        expect(UMAC128OpenSSH.digest_length).toBe(16)
        expect(UMAC64ETMOpenSSH.encrypt_then_mac).toBe(true)
        expect(UMAC128ETMOpenSSH.encrypt_then_mac).toBe(true)
    })

    test("hmac-sha2-512 owns its key and matches the RFC 4231 test case", () => {
        const key = Buffer.alloc(20, 0x0b)
        const expected = Buffer.from(
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
            "hex",
        )
        const mac = new HMACSHA2512(key)
        key.fill(0)

        // RFC 4253 authenticates uint32(sequence_number) || packet. Together these fixed inputs
        // form the RFC 4231 message "Hi There" without bypassing the SSH MAC implementation.
        expect(mac.computeMAC(0x4869_2054, Buffer.from("here"))).toEqual(expected)
    })

    test("hmac-sha2-256 owns its key and matches the RFC 4231 test case", () => {
        const key = Buffer.alloc(20, 0x0b)
        const expected = Buffer.from(
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
            "hex",
        )
        const mac = new HMACSHA2256(key)
        key.fill(0)

        // RFC 4253 authenticates uint32(sequence_number) || packet. Together these fixed inputs
        // form the RFC 4231 message "Hi There" without bypassing the SSH MAC implementation.
        expect(mac.computeMAC(0x4869_2054, Buffer.from("here"))).toEqual(expected)
        expect(HMACSHA2256.key_length).toBe(32)
        expect(HMACSHA2256.digest_length).toBe(32)
    })

    test("historical SHA-2-96 names truncate the RFC 4231 results to 12 bytes", () => {
        const key = Buffer.alloc(20, 0x0b)
        const expected256 = Buffer.from("b0344c61d8db38535ca8afce", "hex")
        const expected512 = Buffer.from("87aa7cdea5ef619d4ff0b424", "hex")
        const sha256 = new HMACSHA225696(key)
        const sha512 = new HMACSHA251296(key)
        key.fill(0)

        // uint32(sequence_number) || packet forms RFC 4231's fixed message "Hi There".
        expect(sha256.computeMAC(0x4869_2054, Buffer.from("here"))).toEqual(expected256)
        expect(sha512.computeMAC(0x4869_2054, Buffer.from("here"))).toEqual(expected512)
        expect(HMACSHA225696.key_length).toBe(32)
        expect(HMACSHA251296.key_length).toBe(64)
        expect(HMACSHA225696.digest_length).toBe(12)
        expect(HMACSHA251296.digest_length).toBe(12)
    })

    test("hmac-sha1-96 owns its key and truncates the RFC 2202 vector", () => {
        const key = Buffer.alloc(20, 0x0b)
        const expected = Buffer.from("b617318655057264e28bc0b6", "hex")
        const mac = new HMACSHA196(key)
        key.fill(0)

        // uint32(sequence_number) || packet forms RFC 2202's fixed message "Hi There".
        expect(mac.computeMAC(0x4869_2054, Buffer.from("here"))).toEqual(expected)
        expect(HMACSHA196.digest_length).toBe(12)
        expect(HMACSHA196ETM.digest_length).toBe(12)
        expect(HMACSHA196ETM.encrypt_then_mac).toBe(true)
    })

    test("hmac-md5 variants own their key and match the RFC 2202 vector", () => {
        const key = Buffer.alloc(16, 0x0b)
        const expected = Buffer.from("9294727a3638bb1c13f48ef8158bfc9d", "hex")
        const full = new HMACMD5(key)
        const truncated = new HMACMD596(key)
        key.fill(0)

        // uint32(sequence_number) || packet forms RFC 2202's fixed message "Hi There".
        expect(full.computeMAC(0x4869_2054, Buffer.from("here"))).toEqual(expected)
        expect(truncated.computeMAC(0x4869_2054, Buffer.from("here"))).toEqual(
            expected.subarray(0, 12),
        )
        expect(HMACMD5ETM.encrypt_then_mac).toBe(true)
        expect(HMACMD596ETM.encrypt_then_mac).toBe(true)
    })

    test("hmac-ripemd160 matches the RFC 2286 vector", () => {
        const key = Buffer.alloc(20, 0x0b)
        const expected = Buffer.from("24cb4bd67d20fc1a5d2ed7732dcc39377f0a5668", "hex")
        const mac = new HMACRIPEMD160(key)
        key.fill(0)

        // uint32(sequence_number) || packet forms RFC 2286's fixed message "Hi There".
        expect(mac.computeMAC(0x4869_2054, Buffer.from("here"))).toEqual(expected)
        expect(HMACRIPEMD160.key_length).toBe(20)
        expect(HMACRIPEMD160.digest_length).toBe(20)
        expect(() => new HMACRIPEMD160(Buffer.alloc(19))).toThrow("key must be 20 bytes")
    })
})
