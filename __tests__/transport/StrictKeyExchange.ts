import { PacketNameToType } from "../../src/constants.js"
import {
    isStrictKeyExchangePacket,
    negotiatesStrictKeyExchange,
    STRICT_KEX_CLIENT_MARKERS,
    STRICT_KEX_SERVER_MARKERS,
} from "../../src/StrictKeyExchange.js"

describe("strict key exchange negotiation", () => {
    test("negotiates only matching standard or legacy marker pairs", () => {
        expect(negotiatesStrictKeyExchange(["kex-strict-c"], ["kex-strict-s"])).toBeTrue()
        expect(
            negotiatesStrictKeyExchange(
                ["kex-strict-c-v00@openssh.com"],
                ["kex-strict-s-v00@openssh.com"],
            ),
        ).toBeTrue()
        expect(
            negotiatesStrictKeyExchange(["kex-strict-c"], ["kex-strict-s-v00@openssh.com"]),
        ).toBeFalse()
        expect(negotiatesStrictKeyExchange([], [])).toBeFalse()
    })

    test("advertises standard and deployed markers without treating them as KEX methods", () => {
        expect(STRICT_KEX_CLIENT_MARKERS).toEqual(["kex-strict-c", "kex-strict-c-v00@openssh.com"])
        expect(STRICT_KEX_SERVER_MARKERS).toEqual(["kex-strict-s", "kex-strict-s-v00@openssh.com"])
    })

    test("permits only transport key-exchange packet numbers", () => {
        for (const type of [20, 21, 30, 31, 32, 33, 34]) {
            expect(isStrictKeyExchangePacket(type)).toBeTrue()
        }
        for (const type of [PacketNameToType.SSH_MSG_IGNORE, 7, 29, 35, 50]) {
            expect(isStrictKeyExchangePacket(type)).toBeFalse()
        }
    })
})
