import { describe, expect, test } from "bun:test"

import Client from "../../src/Client.js"
import { default_algorithm_names, kex_algorithms } from "../../src/algorithms.js"
import { KERBEROS_V5_GSSAPI_OID } from "../../src/GSSAPI.js"

type Exposure = "default" | "opt-in" | "absent"

const fixedMethodPolicy: readonly [name: string, guidance: string, exposure: Exposure][] = [
    ["curve25519-sha256", "SHOULD", "default"],
    ["curve448-sha512", "MAY", "default"],
    ["diffie-hellman-group-exchange-sha1", "SHOULD NOT", "opt-in"],
    ["diffie-hellman-group-exchange-sha256", "MAY", "default"],
    ["diffie-hellman-group1-sha1", "SHOULD NOT", "opt-in"],
    ["diffie-hellman-group14-sha1", "MAY", "opt-in"],
    ["diffie-hellman-group14-sha256", "MUST", "default"],
    ["diffie-hellman-group15-sha512", "MAY", "default"],
    ["diffie-hellman-group16-sha512", "SHOULD", "default"],
    ["diffie-hellman-group17-sha512", "MAY", "default"],
    ["diffie-hellman-group18-sha512", "MAY", "default"],
    ["ecdh-sha2-nistp256", "SHOULD", "default"],
    ["ecdh-sha2-nistp384", "SHOULD", "default"],
    ["ecdh-sha2-nistp521", "SHOULD", "default"],
    ["ecmqv-sha2", "MAY", "absent"],
    ["rsa1024-sha1", "MUST NOT", "absent"],
    ["rsa2048-sha256", "MAY", "opt-in"],
]

describe("RFC 9142 key-exchange policy", () => {
    test.each(fixedMethodPolicy)("exposes %s (%s) as %s", (name, _guidance, exposure) => {
        const supported = kex_algorithms.has(name)
        const enabledByDefault = default_algorithm_names.kex.includes(name)

        expect(supported).toBe(exposure !== "absent")
        expect(enabledByDefault).toBe(exposure === "default")
    })

    test("rejects the MUST-NOT RSA-1024 method through explicit configuration", () => {
        expect(
            () =>
                new Client({
                    hostname: "unused.invalid",
                    username: "test",
                    algorithms: { kex: ["rsa1024-sha1"] },
                }),
        ).toThrow("Unsupported algorithm: rsa1024-sha1")
    })

    test("offers every implemented RFC 8732 family for a configured GSS mechanism", () => {
        const client = new Client({
            hostname: "unused.invalid",
            username: "test",
            gssapi: [
                {
                    oid: KERBEROS_V5_GSSAPI_OID,
                    createKeyExchangeContext: () => {
                        throw new Error("context creation is outside this catalog test")
                    },
                },
            ],
        })
        const offered = client.algorithmOffer.kex
        const enabledPrefixes = [
            "gss-curve25519-sha256-",
            "gss-nistp256-sha256-",
            "gss-nistp384-sha384-",
            "gss-nistp521-sha512-",
            "gss-curve448-sha512-",
            "gss-group16-sha512-",
            "gss-group14-sha256-",
            "gss-group18-sha512-",
            "gss-group17-sha512-",
            "gss-group15-sha512-",
        ]
        const deprecatedPrefixes = ["gss-gex-sha1-", "gss-group1-sha1-", "gss-group14-sha1-"]

        for (const prefix of enabledPrefixes) {
            expect(offered.some((name) => name.startsWith(prefix))).toBe(true)
        }
        for (const prefix of deprecatedPrefixes) {
            expect(offered.some((name) => name.startsWith(prefix))).toBe(false)
        }
        expect(offered).not.toContain("gss-")
    })
})
