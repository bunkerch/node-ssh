import { expect, test } from "bun:test"

import Client from "../../src/Client.js"
import { default_algorithm_names, encryption_algorithms } from "../../src/algorithms.js"

test.each(["arcfour", "arcfour128", "arcfour256"])(
    "RFC 8758 prohibits the %s cipher even through explicit configuration",
    (cipher) => {
        expect(encryption_algorithms.has(cipher)).toBe(false)
        expect(default_algorithm_names.cipher).not.toContain(cipher)
        expect(
            () =>
                new Client({
                    hostname: "unused.invalid",
                    algorithms: { cipher: [cipher] },
                }),
        ).toThrow(`Unsupported algorithm: ${cipher}`)
    },
)
