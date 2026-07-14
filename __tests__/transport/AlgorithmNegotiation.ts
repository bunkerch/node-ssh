import { chooseAlgorithms, describeNegotiatedAlgorithms } from "../../src/algorithms.js"
import Client from "../../src/Client.js"
import KexInit, { type KexInitData } from "../../src/packets/KexInit.js"
import {
    resolveClientAlgorithmOptions,
    resolveServerAlgorithmOptions,
} from "../../src/AlgorithmOptions.js"

function offer(overrides: Partial<KexInitData>): KexInit {
    return new KexInit({
        cookie: Buffer.alloc(16, 0x5a),
        kex_algorithms: ["diffie-hellman-group14-sha256"],
        server_host_key_algorithms: ["ssh-ed25519"],
        encryption_algorithms_client_to_server: ["aes128-ctr"],
        encryption_algorithms_server_to_client: ["aes128-ctr"],
        mac_algorithms_client_to_server: ["hmac-sha2-256"],
        mac_algorithms_server_to_client: ["hmac-sha2-256"],
        compression_algorithms_client_to_server: ["none"],
        compression_algorithms_server_to_client: ["none"],
        languages_client_to_server: [],
        languages_server_to_client: [],
        first_kex_packet_follows: false,
        ...overrides,
    })
}

describe("RFC 4253 algorithm negotiation", () => {
    test("resolves exact and ordered modifier lists without changing defaults", () => {
        const catalog = {
            kex: ["kex-a", "kex-b"],
            serverHostKey: ["key-a"],
            cipher: ["aes128-ctr", "aes192-ctr", "aes256-ctr"],
            hmac: ["mac-a"],
            compress: ["none"],
        }
        const resolved = resolveClientAlgorithmOptions(
            {
                kex: ["kex-b"],
                cipher: {
                    remove: [/^aes(?:192|256)-ctr$/u],
                    prepend: ["aes256-ctr"],
                },
            },
            catalog,
        )

        expect(resolved.kex).toEqual(["kex-b"])
        expect(resolved.cipher).toEqual(["aes256-ctr", "aes128-ctr"])
        expect(catalog.kex).toEqual(["kex-a", "kex-b"])
        expect(catalog.cipher).toEqual(["aes128-ctr", "aes192-ctr", "aes256-ctr"])
        expect(() => resolveClientAlgorithmOptions({ hmac: ["unknown-mac"] }, catalog)).toThrow(
            "Unsupported algorithm: unknown-mac",
        )
        expect(() =>
            resolveClientAlgorithmOptions({ hmac: { append: "unknown-mac" } }, catalog),
        ).toThrow("Unsupported algorithm: unknown-mac")
        expect(() => resolveClientAlgorithmOptions({ cipher: /aes/u } as never, catalog)).toThrow(
            "modifiers must be an object",
        )
        expect(() =>
            resolveClientAlgorithmOptions({ cipher: new Date() } as never, catalog),
        ).toThrow("modifiers must be an object")
        expect(() =>
            resolveClientAlgorithmOptions({ cipher: { append: [42] } } as never, catalog),
        ).toThrow("matchers must be strings or regular expressions")
        expect(() => resolveClientAlgorithmOptions({ cipher: { remove: "" } }, catalog)).toThrow(
            "matcher strings must not be empty",
        )
        expect(() => resolveServerAlgorithmOptions({ cipher: null } as never, catalog)).toThrow(
            "exact algorithm configuration must be an array",
        )

        expect(
            resolveClientAlgorithmOptions(
                { cipher: { append: [/^legacy-/gu] } },
                {
                    ...catalog,
                    cipher: [...catalog.cipher, "legacy-one", "legacy-two"],
                },
                catalog,
            ).cipher,
        ).toEqual(["aes128-ctr", "aes192-ctr", "aes256-ctr", "legacy-one", "legacy-two"])
    })

    test("keeps legacy algorithms supported but outside the default offer", () => {
        const catalog = {
            kex: ["modern-kex", "legacy-kex"],
            serverHostKey: ["modern-key", "legacy-key"],
            cipher: ["modern-cipher", "legacy-cipher"],
            hmac: ["modern-mac", "legacy-mac"],
            compress: ["none"],
        }
        const defaults = {
            kex: ["modern-kex"],
            serverHostKey: ["modern-key"],
            cipher: ["modern-cipher"],
            hmac: ["modern-mac"],
            compress: ["none"],
        }
        expect(resolveClientAlgorithmOptions(undefined, catalog, defaults)).toEqual(defaults)
        expect(resolveServerAlgorithmOptions(undefined, catalog, defaults)).toEqual(defaults)
        expect(
            resolveClientAlgorithmOptions(
                {
                    kex: { append: "legacy-kex" },
                    serverHostKey: { append: "legacy-key" },
                    cipher: { append: "legacy-cipher" },
                    hmac: { append: "legacy-mac" },
                },
                catalog,
                defaults,
            ),
        ).toEqual({
            kex: ["modern-kex", "legacy-kex"],
            serverHostKey: ["modern-key", "legacy-key"],
            cipher: ["modern-cipher", "legacy-cipher"],
            hmac: ["modern-mac", "legacy-mac"],
            compress: ["none"],
        })
        expect(
            resolveClientAlgorithmOptions({ serverHostKey: ["legacy-key"] }, catalog, defaults)
                .serverHostKey,
        ).toEqual(["legacy-key"])
        expect(
            resolveServerAlgorithmOptions({ serverHostKey: ["legacy-key"] }, catalog, defaults)
                .serverHostKey,
        ).toEqual(["legacy-key"])
        expect(() => resolveClientAlgorithmOptions({ cipher: [] }, catalog, defaults)).toThrow(
            "must not be empty",
        )
        expect(() =>
            resolveClientAlgorithmOptions(
                { cipher: { unsupported: "legacy-cipher" } } as never,
                catalog,
                defaults,
            ),
        ).toThrow("Invalid SSH algorithm list operation")

        const standardClient = new Client({ hostname: "unused.invalid" })
        expect(standardClient.algorithmOffer.kex.slice(0, 8)).toEqual([
            "mlkem768x25519-sha256",
            "mlkem768nistp256-sha256",
            "mlkem1024nistp384-sha384",
            "sntrup761x25519-sha512",
            "sntrup761x25519-sha512@openssh.com",
            "curve25519-sha256",
            "curve25519-sha256@libssh.org",
            "curve448-sha512",
        ])
        expect(standardClient.algorithmOffer.serverHostKey).not.toContain("ssh-dss")
        expect(standardClient.algorithmOffer.serverHostKey).not.toContain("ssh-rsa")
        expect(standardClient.algorithmOffer.kex).not.toContain("diffie-hellman-group1-sha1")
        expect(standardClient.algorithmOffer.cipher).not.toContain("aes128-cbc")
        expect(standardClient.algorithmOffer.hmac).not.toContain("hmac-md5")
        expect(standardClient.algorithmOffer.hmac).not.toContain("hmac-ripemd160")
        expect(standardClient.algorithmOffer.hmac.slice(0, 2)).toEqual([
            "umac-128-etm@openssh.com",
            "umac-64-etm@openssh.com",
        ])
        const legacyClient = new Client({
            hostname: "unused.invalid",
            algorithms: {
                serverHostKey: { append: "ssh-dss" },
                hmac: { append: "hmac-ripemd160" },
            },
        })
        expect(legacyClient.algorithmOffer.serverHostKey.at(-1)).toBe("ssh-dss")
        expect(legacyClient.algorithmOffer.hmac.at(-1)).toBe("hmac-ripemd160")
    })

    test("selects the first client-preferred mutual algorithm in every direction", () => {
        const client = new Client({ hostname: "unused.invalid" })
        client.clientKexInit = offer({
            kex_algorithms: ["diffie-hellman-group14-sha256", "diffie-hellman-group16-sha512"],
            server_host_key_algorithms: ["ssh-rsa", "ssh-ed25519"],
            encryption_algorithms_client_to_server: ["aes128-ctr", "aes256-ctr"],
            encryption_algorithms_server_to_client: ["aes192-ctr", "aes256-ctr"],
            mac_algorithms_client_to_server: ["hmac-sha1", "hmac-sha2-256"],
            mac_algorithms_server_to_client: ["hmac-sha2-256", "hmac-sha1"],
            compression_algorithms_client_to_server: ["zlib", "none"],
            compression_algorithms_server_to_client: ["zlib@openssh.com", "none"],
        })
        client.serverKexInit = offer({
            kex_algorithms: ["diffie-hellman-group16-sha512", "diffie-hellman-group14-sha256"],
            server_host_key_algorithms: ["ssh-ed25519", "ssh-rsa"],
            encryption_algorithms_client_to_server: ["aes256-ctr", "aes128-ctr"],
            encryption_algorithms_server_to_client: ["aes256-ctr", "aes192-ctr"],
            mac_algorithms_client_to_server: ["hmac-sha2-256", "hmac-sha1"],
            mac_algorithms_server_to_client: ["hmac-sha1", "hmac-sha2-256"],
            compression_algorithms_client_to_server: ["none", "zlib"],
            compression_algorithms_server_to_client: ["none", "zlib@openssh.com"],
        })

        chooseAlgorithms(client)

        expect(client.kexAlgorithm?.constructor).toHaveProperty(
            "alg_name",
            "diffie-hellman-group14-sha256",
        )
        expect(client.hostKeyAlgorithm?.alg_name).toBe("ssh-rsa")
        expect(client.clientEncryptionAlgorithm?.alg_name).toBe("aes128-ctr")
        expect(client.serverEncryptionAlgorithm?.alg_name).toBe("aes192-ctr")
        expect(client.clientMacAlgorithm?.alg_name).toBe("hmac-sha1")
        expect(client.serverMacAlgorithm?.alg_name).toBe("hmac-sha2-256")
        expect(client.clientCompressionAlgorithm?.alg_name).toBe("zlib")
        expect(client.serverCompressionAlgorithm?.alg_name).toBe("zlib@openssh.com")
    })

    test("treats the MAC as implicit when AEAD ciphers are negotiated", () => {
        const client = new Client({ hostname: "unused.invalid" })
        client.clientKexInit = offer({
            encryption_algorithms_client_to_server: ["chacha20-poly1305@openssh.com"],
            encryption_algorithms_server_to_client: ["aes256-gcm@openssh.com"],
            mac_algorithms_client_to_server: ["client-only-mac@example.test"],
            mac_algorithms_server_to_client: ["client-only-mac@example.test"],
        })
        client.serverKexInit = offer({
            encryption_algorithms_client_to_server: ["chacha20-poly1305@openssh.com"],
            encryption_algorithms_server_to_client: ["aes256-gcm@openssh.com"],
            mac_algorithms_client_to_server: ["server-only-mac@example.test"],
            mac_algorithms_server_to_client: ["server-only-mac@example.test"],
        })

        chooseAlgorithms(client)

        expect(client.clientEncryptionAlgorithm?.alg_name).toBe("chacha20-poly1305@openssh.com")
        expect(client.serverEncryptionAlgorithm?.alg_name).toBe("aes256-gcm@openssh.com")
        expect(client.clientMacAlgorithm).toBeUndefined()
        expect(client.serverMacAlgorithm).toBeUndefined()
    })

    test("requires the matching RFC 5647 MAC name for standard AES-GCM", () => {
        const client = new Client({ hostname: "unused.invalid" })
        client.clientKexInit = offer({
            encryption_algorithms_client_to_server: ["AEAD_AES_128_GCM", "aes128-ctr"],
            encryption_algorithms_server_to_client: ["AEAD_AES_256_GCM", "aes128-ctr"],
            mac_algorithms_client_to_server: ["AEAD_AES_128_GCM", "hmac-sha2-256"],
            mac_algorithms_server_to_client: ["AEAD_AES_256_GCM", "hmac-sha2-256"],
        })
        client.serverKexInit = offer({
            encryption_algorithms_client_to_server: ["AEAD_AES_128_GCM", "aes128-ctr"],
            encryption_algorithms_server_to_client: ["AEAD_AES_256_GCM", "aes128-ctr"],
            mac_algorithms_client_to_server: ["AEAD_AES_128_GCM", "hmac-sha2-256"],
            mac_algorithms_server_to_client: ["AEAD_AES_256_GCM", "hmac-sha2-256"],
        })

        chooseAlgorithms(client)

        expect(client.clientEncryptionAlgorithm?.alg_name).toBe("AEAD_AES_128_GCM")
        expect(client.serverEncryptionAlgorithm?.alg_name).toBe("AEAD_AES_256_GCM")
        expect(client.clientMacAlgorithm).toBeUndefined()
        expect(client.serverMacAlgorithm).toBeUndefined()
        expect(describeNegotiatedAlgorithms(client).cs.mac).toBe("AEAD_AES_128_GCM")
        expect(describeNegotiatedAlgorithms(client).sc.mac).toBe("AEAD_AES_256_GCM")
    })

    test("rejects inconsistent RFC 5647 cipher and MAC selections", () => {
        const client = new Client({ hostname: "unused.invalid" })
        client.clientKexInit = offer({
            encryption_algorithms_client_to_server: ["AEAD_AES_128_GCM", "aes128-ctr"],
            mac_algorithms_client_to_server: ["hmac-sha2-256", "AEAD_AES_128_GCM"],
        })
        client.serverKexInit = offer({
            encryption_algorithms_client_to_server: ["AEAD_AES_128_GCM", "aes128-ctr"],
            mac_algorithms_client_to_server: ["hmac-sha2-256", "AEAD_AES_128_GCM"],
        })

        expect(() => chooseAlgorithms(client)).toThrow(
            "AEAD_AES_128_GCM requires AEAD_AES_128_GCM as the client to server MAC algorithm",
        )

        client.clientKexInit = offer({
            encryption_algorithms_client_to_server: ["aes128-ctr"],
            mac_algorithms_client_to_server: ["AEAD_AES_128_GCM", "hmac-sha2-256"],
        })
        client.serverKexInit = offer({
            encryption_algorithms_client_to_server: ["aes128-ctr"],
            mac_algorithms_client_to_server: ["AEAD_AES_128_GCM", "hmac-sha2-256"],
        })
        expect(() => chooseAlgorithms(client)).toThrow(
            "AEAD_AES_128_GCM may only be selected with the same RFC 5647 encryption algorithm",
        )
    })

    test("clears a prior selection before rejecting a later exchange with no overlap", () => {
        const client = new Client({ hostname: "unused.invalid" })
        client.clientKexInit = offer({})
        client.serverKexInit = offer({})
        chooseAlgorithms(client)
        expect(client.kexAlgorithm).toBeDefined()

        client.serverKexInit = offer({ kex_algorithms: ["unsupported-kex@example.test"] })
        expect(() => chooseAlgorithms(client)).toThrow("No key exchange algorithm found")
        expect(client.kexAlgorithm).toBeUndefined()
        expect(client.hostKeyAlgorithm).toBeUndefined()
        expect(client.clientCompressionAlgorithm).toBeUndefined()
        expect(client.serverCompressionAlgorithm).toBeUndefined()
    })

    test("rejects missing compression overlap independently in each direction", () => {
        const client = new Client({ hostname: "unused.invalid" })
        client.clientKexInit = offer({})
        client.serverKexInit = offer({
            compression_algorithms_server_to_client: ["unsupported-compression@example.test"],
        })

        expect(() => chooseAlgorithms(client)).toThrow(
            "No server to client compression algorithm found",
        )
        expect(client.clientCompressionAlgorithm?.alg_name).toBe("none")
        expect(client.serverCompressionAlgorithm).toBeUndefined()
    })

    test("negotiates an RSA SHA-2 signature while retaining the ssh-rsa key format", () => {
        const client = new Client({ hostname: "unused.invalid" })
        client.clientKexInit = offer({
            server_host_key_algorithms: ["rsa-sha2-512", "rsa-sha2-256"],
        })
        client.serverKexInit = offer({
            server_host_key_algorithms: ["rsa-sha2-256", "rsa-sha2-512"],
        })

        chooseAlgorithms(client)

        expect(client.hostKeyAlgorithm).toEqual({
            alg_name: "rsa-sha2-512",
            key_format: "ssh-rsa",
            signature_algorithm: "rsa-sha2-512",
            has_encryption: false,
            has_signature: true,
        })
    })
})
