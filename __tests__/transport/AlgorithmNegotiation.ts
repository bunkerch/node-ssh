import {
    chooseAlgorithms,
    default_algorithm_names,
    describeNegotiatedAlgorithms,
    kex_algorithms,
    mac_algorithms,
} from "../../src/algorithms.js"
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

function select(clientOffer: KexInit, serverOffer: KexInit) {
    return chooseAlgorithms({
        clientOffer: clientOffer.data,
        serverOffer: serverOffer.data,
        keyExchanges: kex_algorithms,
    })
}

describe("RFC 4253 algorithm negotiation", () => {
    test("keeps historical truncated SHA-2 MAC names available only by explicit configuration", () => {
        expect(mac_algorithms.has("hmac-sha2-256-96")).toBe(true)
        expect(mac_algorithms.has("hmac-sha2-512-96")).toBe(true)
        expect(default_algorithm_names.hmac).not.toContain("hmac-sha2-256-96")
        expect(default_algorithm_names.hmac).not.toContain("hmac-sha2-512-96")
    })

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
        expect("kexAlgorithms" in standardClient).toBe(false)
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
        expect(standardClient.algorithmOffer.kex).not.toContain("mlkem512-sha256")
        expect(standardClient.algorithmOffer.cipher).not.toContain("aes128-cbc")
        expect(standardClient.algorithmOffer.cipher).not.toContain("blowfish-cbc")
        expect(standardClient.algorithmOffer.cipher).not.toContain("cast128-cbc")
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
                cipher: { append: ["blowfish-cbc", "cast128-cbc"] },
                hmac: { append: "hmac-ripemd160" },
            },
        })
        expect(legacyClient.algorithmOffer.serverHostKey.at(-1)).toBe("ssh-dss")
        expect(legacyClient.algorithmOffer.cipher.slice(-2)).toEqual([
            "blowfish-cbc",
            "cast128-cbc",
        ])
        expect(legacyClient.algorithmOffer.hmac.at(-1)).toBe("hmac-ripemd160")

        const standaloneMLKEM = new Client({
            hostname: "unused.invalid",
            algorithms: {
                kex: ["mlkem512-sha256", "mlkem768-sha256", "mlkem1024-sha384"],
            },
        })
        expect(standaloneMLKEM.algorithmOffer.kex).toEqual([
            "mlkem512-sha256",
            "mlkem768-sha256",
            "mlkem1024-sha384",
        ])
    })

    test("selects the first client-preferred mutual algorithm in every direction", () => {
        const clientOffer = offer({
            kex_algorithms: ["diffie-hellman-group14-sha256", "diffie-hellman-group16-sha512"],
            server_host_key_algorithms: ["ssh-rsa", "ssh-ed25519"],
            encryption_algorithms_client_to_server: ["aes128-ctr", "aes256-ctr"],
            encryption_algorithms_server_to_client: ["aes192-ctr", "aes256-ctr"],
            mac_algorithms_client_to_server: ["hmac-sha1", "hmac-sha2-256"],
            mac_algorithms_server_to_client: ["hmac-sha2-256", "hmac-sha1"],
            compression_algorithms_client_to_server: ["zlib", "none"],
            compression_algorithms_server_to_client: ["zlib@openssh.com", "none"],
        })
        const serverOffer = offer({
            kex_algorithms: ["diffie-hellman-group16-sha512", "diffie-hellman-group14-sha256"],
            server_host_key_algorithms: ["ssh-ed25519", "ssh-rsa"],
            encryption_algorithms_client_to_server: ["aes256-ctr", "aes128-ctr"],
            encryption_algorithms_server_to_client: ["aes256-ctr", "aes192-ctr"],
            mac_algorithms_client_to_server: ["hmac-sha2-256", "hmac-sha1"],
            mac_algorithms_server_to_client: ["hmac-sha1", "hmac-sha2-256"],
            compression_algorithms_client_to_server: ["none", "zlib"],
            compression_algorithms_server_to_client: ["none", "zlib@openssh.com"],
        })

        const algorithms = select(clientOffer, serverOffer)

        expect(algorithms.keyExchange.constructor).toHaveProperty(
            "alg_name",
            "diffie-hellman-group14-sha256",
        )
        expect(algorithms.hostKey.alg_name).toBe("ssh-rsa")
        expect(algorithms.clientEncryption.alg_name).toBe("aes128-ctr")
        expect(algorithms.serverEncryption.alg_name).toBe("aes192-ctr")
        expect(algorithms.clientMac?.alg_name).toBe("hmac-sha1")
        expect(algorithms.serverMac?.alg_name).toBe("hmac-sha2-256")
        expect(algorithms.clientCompression.alg_name).toBe("zlib")
        expect(algorithms.serverCompression.alg_name).toBe("zlib@openssh.com")
    })

    test("treats the MAC as implicit when AEAD ciphers are negotiated", () => {
        const clientOffer = offer({
            encryption_algorithms_client_to_server: ["chacha20-poly1305@openssh.com"],
            encryption_algorithms_server_to_client: ["aes256-gcm@openssh.com"],
            mac_algorithms_client_to_server: ["client-only-mac@example.test"],
            mac_algorithms_server_to_client: ["client-only-mac@example.test"],
        })
        const serverOffer = offer({
            encryption_algorithms_client_to_server: ["chacha20-poly1305@openssh.com"],
            encryption_algorithms_server_to_client: ["aes256-gcm@openssh.com"],
            mac_algorithms_client_to_server: ["server-only-mac@example.test"],
            mac_algorithms_server_to_client: ["server-only-mac@example.test"],
        })

        const algorithms = select(clientOffer, serverOffer)

        expect(algorithms.clientEncryption.alg_name).toBe("chacha20-poly1305@openssh.com")
        expect(algorithms.serverEncryption.alg_name).toBe("aes256-gcm@openssh.com")
        expect(algorithms.clientMac).toBeUndefined()
        expect(algorithms.serverMac).toBeUndefined()
    })

    test("requires the matching RFC 5647 MAC name for standard AES-GCM", () => {
        const clientOffer = offer({
            encryption_algorithms_client_to_server: ["AEAD_AES_128_GCM", "aes128-ctr"],
            encryption_algorithms_server_to_client: ["AEAD_AES_256_GCM", "aes128-ctr"],
            mac_algorithms_client_to_server: ["AEAD_AES_128_GCM", "hmac-sha2-256"],
            mac_algorithms_server_to_client: ["AEAD_AES_256_GCM", "hmac-sha2-256"],
        })
        const serverOffer = offer({
            encryption_algorithms_client_to_server: ["AEAD_AES_128_GCM", "aes128-ctr"],
            encryption_algorithms_server_to_client: ["AEAD_AES_256_GCM", "aes128-ctr"],
            mac_algorithms_client_to_server: ["AEAD_AES_128_GCM", "hmac-sha2-256"],
            mac_algorithms_server_to_client: ["AEAD_AES_256_GCM", "hmac-sha2-256"],
        })

        const algorithms = select(clientOffer, serverOffer)

        expect(algorithms.clientEncryption.alg_name).toBe("AEAD_AES_128_GCM")
        expect(algorithms.serverEncryption.alg_name).toBe("AEAD_AES_256_GCM")
        expect(algorithms.clientMac).toBeUndefined()
        expect(algorithms.serverMac).toBeUndefined()
        expect(describeNegotiatedAlgorithms(algorithms).cs.mac).toBe("AEAD_AES_128_GCM")
        expect(describeNegotiatedAlgorithms(algorithms).sc.mac).toBe("AEAD_AES_256_GCM")
    })

    test("rejects inconsistent RFC 5647 cipher and MAC selections", () => {
        let clientOffer = offer({
            encryption_algorithms_client_to_server: ["AEAD_AES_128_GCM", "aes128-ctr"],
            mac_algorithms_client_to_server: ["hmac-sha2-256", "AEAD_AES_128_GCM"],
        })
        let serverOffer = offer({
            encryption_algorithms_client_to_server: ["AEAD_AES_128_GCM", "aes128-ctr"],
            mac_algorithms_client_to_server: ["hmac-sha2-256", "AEAD_AES_128_GCM"],
        })

        expect(() => select(clientOffer, serverOffer)).toThrow(
            "AEAD_AES_128_GCM requires AEAD_AES_128_GCM as the client to server MAC algorithm",
        )

        clientOffer = offer({
            encryption_algorithms_client_to_server: ["aes128-ctr"],
            mac_algorithms_client_to_server: ["AEAD_AES_128_GCM", "hmac-sha2-256"],
        })
        serverOffer = offer({
            encryption_algorithms_client_to_server: ["aes128-ctr"],
            mac_algorithms_client_to_server: ["AEAD_AES_128_GCM", "hmac-sha2-256"],
        })
        expect(() => select(clientOffer, serverOffer)).toThrow(
            "AEAD_AES_128_GCM may only be selected with the same RFC 5647 encryption algorithm",
        )
    })

    test("does not partially install a selection when a later exchange has no overlap", () => {
        const clientOffer = offer({})
        let serverOffer = offer({})
        const first = select(clientOffer, serverOffer)
        expect(first.keyExchange).toBeDefined()

        serverOffer = offer({ kex_algorithms: ["unsupported-kex@example.test"] })
        expect(() => select(clientOffer, serverOffer)).toThrow("No key exchange algorithm found")
    })

    test("rejects missing compression overlap independently in each direction", () => {
        const clientOffer = offer({})
        const serverOffer = offer({
            compression_algorithms_server_to_client: ["unsupported-compression@example.test"],
        })

        expect(() => select(clientOffer, serverOffer)).toThrow(
            "No server to client compression algorithm found",
        )
    })

    test("negotiates an RSA SHA-2 signature while retaining the ssh-rsa key format", () => {
        const clientOffer = offer({
            server_host_key_algorithms: ["rsa-sha2-512", "rsa-sha2-256"],
        })
        const serverOffer = offer({
            server_host_key_algorithms: ["rsa-sha2-256", "rsa-sha2-512"],
        })

        const algorithms = select(clientOffer, serverOffer)

        expect(algorithms.hostKey).toEqual({
            alg_name: "rsa-sha2-512",
            key_format: "ssh-rsa",
            signature_algorithm: "rsa-sha2-512",
            has_encryption: false,
            has_signature: true,
        })
    })
})
