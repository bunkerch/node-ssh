import { chooseAlgorithms } from "../../src/algorithms.js"
import Client from "../../src/Client.js"
import KexInit, { type KexInitData } from "../../src/packets/KexInit.js"
import { resolveClientAlgorithmOptions } from "../../src/AlgorithmOptions.js"

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
        })
        client.serverKexInit = offer({
            kex_algorithms: ["diffie-hellman-group16-sha512", "diffie-hellman-group14-sha256"],
            server_host_key_algorithms: ["ssh-ed25519", "ssh-rsa"],
            encryption_algorithms_client_to_server: ["aes256-ctr", "aes128-ctr"],
            encryption_algorithms_server_to_client: ["aes256-ctr", "aes192-ctr"],
            mac_algorithms_client_to_server: ["hmac-sha2-256", "hmac-sha1"],
            mac_algorithms_server_to_client: ["hmac-sha1", "hmac-sha2-256"],
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
    })

    test("treats the MAC as implicit when AES-GCM is negotiated", () => {
        const client = new Client({ hostname: "unused.invalid" })
        client.clientKexInit = offer({
            encryption_algorithms_client_to_server: ["aes128-gcm@openssh.com"],
            encryption_algorithms_server_to_client: ["aes256-gcm@openssh.com"],
            mac_algorithms_client_to_server: ["client-only-mac@example.test"],
            mac_algorithms_server_to_client: ["client-only-mac@example.test"],
        })
        client.serverKexInit = offer({
            encryption_algorithms_client_to_server: ["aes128-gcm@openssh.com"],
            encryption_algorithms_server_to_client: ["aes256-gcm@openssh.com"],
            mac_algorithms_client_to_server: ["server-only-mac@example.test"],
            mac_algorithms_server_to_client: ["server-only-mac@example.test"],
        })

        chooseAlgorithms(client)

        expect(client.clientEncryptionAlgorithm?.alg_name).toBe("aes128-gcm@openssh.com")
        expect(client.serverEncryptionAlgorithm?.alg_name).toBe("aes256-gcm@openssh.com")
        expect(client.clientMacAlgorithm).toBeUndefined()
        expect(client.serverMacAlgorithm).toBeUndefined()
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
