import PrivateKey, {
    SSHECDSASecurityKeyPrivateKey,
    SSHED25519SecurityKeyPrivateKey,
} from "../../src/utils/PrivateKey.js"
import {
    SSHECDSASecurityKeyPublicKey,
    SSHED25519SecurityKeyPublicKey,
} from "../../src/utils/PublicKey.js"

const ed25519Container = Buffer.from(
    "6f70656e7373682d6b65792d763100" +
        "000000046e6f6e65" +
        "000000046e6f6e65" +
        "00000000" +
        "00000001" +
        "0000004e" +
        "0000001a736b2d7373682d65643235353139406f70656e7373682e636f6d" +
        "00000020d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a" +
        "000000087373683a74657374" +
        "00000080" +
        "1234567812345678" +
        "0000001a736b2d7373682d65643235353139406f70656e7373682e636f6d" +
        "00000020d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a" +
        "000000087373683a74657374" +
        "01" +
        "000000080102030405060708" +
        "00000000" +
        "0000001473656375726974792d6b65792066697874757265" +
        "01",
    "hex",
)
const ecdsaContainer = Buffer.from(
    "6f70656e7373682d6b65792d763100" +
        "000000046e6f6e65000000046e6f6e650000000000000001" +
        "00000083" +
        "00000022736b2d65636473612d736861322d6e69737470323536406f70656e7373682e636f6d" +
        "000000086e69737470323536" +
        "000000410460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6" +
        "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299" +
        "000000087373683a74657374" +
        "000000b8" +
        "90abcdef90abcdef" +
        "00000022736b2d65636473612d736861322d6e69737470323536406f70656e7373682e636f6d" +
        "000000086e69737470323536" +
        "000000410460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6" +
        "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299" +
        "000000087373683a74657374" +
        "05" +
        "00000006a1a2a3a4a5a6" +
        "000000087265736572766564" +
        "000000126563647361207365637572697479206b6579",
    "hex",
)

describe("security-key private identities", () => {
    test("parses the published Ed25519 private-key layout from a fixed container", () => {
        const privateKey = PrivateKey.parse(ed25519Container)
        expect(privateKey.data.alg).toBe("sk-ssh-ed25519@openssh.com")
        expect(privateKey.data.comment).toBe("security-key fixture")
        expect(privateKey.data.publicKey.data.algorithm).toBeInstanceOf(
            SSHED25519SecurityKeyPublicKey,
        )
        expect(privateKey.data.algorithm).toBeInstanceOf(SSHED25519SecurityKeyPrivateKey)
        expect((privateKey.data.algorithm as SSHED25519SecurityKeyPrivateKey).data).toEqual({
            publicKey: Buffer.from(
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                "hex",
            ),
            application: "ssh:test",
            flags: 1,
            keyHandle: Buffer.from("0102030405060708", "hex"),
            reserved: Buffer.alloc(0),
        })
        expect(() => privateKey.sign(Buffer.from("requires hardware"))).toThrow(
            "requires an SSH agent security-key provider",
        )
    })

    test("exposes both security-key public-key implementations", () => {
        expect(SSHED25519SecurityKeyPublicKey.alg_name).toBe("sk-ssh-ed25519@openssh.com")
        expect(SSHECDSASecurityKeyPublicKey.alg_name).toBe("sk-ecdsa-sha2-nistp256@openssh.com")
    })

    test("parses the published P-256 private-key layout from a fixed container", () => {
        const privateKey = PrivateKey.parse(ecdsaContainer)
        expect(privateKey.data.alg).toBe("sk-ecdsa-sha2-nistp256@openssh.com")
        expect(privateKey.data.comment).toBe("ecdsa security key")
        expect(privateKey.data.publicKey.data.algorithm).toBeInstanceOf(
            SSHECDSASecurityKeyPublicKey,
        )
        expect(privateKey.data.algorithm).toBeInstanceOf(SSHECDSASecurityKeyPrivateKey)
        const data = (privateKey.data.algorithm as SSHECDSASecurityKeyPrivateKey).data
        expect(data.application).toBe("ssh:test")
        expect(data.flags).toBe(5)
        expect(data.keyHandle).toEqual(Buffer.from("a1a2a3a4a5a6", "hex"))
        expect(data.reserved).toEqual(Buffer.from("reserved"))
    })

    test.each([ed25519Container, ecdsaContainer])(
        "round-trips a security-key identity through encrypted private storage",
        (container) => {
            const privateKey = PrivateKey.parse(container)
            const encrypted = privateKey.toString({
                passphrase: "security-key secret",
                rounds: 1,
            })
            const reparsed = PrivateKey.fromString(encrypted, "security-key secret")
            expect(reparsed.data.publicKey.equals(privateKey.data.publicKey)).toBeTrue()
            expect(
                (
                    reparsed.data.algorithm as
                        | SSHED25519SecurityKeyPrivateKey
                        | SSHECDSASecurityKeyPrivateKey
                ).data,
            ).toEqual(
                (
                    privateKey.data.algorithm as
                        | SSHED25519SecurityKeyPrivateKey
                        | SSHECDSASecurityKeyPrivateKey
                ).data,
            )
        },
    )

    test("copies and revalidates security-key private metadata", () => {
        const publicKey = Buffer.from(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "hex",
        )
        const keyHandle = Buffer.from([1, 2, 3])
        const reserved = Buffer.from([4, 5])
        const algorithm = new SSHED25519SecurityKeyPrivateKey({
            publicKey,
            application: "ssh:test",
            flags: 1,
            keyHandle,
            reserved,
        })
        const serialized = algorithm.serialize()
        publicKey.fill(0)
        keyHandle.fill(0)
        reserved.fill(0)
        expect(algorithm.serialize()).toEqual(serialized)

        algorithm.data.flags = 0x100
        expect(() => algorithm.serialize()).toThrow()
        algorithm.data.flags = 1
        algorithm.data.publicKey = Buffer.alloc(31)
        expect(() => algorithm.serialize()).toThrow("Invalid Ed25519 public key length")
    })
})
