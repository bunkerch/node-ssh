import EncodedSignature from "../../src/utils/Signature.js"
import PrivateKey, { SSHECDSAPrivateKey } from "../../src/utils/PrivateKey.js"
import PublicKey, { ECDSA_CURVES, SSHECDSAPublicKey } from "../../src/utils/PublicKey.js"

const rfc6979P256PublicKey = Buffer.from(
    "0000001365636473612d736861322d6e69737470323536" +
        "000000086e69737470323536" +
        "0000004104" +
        "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6" +
        "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
    "hex",
)
const rfc6979P256Signature = new EncodedSignature({
    alg: "ecdsa-sha2-nistp256",
    data: Buffer.from(
        "0000002100efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716" +
            "0000002100f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
        "hex",
    ),
})
const rfc6979P256PrivateKey = Buffer.from(
    "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
    "hex",
)
const rfc6979P256Point = Buffer.from(rfc6979P256PublicKey.subarray(-65))
const OPENSSH_PRIVATE_KEY_BEGIN = "-----BEGIN OPENSSH PRIVATE KEY-----"
const OPENSSH_PRIVATE_KEY_END = "-----END OPENSSH PRIVATE KEY-----"

function hex(value: string): Buffer {
    const normalized = value.replace(/\s/g, "")
    return Buffer.from(normalized.length % 2 === 0 ? normalized : `0${normalized}`, "hex")
}

function point(x: string, y: string): Buffer {
    return Buffer.concat([Buffer.from([4]), hex(x), hex(y)])
}

function signature(algorithm: string, r: string, s: string): EncodedSignature {
    const encode = (value: string): Buffer => {
        let scalar = hex(value)
        while (scalar.length > 1 && scalar[0] === 0) scalar = scalar.subarray(1)
        const encoded =
            (scalar[0] & 0x80) === 0 ? scalar : Buffer.concat([Buffer.from([0]), scalar])
        const length = Buffer.alloc(4)
        length.writeUInt32BE(encoded.length)
        return Buffer.concat([length, encoded])
    }
    return new EncodedSignature({
        alg: algorithm,
        data: Buffer.concat([encode(r), encode(s)]),
    })
}

const additionalRFC6979Vectors = [
    {
        name: "P-384/SHA-384",
        curve: ECDSA_CURVES[1],
        privateKey: hex(`
            6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D8
            96D5724E4C70A825F872C9EA60D2EDF5
        `),
        publicKey: point(
            `
                EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64
                DEF8F0EA9055866064A254515480BC13
            `,
            `
                8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1
                288B231C3AE0D4FE7344FD2533264720
            `,
        ),
        signature: signature(
            ECDSA_CURVES[1].algorithm,
            `
                94EDBB92A5ECB8AAD4736E56C691916B3F88140666CE9FA73D64C4EA95AD133C
                81A648152E44ACF96E36DD1E80FABE46
            `,
            `
                99EF4AEB15F178CEA1FE40DB2603138F130E740A19624526203B6351D0A3A94F
                A329C145786E679E7B82C71A38628AC8
            `,
        ),
    },
    {
        name: "P-521/SHA-512",
        curve: ECDSA_CURVES[2],
        privateKey: hex(`
            0FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75C
            AA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83
            538
        `),
        publicKey: point(
            `
                01894550D0785932E00EAA23B694F213F8C3121F86DC97A04E5A7167DB4E5BCD3
                71123D46E45DB6B5D5370A7F20FB633155D38FFA16D2BD761DCAC474B9A2F502
                3A4
            `,
            `
                00493101C962CD4D2FDDF782285E64584139C2F91B47F87FF82354D6630F746A2
                8A0DB25741B5B34A828008B22ACC23F924FAAFBD4D33F81EA66956DFEAA2BFDF
                CF5
            `,
        ),
        signature: signature(
            ECDSA_CURVES[2].algorithm,
            `
                0C328FAFCBD79DD77850370C46325D987CB525569FB63C5D3BC53950E6D4C5F1
                74E25A1EE9017B5D450606ADD152B534931D7D4E8455CC91F9B15BF05EC36E37
                7FA
            `,
            `
                0617CCE7CF5064806C467F678D3B4080D6F1CC50AF26CA209417308281B68AF2
                82623EAA63E5B5C0723D8B8C37FF0777B1A20F8CCB1DCCC43997F1EE0E44DA4A
                67A
            `,
        ),
    },
]

describe("RFC 5656 ECDSA keys and signatures", () => {
    test("rejects non-ASCII ECDSA curve identifiers without lossy normalization", async () => {
        const malformedPublic = Buffer.from(rfc6979P256PublicKey)
        const publicIdentifierOffset = malformedPublic.lastIndexOf("nistp256")
        expect(publicIdentifierOffset).toBeGreaterThanOrEqual(0)
        malformedPublic[publicIdentifierOffset] |= 0x80
        expect(() => PublicKey.parse(malformedPublic)).toThrow(
            "Invalid ECDSA curve identifier nistp256",
        )

        const privateKey = await PrivateKey.generate("ecdsa-sha2-nistp256")
        const encoded = privateKey.toString()
        const lines = encoded.split("\n")
        const raw = Buffer.from(lines.slice(1, -1).join(""), "base64")
        const privateIdentifierOffset = raw.lastIndexOf("nistp256")
        expect(privateIdentifierOffset).toBeGreaterThanOrEqual(0)
        raw[privateIdentifierOffset] |= 0x80
        const malformedPrivate = [
            OPENSSH_PRIVATE_KEY_BEGIN,
            ...(raw.toString("base64").match(/.{1,70}/gu) ?? []),
            OPENSSH_PRIVATE_KEY_END,
        ].join("\n")
        expect(() => PrivateKey.fromString(malformedPrivate)).toThrow(
            "Invalid ECDSA curve identifier nistp256",
        )
    })

    test("signs the RFC 6979 P-256 SHA-256 signature in SSH mpint encoding", () => {
        const publicKey = PublicKey.parse(rfc6979P256PublicKey)
        const privateAlgorithm = new SSHECDSAPrivateKey(ECDSA_CURVES[0], {
            publicKey: rfc6979P256Point,
            privateKey: rfc6979P256PrivateKey,
        })
        const privateKey = new PrivateKey({
            alg: ECDSA_CURVES[0].algorithm,
            algorithm: privateAlgorithm,
            publicKey: privateAlgorithm.getPublicKey(),
        })

        expect(publicKey.data.alg).toBe("ecdsa-sha2-nistp256")
        expect(publicKey.serialize()).toEqual(rfc6979P256PublicKey)
        expect(privateKey.sign(Buffer.from("sample"))).toEqual(rfc6979P256Signature)
        expect(privateKey.sign(Buffer.from("sample"))).toEqual(rfc6979P256Signature)
        expect(publicKey.verifySignature(Buffer.from("sample"), rfc6979P256Signature)).toBe(true)

        const tampered = new EncodedSignature({
            alg: rfc6979P256Signature.data.alg,
            data: Buffer.from(rfc6979P256Signature.data.data),
        })
        tampered.data.data[tampered.data.data.length - 1] ^= 1
        expect(publicKey.verifySignature(Buffer.from("sample"), tampered)).toBe(false)
    })

    test.each(additionalRFC6979Vectors)(
        "signs the RFC 6979 $name vector in SSH mpint encoding",
        ({ curve, privateKey: privateScalar, publicKey: publicPoint, signature: expected }) => {
            const privateAlgorithm = new SSHECDSAPrivateKey(curve, {
                publicKey: publicPoint,
                privateKey: privateScalar,
            })
            const privateKey = new PrivateKey({
                alg: curve.algorithm,
                algorithm: privateAlgorithm,
                publicKey: privateAlgorithm.getPublicKey(),
            })

            expect(privateKey.sign(Buffer.from("sample"))).toEqual(expected)
            expect(privateKey.sign(Buffer.from("sample"))).toEqual(expected)
            expect(privateKey.data.publicKey.verifySignature(Buffer.from("sample"), expected)).toBe(
                true,
            )
        },
    )

    test("generates, serializes, signs, and verifies every required NIST curve", async () => {
        for (const algorithm of [
            "ecdsa-sha2-nistp256",
            "ecdsa-sha2-nistp384",
            "ecdsa-sha2-nistp521",
        ]) {
            const privateKey = await PrivateKey.generate(algorithm)
            const parsed = PrivateKey.fromString(privateKey.toString())
            const data = Buffer.from(`signed with ${algorithm}`)
            const signature = parsed.sign(data)

            expect(parsed.data.alg).toBe(algorithm)
            expect(parsed.data.publicKey.equals(privateKey.data.publicKey)).toBe(true)
            expect(signature.data.alg).toBe(algorithm)
            expect(parsed.data.publicKey.verifySignature(data, signature)).toBe(true)
        }
    })

    test("rejects malformed curve points and mismatched signature algorithms", () => {
        const publicKey = PublicKey.parse(rfc6979P256PublicKey)
        const malformed = Buffer.from(rfc6979P256PublicKey)
        malformed[malformed.length - 1] ^= 1

        expect(() => PublicKey.parse(malformed)).toThrow("Invalid nistp256 public key")
        expect(
            publicKey.verifySignature(
                Buffer.from("sample"),
                new EncodedSignature({
                    alg: "ecdsa-sha2-nistp384",
                    data: rfc6979P256Signature.data.data,
                }),
            ),
        ).toBe(false)
    })

    test("does not retain caller-owned public or private key storage", () => {
        const publicInput = Buffer.from(rfc6979P256Point)
        const publicAlgorithm = new SSHECDSAPublicKey(ECDSA_CURVES[0], {
            publicKey: publicInput,
        })
        publicInput.fill(0xff)
        expect(publicAlgorithm.serialize().subarray(-65)).toEqual(rfc6979P256Point)

        const privatePublicInput = Buffer.from(rfc6979P256Point)
        const privateInput = Buffer.from(rfc6979P256PrivateKey)
        const privateAlgorithm = new SSHECDSAPrivateKey(ECDSA_CURVES[0], {
            publicKey: privatePublicInput,
            privateKey: privateInput,
        })
        privatePublicInput.fill(0xff)
        privateInput.fill(0xff)

        const key = new PrivateKey({
            alg: ECDSA_CURVES[0].algorithm,
            algorithm: privateAlgorithm,
            publicKey: privateAlgorithm.getPublicKey(),
        })
        const message = Buffer.from("stable ECDSA key ownership")
        expect(key.data.publicKey.verifySignature(message, key.sign(message))).toBe(true)
        expect(privateAlgorithm.data.publicKey).toEqual(rfc6979P256Point)
        expect(privateAlgorithm.data.privateKey).toEqual(rfc6979P256PrivateKey)
    })
})
