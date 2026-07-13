import {
    ECDHSHA2NISTP256,
    ECDHSHA2NISTP384,
    ECDHSHA2NISTP521,
} from "../../src/algorithms/kex/ecdh-sha2-nist.js"

function hex(value: string): Buffer {
    return Buffer.from(value.replaceAll(/\s/gu, ""), "hex")
}

describe("RFC 5656 ECDH key exchange", () => {
    test.each([
        {
            name: "nistp256",
            create: (privateKey: Buffer) => new ECDHSHA2NISTP256(privateKey),
            privateKey: hex(
                "C88F01F5 10D9AC3F 70A292DA A2316DE5 44E9AAB8 AFE84049 C62A9C57 862D1433",
            ),
            publicKey: hex(`04
                DAD0B653 94221CF9 B051E1FE CA5787D0 98DFE637 FC90B9EF 945D0C37 72581180
                5271A046 1CDB8252 D61F1C45 6FA3E59A B1F45B33 ACCF5F58 389E0577 B8990BB3`),
            peerPublicKey: hex(`04
                D12DFB52 89C8D4F8 1208B702 70398C34 2296970A 0BCCB74C 736FC755 4494BF63
                56FBF3CA 366CC23E 8157854C 13C58D6A AC23F046 ADA30F83 53E74F33 039872AB`),
            sharedSecret: hex(
                "D6840F6B 42F6EDAF D13116E0 E1256520 2FEF8E9E CE7DCE03 812464D0 4B9442DE",
            ),
        },
        {
            name: "nistp384",
            create: (privateKey: Buffer) => new ECDHSHA2NISTP384(privateKey),
            privateKey: hex(`
                099F3C70 34D4A2C6 99884D73 A375A67F 7624EF7C 6B3C0F16 0647B674 14DCE655
                E35B5380 41E649EE 3FAEF896 783AB194`),
            publicKey: hex(`04
                667842D7 D180AC2C DE6F74F3 7551F557 55C7645C 20EF73E3 1634FE72 B4C55EE6
                DE3AC808 ACB4BDB4 C88732AE E95F41AA
                9482ED1F C0EEB9CA FC498462 5CCFC23F 65032149 E0E144AD A0241815 35A0F38E
                EB9FCFF3 C2C947DA E69B4C63 4573A81C`),
            peerPublicKey: hex(`04
                E558DBEF 53EECDE3 D3FCCFC1 AEA08A89 A987475D 12FD950D 83CFA417 32BC509D
                0D1AC43A 0336DEF9 6FDA41D0 774A3571
                DCFBEC7A ACF31964 72169E83 8430367F 66EEBE3C 6E70C416 DD5F0C68 759DD1FF
                F83FA401 42209DFF 5EAAD96D B9E6386C`),
            sharedSecret: hex(`
                11187331 C279962D 93D60424 3FD592CB 9D0A926F 422E4718 7521287E 7156C5C4
                D6031355 69B9E9D0 9CF5D4A2 70F59746`),
        },
        {
            name: "nistp521",
            create: (privateKey: Buffer) => new ECDHSHA2NISTP521(privateKey),
            privateKey: hex(`
                0037ADE9 319A89F4 DABDB3EF 411AACCC A5123C61 ACAB57B5 393DCE47 608172A0
                95AA85A3 0FE1C295 2C6771D9 37BA9777 F5957B26 39BAB072 462F68C2 7A57382D
                4A52`),
            publicKey: hex(`04
                0015417E 84DBF28C 0AD3C278 713349DC 7DF153C8 97A1891B D98BAB43 57C9ECBE
                E1E3BF42 E00B8E38 0AEAE57C 2D107564 94188594 2AF5A7F4 601723C4 195D176C
                ED3E
                017CAE20 B6641D2E EB695786 D8C94614 6239D099 E18E1D5A 514C739D 7CB4A10A
                D8A78801 5AC405D7 799DC75E 7B7D5B6C F2261A6A 7F150743 8BF01BEB 6CA3926F
                9582`),
            peerPublicKey: hex(`04
                00D0B397 5AC4B799 F5BEA16D 5E13E9AF 971D5E9B 984C9F39 728B5E57 39735A21
                9B97C356 436ADC6E 95BB0352 F6BE64A6 C2912D4E F2D0433C ED2B6171 640012D9
                460F
                015C6822 6383956E 3BD066E7 97B623C2 7CE0EAC2 F551A10C 2C724D98 52077B87
                220B6536 C5C408A1 D2AEBB8E 86D678AE 49CB5709 1F473229 6579AB44 FCD17F0F
                C56A`),
            sharedSecret: hex(`
                01144C7D 79AE6956 BC8EDB8E 7C787C45 21CB086F A64407F9 7894E5E6 B2D79B04
                D1427E73 CA4BAA24 0A347868 59810C06 B3C715A3 A8CC3151 F2BEE417 996D19F3
                DDEA`),
        },
    ])("matches the RFC 5903 $name public-key and shared-secret vector", (vector) => {
        const algorithm = vector.create(vector.privateKey)
        algorithm.generateKeyPair()
        expect(algorithm.getPublicKey()).toEqual(vector.publicKey)
        expect(algorithm.computeSharedSecret(vector.peerPublicKey)).toEqual(vector.sharedSecret)
    })

    test("rejects malformed and off-curve SEC1 points", () => {
        const algorithm = new ECDHSHA2NISTP256()
        algorithm.generateKeyPair()
        expect(() => algorithm.computeSharedSecret(Buffer.alloc(64))).toThrow(
            "Invalid prime256v1 ECDH public key",
        )
        expect(() => algorithm.computeSharedSecret(Buffer.alloc(65, 0x04))).toThrow(
            "Invalid prime256v1 ECDH public key",
        )
    })
})
