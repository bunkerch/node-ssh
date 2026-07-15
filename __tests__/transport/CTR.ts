import AES128CTR from "../../src/algorithms/encryption/aes128-ctr.js"
import AES192CTR from "../../src/algorithms/encryption/aes192-ctr.js"
import AES256CTR from "../../src/algorithms/encryption/aes256-ctr.js"

const plaintext = Buffer.from(
    "6bc1bee22e409f96e93d7e117393172a" +
        "ae2d8a571e03ac9c9eb76fac45af8e51" +
        "30c81c46a35ce411e5fbc1191a0a52ef" +
        "f69f2445df4f9b17ad2b417be66c3710",
    "hex",
)
const initialCounter = Buffer.from("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", "hex")

describe("RFC 4344 AES-CTR ciphers", () => {
    test.each([
        [
            "aes128-ctr",
            AES128CTR,
            "2b7e151628aed2a6abf7158809cf4f3c",
            "874d6191b620e3261bef6864990db6ce" +
                "9806f66b7970fdff8617187bb9fffdff" +
                "5ae4df3edbd5d35e5b4f09020db03eab" +
                "1e031dda2fbe03d1792170a0f3009cee",
        ],
        [
            "aes192-ctr",
            AES192CTR,
            "8e73b0f7da0e6452c810f32b809079e5" + "62f8ead2522c6b7b",
            "1abc932417521ca24f2b0459fe7e6e0b" +
                "090339ec0aa6faefd5ccc2c6f4ce8e94" +
                "1e36b26bd1ebc670d1bd1d665620abf7" +
                "4f78a7f6d29809585a97daec58c6b050",
        ],
        [
            "aes256-ctr",
            AES256CTR,
            "603deb1015ca71be2b73aef0857d7781" + "1f352c073b6108d72d9810a30914dff4",
            "601ec313775789a5b7a7f504bbf3d228" +
                "f443e3ca4d62b59aca84e990cacaf5c5" +
                "2b0930daa23de94ce87017ba2d84988d" +
                "dfc9c58db67aada613c2dd08457941a6",
        ],
    ] as const)("%s matches the NIST SP 800-38A vector", (_name, Cipher, keyHex, ciphertextHex) => {
        const key = Buffer.from(keyHex, "hex")
        const iv = Buffer.from(initialCounter)
        const expected = Buffer.from(ciphertextHex, "hex")
        const encryptor = new Cipher(key, iv)
        const decryptor = new Cipher(key, iv)
        key.fill(0)
        iv.fill(0)

        const ciphertext = Buffer.concat([
            encryptor.encrypt(plaintext.subarray(0, 7)),
            encryptor.encrypt(plaintext.subarray(7, 39)),
            encryptor.encrypt(plaintext.subarray(39)),
        ])
        expect(ciphertext).toEqual(expected)
        expect(
            Buffer.concat([
                decryptor.decrypt(ciphertext.subarray(0, 23)),
                decryptor.decrypt(ciphertext.subarray(23)),
            ]),
        ).toEqual(plaintext)
    })

    test.each([
        ["aes128-ctr", AES128CTR],
        ["aes192-ctr", AES192CTR],
        ["aes256-ctr", AES256CTR],
    ] as const)("%s enforces its declared key and IV sizes", (_name, Cipher) => {
        expect(() => new Cipher(Buffer.alloc(Cipher.key_length - 1), Buffer.alloc(16))).toThrow(
            `key must be ${Cipher.key_length} bytes`,
        )
        expect(() => new Cipher(Buffer.alloc(Cipher.key_length), Buffer.alloc(15))).toThrow(
            "IV must be 16 bytes",
        )
    })
})
