import assert from "node:assert"
import {
    createCipheriv,
    createDecipheriv,
    randomBytes,
    timingSafeEqual,
    type CipherGCM,
    type DecipherGCM,
} from "node:crypto"
import { pbkdf } from "bcrypt-pbkdf"
import { readNextBuffer, readNextUint32 } from "./Buffer.js"
import { chacha20, poly1305 } from "./chacha20.js"

interface CipherInfo {
    nodeName?: string
    blockLength: number
    keyLength: number
    ivLength: number
    authLength: number
    chacha?: true
}

const ciphers = new Map<string, CipherInfo>([
    [
        "3des-cbc",
        {
            nodeName: "des-ede3-cbc",
            blockLength: 8,
            keyLength: 24,
            ivLength: 8,
            authLength: 0,
        },
    ],
    ...([128, 192, 256] as const).flatMap((bits) =>
        (["cbc", "ctr"] as const).map(
            (mode) =>
                [
                    `aes${bits}-${mode}`,
                    {
                        nodeName: `aes-${bits}-${mode}`,
                        blockLength: 16,
                        keyLength: bits / 8,
                        ivLength: 16,
                        authLength: 0,
                    },
                ] as const,
        ),
    ),
    ...([128, 256] as const).map(
        (bits) =>
            [
                `aes${bits}-gcm@openssh.com`,
                {
                    nodeName: `aes-${bits}-gcm`,
                    blockLength: 16,
                    keyLength: bits / 8,
                    ivLength: 12,
                    authLength: 16,
                },
            ] as const,
    ),
    [
        "chacha20-poly1305@openssh.com",
        {
            blockLength: 8,
            keyLength: 64,
            ivLength: 0,
            authLength: 16,
            chacha: true,
        },
    ],
])

export type OpenSSHPrivateKeyCipher =
    | "3des-cbc"
    | "aes128-cbc"
    | "aes192-cbc"
    | "aes256-cbc"
    | "aes128-ctr"
    | "aes192-ctr"
    | "aes256-ctr"
    | "aes128-gcm@openssh.com"
    | "aes256-gcm@openssh.com"
    | "chacha20-poly1305@openssh.com"

export interface OpenSSHPrivateKeyEncryptionOptions {
    passphrase: string | Buffer
    cipher?: OpenSSHPrivateKeyCipher
    /** bcrypt_pbkdf rounds; defaults to 16. */
    rounds?: number
}

export interface OpenSSHPrivateKeyEncryptionResult {
    cipherName: OpenSSHPrivateKeyCipher
    kdfName: "bcrypt"
    kdfOptions: Buffer
    ciphertext: Buffer
    authenticationTag: Buffer
    blockLength: number
}

export function getOpenSSHPrivateKeyCipherBlockLength(name: OpenSSHPrivateKeyCipher): number {
    const cipher = ciphers.get(name)
    assert(cipher, `Unsupported OpenSSH private key cipher: ${name}`)
    return cipher.blockLength
}

export function encryptOpenSSHPrivateKey(
    plaintext: Buffer,
    options: OpenSSHPrivateKeyEncryptionOptions,
): OpenSSHPrivateKeyEncryptionResult {
    const cipherName = options.cipher ?? "aes256-ctr"
    const cipher = ciphers.get(cipherName)
    assert(cipher, `Unsupported OpenSSH private key cipher: ${cipherName}`)
    const rounds = options.rounds ?? 16
    if (!Number.isInteger(rounds)) throw new TypeError("bcrypt KDF rounds must be an integer")
    if (rounds < 1 || rounds > 0xffff_ffff) {
        throw new RangeError("bcrypt KDF rounds must be between 1 and 4294967295")
    }
    assert(plaintext.length > 0, "OpenSSH private key plaintext must not be empty")
    assert(
        plaintext.length % cipher.blockLength === 0,
        "OpenSSH private key plaintext is not block-aligned",
    )

    const passphrase = Buffer.isBuffer(options.passphrase)
        ? Buffer.from(options.passphrase)
        : Buffer.from(options.passphrase, "utf8")
    assert(passphrase.length > 0, "Encrypted OpenSSH private key requires a passphrase")
    const salt = randomBytes(16)
    const keyAndIV = Buffer.alloc(cipher.keyLength + cipher.ivLength)
    try {
        assert(
            pbkdf(
                passphrase,
                passphrase.length,
                salt,
                salt.length,
                keyAndIV,
                keyAndIV.length,
                rounds,
            ) === 0,
            "Failed to derive OpenSSH private key encryption key",
        )
        const key = keyAndIV.subarray(0, cipher.keyLength)
        const iv = keyAndIV.subarray(cipher.keyLength)
        let ciphertext: Buffer
        let authenticationTag: Buffer
        if (cipher.chacha) {
            const mainKey = key.subarray(0, 32)
            const polyKey = chacha20(Buffer.alloc(32), mainKey, 0n)
            try {
                ciphertext = chacha20(plaintext, mainKey, 1n)
                authenticationTag = poly1305(ciphertext, polyKey)
            } finally {
                polyKey.fill(0)
            }
        } else {
            assert(cipher.nodeName)
            const encryptor = (
                cipher.authLength > 0
                    ? createCipheriv(cipher.nodeName, key, iv, {
                          authTagLength: cipher.authLength,
                      } as never)
                    : createCipheriv(cipher.nodeName, key, iv)
            ) as CipherGCM
            encryptor.setAutoPadding(false)
            ciphertext = Buffer.concat([encryptor.update(plaintext), encryptor.final()])
            authenticationTag = cipher.authLength > 0 ? encryptor.getAuthTag() : Buffer.alloc(0)
        }
        const kdfOptions = Buffer.allocUnsafe(4 + salt.length + 4)
        kdfOptions.writeUInt32BE(salt.length, 0)
        salt.copy(kdfOptions, 4)
        kdfOptions.writeUInt32BE(rounds, 4 + salt.length)
        return {
            cipherName,
            kdfName: "bcrypt",
            kdfOptions,
            ciphertext,
            authenticationTag,
            blockLength: cipher.blockLength,
        }
    } finally {
        passphrase.fill(0)
        keyAndIV.fill(0)
        salt.fill(0)
    }
}

function decryptChacha20(ciphertext: Buffer, tag: Buffer, key: Buffer): Buffer {
    const mainKey = key.subarray(0, 32)
    const polyKey = chacha20(Buffer.alloc(32), mainKey, 0n)
    const expectedTag = poly1305(ciphertext, polyKey)
    try {
        assert(timingSafeEqual(tag, expectedTag), "OpenSSH key integrity check failed")
        return chacha20(ciphertext, mainKey, 1n)
    } finally {
        polyKey.fill(0)
        expectedTag.fill(0)
    }
}

export interface OpenSSHPrivateKeyDecryptionResult {
    plaintext: Buffer
    blockLength: number
}

export function decryptOpenSSHPrivateKey(
    cipherName: string,
    kdfName: string,
    kdfOptions: Buffer,
    ciphertext: Buffer,
    authenticationTag: Buffer,
    passphrase?: string | Buffer,
): OpenSSHPrivateKeyDecryptionResult {
    const cipher = ciphers.get(cipherName)
    assert(cipher, `Unsupported OpenSSH private key cipher: ${cipherName}`)
    assert(kdfName === "bcrypt", `Unsupported OpenSSH private key KDF: ${kdfName}`)
    assert(passphrase !== undefined, "Encrypted OpenSSH private key requires a passphrase")

    const passphraseBuffer = Buffer.isBuffer(passphrase)
        ? Buffer.from(passphrase)
        : Buffer.from(passphrase, "utf8")
    const keyAndIV = Buffer.alloc(cipher.keyLength + cipher.ivLength)
    try {
        assert(passphraseBuffer.length > 0, "Encrypted OpenSSH private key requires a passphrase")

        let salt: Buffer
        ;[salt, kdfOptions] = readNextBuffer(kdfOptions)
        let rounds: number
        ;[rounds, kdfOptions] = readNextUint32(kdfOptions)
        assert(kdfOptions.length === 0, "Invalid bcrypt KDF options")
        assert(salt.length > 0, "Invalid bcrypt KDF salt")
        assert(rounds > 0, "Invalid bcrypt KDF rounds")
        assert(ciphertext.length >= cipher.blockLength, "Invalid encrypted private key length")
        assert(
            ciphertext.length % cipher.blockLength === 0,
            "Invalid encrypted private key block length",
        )
        assert(
            authenticationTag.length === cipher.authLength,
            "Invalid private key authentication tag length",
        )

        assert(
            pbkdf(
                passphraseBuffer,
                passphraseBuffer.length,
                salt,
                salt.length,
                keyAndIV,
                keyAndIV.length,
                rounds,
            ) === 0,
            "Failed to derive OpenSSH private key encryption key",
        )

        const key = keyAndIV.subarray(0, cipher.keyLength)
        const iv = keyAndIV.subarray(cipher.keyLength)
        let plaintext: Buffer
        if (cipher.chacha) {
            plaintext = decryptChacha20(ciphertext, authenticationTag, key)
        } else {
            assert(cipher.nodeName)
            const decipher = createDecipheriv(cipher.nodeName, key, iv) as DecipherGCM
            decipher.setAutoPadding(false)
            if (cipher.authLength > 0) decipher.setAuthTag(authenticationTag)
            plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()])
        }

        return { plaintext, blockLength: cipher.blockLength }
    } finally {
        keyAndIV.fill(0)
        passphraseBuffer.fill(0)
    }
}
