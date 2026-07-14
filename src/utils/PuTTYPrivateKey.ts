import assert from "node:assert"
import { createDecipheriv, createHash, createHmac, timingSafeEqual } from "node:crypto"
import { argon2d, argon2i, argon2id } from "@noble/hashes/argon2.js"
import { serializeBuffer, serializeUint32 } from "./Buffer.js"
import { decodeSSHUTF8, encodeSSHUTF8 } from "./SSHText.js"

const PUTTY_PRIVATE_KEY_PREFIX = "PuTTY-User-Key-File-"
const MAX_FILE_BYTES = 16 * 1024 * 1024
const MAX_BLOB_BYTES = 8 * 1024 * 1024
const MAX_ARGON2_MEMORY_KIB = 256 * 1024
const MAX_ARGON2_PASSES = 100
const MAX_ARGON2_PARALLELISM = 64

type PuTTYKeyVersion = 2 | 3
type PuTTYEncryption = "none" | "aes256-cbc"
type PuTTYArgon2Mode = "Argon2d" | "Argon2i" | "Argon2id"

export interface ParsedPuTTYPrivateKey {
    readonly version: PuTTYKeyVersion
    readonly algorithmName: string
    readonly encryption: PuTTYEncryption
    readonly comment: string
    readonly publicKey: Buffer
    /** Authenticated plaintext, including any encryption padding. Clear after key construction. */
    readonly privateKey: Buffer
}

interface PuTTYArgon2Parameters {
    readonly mode: PuTTYArgon2Mode
    readonly memory: number
    readonly passes: number
    readonly parallelism: number
    readonly salt: Buffer
}

export function isPuTTYPrivateKey(data: string | Buffer): boolean {
    if (typeof data === "string") return data.startsWith(PUTTY_PRIVATE_KEY_PREFIX)
    return data
        .subarray(0, Buffer.byteLength(PUTTY_PRIVATE_KEY_PREFIX))
        .equals(Buffer.from(PUTTY_PRIVATE_KEY_PREFIX, "ascii"))
}

function decodeText(data: string | Buffer): string {
    const bytes = Buffer.isBuffer(data) ? data : encodeSSHUTF8(data, "PuTTY private key file")
    assert(bytes.length <= MAX_FILE_BYTES, `PuTTY private key file exceeds ${MAX_FILE_BYTES} bytes`)
    return Buffer.isBuffer(data) ? decodeSSHUTF8(data, "PuTTY private key file") : data
}

function decimal(value: string, field: string, maximum = Number.MAX_SAFE_INTEGER): number {
    assert(/^(?:0|[1-9][0-9]*)$/u.test(value), `Invalid PuTTY ${field}`)
    const parsed = Number(value)
    assert(Number.isSafeInteger(parsed) && parsed <= maximum, `Invalid PuTTY ${field}`)
    return parsed
}

function header(line: string | undefined, name: string): string {
    const prefix = `${name}: `
    assert(line !== undefined && line.startsWith(prefix), `Invalid PuTTY ${name} header`)
    return line.slice(prefix.length)
}

function decodeHex(value: string, field: string, expectedLength?: number): Buffer {
    assert(
        value.length > 0 && value.length % 2 === 0 && /^[0-9a-fA-F]+$/u.test(value),
        `Invalid PuTTY ${field}`,
    )
    const decoded = Buffer.from(value, "hex")
    if (expectedLength !== undefined) {
        assert(decoded.length === expectedLength, `Invalid PuTTY ${field} length`)
    }
    return decoded
}

function decodeBase64Lines(lines: readonly string[], field: string): Buffer {
    assert(lines.length > 0, `PuTTY ${field} must contain at least one line`)
    assert(
        lines.every((line) => line.length > 0),
        `PuTTY ${field} contains an empty line`,
    )
    assert(
        lines.every(
            (line, index) =>
                line.length <= 64 && (index === lines.length - 1 || line.length === 64),
        ),
        `Invalid PuTTY ${field} base64 line length`,
    )
    const encoded = lines.join("")
    assert(encoded.length <= Math.ceil((MAX_BLOB_BYTES * 4) / 3) + 4, `PuTTY ${field} is too large`)
    assert(/^[A-Za-z0-9+/]+={0,2}$/u.test(encoded), `Invalid PuTTY ${field} base64`)
    assert(encoded.length % 4 === 0, `Invalid PuTTY ${field} base64 length`)
    const decoded = Buffer.from(encoded, "base64")
    assert(decoded.length <= MAX_BLOB_BYTES, `PuTTY ${field} exceeds ${MAX_BLOB_BYTES} bytes`)
    assert(decoded.toString("base64") === encoded, `Non-canonical PuTTY ${field} base64`)
    return decoded
}

function macPreimage(
    algorithmName: string,
    encryption: string,
    comment: string,
    publicKey: Buffer,
    privateKey: Buffer,
): Buffer {
    return Buffer.concat(
        [algorithmName, encryption, comment]
            .map((value) => serializeBuffer(encodeSSHUTF8(value, "PuTTY private key MAC field")))
            .concat([serializeBuffer(publicKey), serializeBuffer(privateKey)]),
    )
}

function v2KeyMaterial(passphrase: Buffer): {
    cipherKey: Buffer
    iv: Buffer
    macKey: Buffer
} {
    const first = createHash("sha1").update(serializeUint32(0)).update(passphrase).digest()
    const second = createHash("sha1").update(serializeUint32(1)).update(passphrase).digest()
    const cipherKey = Buffer.concat([first, second], 32)
    first.fill(0)
    second.fill(0)
    return {
        cipherKey,
        iv: Buffer.alloc(16),
        macKey: createHash("sha1")
            .update("putty-private-key-file-mac-key", "ascii")
            .update(passphrase)
            .digest(),
    }
}

function v3KeyMaterial(
    passphrase: Buffer,
    parameters: PuTTYArgon2Parameters,
): { cipherKey: Buffer; iv: Buffer; macKey: Buffer; derived: Buffer } {
    assert(
        parameters.memory <= MAX_ARGON2_MEMORY_KIB,
        `PuTTY Argon2 memory exceeds ${MAX_ARGON2_MEMORY_KIB} KiB`,
    )
    assert(
        parameters.passes <= MAX_ARGON2_PASSES,
        `PuTTY Argon2 passes exceed ${MAX_ARGON2_PASSES}`,
    )
    assert(
        parameters.parallelism <= MAX_ARGON2_PARALLELISM,
        `PuTTY Argon2 parallelism exceeds ${MAX_ARGON2_PARALLELISM}`,
    )
    const derive =
        parameters.mode === "Argon2d" ? argon2d : parameters.mode === "Argon2i" ? argon2i : argon2id
    const derived = Buffer.from(
        derive(passphrase, parameters.salt, {
            m: parameters.memory,
            t: parameters.passes,
            p: parameters.parallelism,
            dkLen: 80,
            maxmem: MAX_ARGON2_MEMORY_KIB * 1024,
        }),
    )
    return {
        cipherKey: derived.subarray(0, 32),
        iv: derived.subarray(32, 48),
        macKey: derived.subarray(48, 80),
        derived,
    }
}

function decryptPrivateKey(ciphertext: Buffer, key: Buffer, iv: Buffer): Buffer {
    assert(
        ciphertext.length > 0 && ciphertext.length % 16 === 0,
        "Invalid encrypted PuTTY private key length",
    )
    const decipher = createDecipheriv("aes-256-cbc", key, iv)
    decipher.setAutoPadding(false)
    return Buffer.concat([decipher.update(ciphertext), decipher.final()])
}

export function parsePuTTYPrivateKey(
    data: string | Buffer,
    passphrase?: string | Buffer,
): ParsedPuTTYPrivateKey {
    const text = decodeText(data)
    const lines = text.split(/\r\n|\r|\n/u)
    if (lines.at(-1) === "") lines.pop()
    let index = 0

    const identification = /^PuTTY-User-Key-File-([0-9]+): (.+)$/u.exec(lines[index++] ?? "")
    assert(identification, "Invalid PuTTY private key identification")
    const versionNumber = decimal(identification[1]!, "private key version")
    assert(versionNumber === 2 || versionNumber === 3, "Unsupported PuTTY private key version")
    const version: PuTTYKeyVersion = versionNumber
    const algorithmName = identification[2]!

    const encryptionValue = header(lines[index++], "Encryption")
    assert(
        encryptionValue === "none" || encryptionValue === "aes256-cbc",
        "Unsupported PuTTY private key encryption",
    )
    const encryption: PuTTYEncryption = encryptionValue
    const comment = header(lines[index++], "Comment")
    encodeSSHUTF8(comment, "PuTTY private key comment")

    const publicLineCount = decimal(header(lines[index++], "Public-Lines"), "public line count")
    assert(
        publicLineCount > 0 && publicLineCount <= lines.length - index,
        "Invalid PuTTY public line count",
    )
    const publicKey = decodeBase64Lines(
        lines.slice(index, (index += publicLineCount)),
        "public key",
    )

    let argon2Parameters: PuTTYArgon2Parameters | undefined
    if (version === 3 && encryption !== "none") {
        const mode = header(lines[index++], "Key-Derivation")
        assert(
            mode === "Argon2d" || mode === "Argon2i" || mode === "Argon2id",
            "Unsupported PuTTY key derivation",
        )
        const memory = decimal(header(lines[index++], "Argon2-Memory"), "Argon2 memory")
        const passes = decimal(header(lines[index++], "Argon2-Passes"), "Argon2 passes")
        const parallelism = decimal(
            header(lines[index++], "Argon2-Parallelism"),
            "Argon2 parallelism",
        )
        const salt = decodeHex(header(lines[index++], "Argon2-Salt"), "Argon2 salt")
        assert(
            memory > 0 && passes > 0 && parallelism > 0 && salt.length >= 8 && salt.length <= 1024,
            "Invalid PuTTY Argon2 parameters",
        )
        argon2Parameters = { mode, memory, passes, parallelism, salt }
    }

    const privateLineCount = decimal(header(lines[index++], "Private-Lines"), "private line count")
    assert(
        privateLineCount > 0 && privateLineCount <= lines.length - index,
        "Invalid PuTTY private line count",
    )
    const encodedPrivateKey = decodeBase64Lines(
        lines.slice(index, (index += privateLineCount)),
        "private key",
    )
    const expectedMacLength = version === 2 ? 20 : 32
    const expectedMac = decodeHex(
        header(lines[index++], "Private-MAC"),
        "private MAC",
        expectedMacLength,
    )
    assert(index === lines.length, "Unexpected data after PuTTY private key")

    const encrypted = encryption !== "none"
    assert(
        !encrypted || passphrase !== undefined,
        "Encrypted PuTTY private key requires a passphrase",
    )
    const passphraseCopy = Buffer.isBuffer(passphrase)
        ? Buffer.from(passphrase)
        : encodeSSHUTF8(passphrase ?? "", "PuTTY private key passphrase")
    let privateKey: Buffer | undefined
    let derived: Buffer | undefined
    let cipherKey: Buffer | undefined
    let iv: Buffer | undefined
    let macKey: Buffer | undefined
    try {
        if (version === 2) {
            const material = v2KeyMaterial(encrypted ? passphraseCopy : Buffer.alloc(0))
            cipherKey = material.cipherKey
            iv = material.iv
            macKey = material.macKey
        } else if (encrypted) {
            assert(argon2Parameters)
            const material = v3KeyMaterial(passphraseCopy, argon2Parameters)
            cipherKey = material.cipherKey
            iv = material.iv
            macKey = material.macKey
            derived = material.derived
        } else {
            macKey = Buffer.alloc(0)
        }

        privateKey = encrypted
            ? decryptPrivateKey(encodedPrivateKey, cipherKey!, iv!)
            : Buffer.from(encodedPrivateKey)
        const preimage = macPreimage(algorithmName, encryption, comment, publicKey, privateKey)
        let actualMac: Buffer
        try {
            actualMac = createHmac(version === 2 ? "sha1" : "sha256", macKey)
                .update(preimage)
                .digest()
        } finally {
            preimage.fill(0)
        }
        const validMac = timingSafeEqual(actualMac, expectedMac)
        actualMac.fill(0)
        assert(
            validMac,
            encrypted
                ? "PuTTY private key integrity check failed; wrong passphrase?"
                : "PuTTY private key integrity check failed",
        )
        return { version, algorithmName, encryption, comment, publicKey, privateKey }
    } catch (error) {
        privateKey?.fill(0)
        throw error
    } finally {
        encodedPrivateKey.fill(0)
        passphraseCopy.fill(0)
        if (derived) derived.fill(0)
        else {
            cipherKey?.fill(0)
            iv?.fill(0)
            macKey?.fill(0)
        }
    }
}
