import assert from "node:assert"
import { createHash } from "node:crypto"

import Agent from "./publickey/Agent.js"
import { readNextBuffer, readNextUint32, serializeBuffer, serializeUint32 } from "./utils/Buffer.js"
import PrivateKey, { SSHRSAPrivateKey } from "./utils/PrivateKey.js"
import PublicKey, { SSHCertificatePublicKey, SSHRSAPublicKey } from "./utils/PublicKey.js"
import EncodedSignature from "./utils/Signature.js"
import { decodeSSHName, encodeSSHName } from "./utils/SSHName.js"
import { encodeSSHUTF8 } from "./utils/SSHText.js"

const MAGIC = Buffer.from("SSHSIG", "ascii")
const FORMAT_VERSION = 1
const BEGIN_MARKER = "-----BEGIN SSH SIGNATURE-----"
const END_MARKER = "-----END SSH SIGNATURE-----"
const ARMOR_LINE_LENGTH = 70
const MAX_BINARY_SIGNATURE_LENGTH = 1024 * 1024
const MAX_ARMORED_SIGNATURE_LENGTH = 2 * 1024 * 1024

export type SSHSignatureHashAlgorithm = "sha256" | "sha512"

export interface SSHSignatureOptions {
    /** Application domain that prevents a signature from being reused by another protocol. */
    namespace: string | Buffer
    /** Message digest placed in the signed preimage. Defaults to `sha512`. */
    hashAlgorithm?: SSHSignatureHashAlgorithm
}

interface SSHSignatureData {
    readonly version: number
    readonly publicKey: PublicKey
    readonly namespace: Buffer
    readonly reserved: Buffer
    readonly hashAlgorithm: SSHSignatureHashAlgorithm
    readonly signature: EncodedSignature
}

/** OpenSSH-compatible detached signatures with mandatory namespace-bound verification. */
export default class SSHSignature {
    readonly version: number
    readonly publicKey: PublicKey
    readonly hashAlgorithm: SSHSignatureHashAlgorithm
    readonly signature: EncodedSignature
    readonly #namespace: Buffer
    readonly #reserved: Buffer

    private constructor(data: SSHSignatureData) {
        assert(
            Number.isInteger(data.version) && data.version >= 0 && data.version <= FORMAT_VERSION,
            `Unsupported SSH signature format version ${data.version}`,
        )
        this.version = data.version
        this.publicKey = PublicKey.parse(data.publicKey.serialize())
        this.#namespace = normalizeNamespace(data.namespace)
        this.#reserved = Buffer.from(data.reserved)
        this.hashAlgorithm = normalizeHashAlgorithm(data.hashAlgorithm)
        this.signature = EncodedSignature.parse(data.signature.serialize())
        validateSignatureKey(this.publicKey, this.signature)
    }

    /** Namespace bytes retained by the detached signature. */
    get namespace(): Buffer {
        return Buffer.from(this.#namespace)
    }

    /** Reserved format bytes. Version 1 signers emit an empty value. */
    get reserved(): Buffer {
        return Buffer.from(this.#reserved)
    }

    static sign(
        message: Buffer,
        privateKey: PrivateKey,
        options: SSHSignatureOptions,
    ): SSHSignature {
        validateMessage(message)
        if (!(privateKey instanceof PrivateKey)) {
            throw new TypeError("SSH signature signing requires a private key")
        }
        const namespace = normalizeNamespace(options.namespace)
        const hashAlgorithm = normalizeHashAlgorithm(options.hashAlgorithm ?? "sha512")
        const digest = createHash(hashAlgorithm).update(message).digest()
        const signedData = buildSignedData(namespace, hashAlgorithm, digest)
        try {
            const signature = privateKey.sign(
                signedData,
                privateKey.data.algorithm instanceof SSHRSAPrivateKey
                    ? rsaSignatureAlgorithm(hashAlgorithm)
                    : undefined,
            )
            return new SSHSignature({
                version: FORMAT_VERSION,
                publicKey: privateKey.data.publicKey,
                namespace,
                reserved: Buffer.alloc(0),
                hashAlgorithm,
                signature,
            })
        } finally {
            digest.fill(0)
            signedData.fill(0)
        }
    }

    static async signWithAgent<Id>(
        message: Buffer,
        agent: Agent<Id>,
        id: Id,
        options: SSHSignatureOptions,
    ): Promise<SSHSignature> {
        validateMessage(message)
        if (!(agent instanceof Agent)) {
            throw new TypeError("SSH signature agent signing requires an agent")
        }
        const ownedMessage = Buffer.from(message)
        const namespace = normalizeNamespace(options.namespace)
        const hashAlgorithm = normalizeHashAlgorithm(options.hashAlgorithm ?? "sha512")
        const digest = createHash(hashAlgorithm).update(ownedMessage).digest()
        const signedData = buildSignedData(namespace, hashAlgorithm, digest)
        ownedMessage.fill(0)
        try {
            const publicKey = await agent.getPublicKey(id)
            const signature = await agent.sign(
                id,
                signedData,
                underlyingPublicKey(publicKey).data.algorithm instanceof SSHRSAPublicKey
                    ? rsaSignatureAlgorithm(hashAlgorithm)
                    : undefined,
            )
            assert(
                publicKey.verifySignature(signedData, signature),
                "SSH agent returned an invalid detached signature",
            )
            return new SSHSignature({
                version: FORMAT_VERSION,
                publicKey,
                namespace,
                reserved: Buffer.alloc(0),
                hashAlgorithm,
                signature,
            })
        } finally {
            digest.fill(0)
            signedData.fill(0)
        }
    }

    static parse(content: string | Buffer): SSHSignature {
        try {
            const binary = decodeSignature(content)
            if (binary.length > MAX_BINARY_SIGNATURE_LENGTH) {
                throw new Error("SSH signature exceeds the maximum binary length")
            }
            return new SSHSignature(parseBinarySignature(binary))
        } catch (error) {
            const reason = error instanceof Error ? error.message : String(error)
            throw new Error(`Invalid SSH signature: ${reason}`, { cause: error })
        }
    }

    verify(message: Buffer, expectedNamespace: string | Buffer): boolean {
        validateMessage(message)
        const namespace = normalizeNamespace(expectedNamespace)
        if (!namespace.equals(this.#namespace)) return false
        const digest = createHash(this.hashAlgorithm).update(message).digest()
        const signedData = buildSignedData(namespace, this.hashAlgorithm, digest)
        try {
            return this.publicKey.verifySignature(signedData, this.signature)
        } finally {
            digest.fill(0)
            signedData.fill(0)
        }
    }

    serialize(): Buffer {
        validateSignatureKey(this.publicKey, this.signature)
        const publicKey = this.publicKey.serialize()
        const signature = this.signature.serialize()
        const binary = Buffer.concat([
            MAGIC,
            serializeUint32(this.version),
            serializeBuffer(publicKey),
            serializeBuffer(this.#namespace),
            serializeBuffer(this.#reserved),
            serializeBuffer(encodeSSHName(this.hashAlgorithm, "SSH signature hash algorithm")),
            serializeBuffer(signature),
        ])
        assert(
            binary.length <= MAX_BINARY_SIGNATURE_LENGTH,
            "SSH signature exceeds the maximum binary length",
        )
        return binary
    }

    toString(): string {
        const base64 = this.serialize().toString("base64")
        const lines: string[] = []
        for (let offset = 0; offset < base64.length; offset += ARMOR_LINE_LENGTH) {
            lines.push(base64.slice(offset, offset + ARMOR_LINE_LENGTH))
        }
        return `${BEGIN_MARKER}\n${lines.join("\n")}\n${END_MARKER}\n`
    }
}

function validateMessage(message: Buffer): void {
    if (!Buffer.isBuffer(message)) throw new TypeError("SSH signature message must be a buffer")
}

function normalizeNamespace(namespace: string | Buffer): Buffer {
    const encoded = Buffer.isBuffer(namespace)
        ? Buffer.from(namespace)
        : encodeSSHUTF8(namespace, "SSH signature namespace")
    assert(encoded.length > 0, "SSH signature namespace must not be empty")
    assert(!encoded.includes(0), "SSH signature namespace must not contain NUL")
    assert(
        encoded.length <= MAX_BINARY_SIGNATURE_LENGTH,
        "SSH signature namespace exceeds the maximum length",
    )
    return encoded
}

function normalizeHashAlgorithm(algorithm: string): SSHSignatureHashAlgorithm {
    assert(
        algorithm === "sha256" || algorithm === "sha512",
        `Unsupported SSH signature hash algorithm: ${algorithm}`,
    )
    return algorithm
}

function buildSignedData(
    namespace: Buffer,
    hashAlgorithm: SSHSignatureHashAlgorithm,
    digest: Buffer,
): Buffer {
    return Buffer.concat([
        MAGIC,
        serializeBuffer(namespace),
        serializeBuffer(Buffer.alloc(0)),
        serializeBuffer(encodeSSHName(hashAlgorithm, "SSH signature hash algorithm")),
        serializeBuffer(digest),
    ])
}

function underlyingPublicKey(publicKey: PublicKey): PublicKey {
    return publicKey.data.algorithm instanceof SSHCertificatePublicKey
        ? publicKey.data.algorithm.publicKey
        : publicKey
}

function validateSignatureKey(publicKey: PublicKey, signature: EncodedSignature): void {
    publicKey.signatureAlgorithmFor(signature.data.alg)
    if (underlyingPublicKey(publicKey).data.algorithm instanceof SSHRSAPublicKey) {
        assert(
            signature.data.alg === "rsa-sha2-512" || signature.data.alg === "rsa-sha2-256",
            "SSH signatures with RSA keys require an RSA-SHA2 signature",
        )
    }
}

function rsaSignatureAlgorithm(hashAlgorithm: SSHSignatureHashAlgorithm): string {
    return hashAlgorithm === "sha512" ? "rsa-sha2-512" : "rsa-sha2-256"
}

function decodeSignature(content: string | Buffer): Buffer {
    if (typeof content !== "string" && !Buffer.isBuffer(content)) {
        throw new TypeError("SSH signature must be a string or buffer")
    }
    if (Buffer.isBuffer(content) && content.subarray(0, MAGIC.length).equals(MAGIC)) {
        assert(
            content.length <= MAX_BINARY_SIGNATURE_LENGTH,
            "SSH signature exceeds the maximum binary length",
        )
        return Buffer.from(content)
    }
    if (Buffer.isBuffer(content)) {
        assert(
            content.every((byte) => byte <= 0x7f),
            "SSH signature armor must be ASCII",
        )
    }
    const text = Buffer.isBuffer(content) ? content.toString("ascii") : content
    assert(
        Buffer.byteLength(text, "utf8") <= MAX_ARMORED_SIGNATURE_LENGTH,
        "SSH signature exceeds the maximum armored length",
    )
    assert(
        [...text].every((character) => {
            const code = character.charCodeAt(0)
            return code === 0x09 || code === 0x0a || code === 0x0d || (code >= 0x20 && code <= 0x7e)
        }),
        "SSH signature armor must be ASCII",
    )
    const lines = text.split(/\r?\n/u)
    if (lines.at(-1) === "") lines.pop()
    assert(lines[0] === BEGIN_MARKER, "Missing SSH signature armor header")
    assert(lines.at(-1) === END_MARKER, "Missing SSH signature armor footer")
    assert(lines.length >= 3, "SSH signature armor has no body")
    const body = lines.slice(1, -1)
    assert(
        body.every((line) => line.length > 0),
        "SSH signature armor contains a blank line",
    )
    const base64 = body.join("")
    assert(/^[A-Za-z0-9+/]+={0,2}$/u.test(base64), "Invalid SSH signature base64")
    assert(base64.length % 4 === 0, "Invalid SSH signature base64 length")
    const decoded = Buffer.from(base64, "base64")
    assert(decoded.toString("base64") === base64, "Non-canonical SSH signature base64")
    return decoded
}

function parseBinarySignature(content: Buffer): SSHSignatureData {
    assert(
        content.length >= MAGIC.length && content.subarray(0, MAGIC.length).equals(MAGIC),
        "Invalid SSH signature magic",
    )
    const [version, afterVersion] = readNextUint32(content.subarray(MAGIC.length))
    const [publicKeyBlob, afterPublicKey] = readNextBuffer(afterVersion)
    const [namespace, afterNamespace] = readNextBuffer(afterPublicKey)
    const [reserved, afterReserved] = readNextBuffer(afterNamespace)
    const [hashAlgorithmRaw, afterHashAlgorithm] = readNextBuffer(afterReserved)
    const [signatureBlob, remaining] = readNextBuffer(afterHashAlgorithm)
    assert(remaining.length === 0, "SSH signature contains trailing data")
    return {
        version,
        publicKey: PublicKey.parse(publicKeyBlob),
        namespace,
        reserved,
        hashAlgorithm: normalizeHashAlgorithm(
            decodeSSHName(hashAlgorithmRaw, "SSH signature hash algorithm"),
        ),
        signature: EncodedSignature.parse(signatureBlob),
    }
}
