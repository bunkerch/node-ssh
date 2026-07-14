import assert from "node:assert"
import {
    constants,
    createHash,
    generateKeyPair,
    privateDecrypt,
    publicEncrypt,
    randomBytes,
    type KeyObject,
} from "node:crypto"
import type { KeyExchangeHashContext } from "../../algorithms.js"
import { readNextBuffer, serializeBuffer } from "../../utils/Buffer.js"
import PublicKey, { SSHRSAPublicKey } from "../../utils/PublicKey.js"
import { serializeMpintBufferToBuffer } from "../../utils/mpint.js"
import KeyExchange, { KeyExchangeError } from "./key-exchange.js"

const HASH_LENGTH_BITS = 256
const MINIMUM_MODULUS_BITS = 2048

export interface RSAKeyExchangeHashFields {
    clientVersion: string | Buffer
    serverVersion: string | Buffer
    clientKexInit: Buffer
    serverKexInit: Buffer
    hostKey: Buffer
    transientKey: Buffer
    encryptedSecret: Buffer
    sharedSecret: Buffer
}

export function computeRSAKeyExchangeHash(fields: RSAKeyExchangeHashFields): Buffer {
    const hash = createHash("sha256")
    for (const field of [
        fields.clientVersion,
        fields.serverVersion,
        fields.clientKexInit,
        fields.serverKexInit,
        fields.hostKey,
        fields.transientKey,
        fields.encryptedSecret,
        serializeMpintBufferToBuffer(fields.sharedSecret),
    ]) {
        const value = typeof field === "string" ? Buffer.from(field, "utf8") : field
        hash.update(serializeBuffer(value))
    }
    return hash.digest()
}

export default class RSA2048SHA256 extends KeyExchange {
    static alg_name = "rsa2048-sha256"
    static requires_encryption = false
    static requires_signature = true

    static instantiate(): RSA2048SHA256 {
        return new RSA2048SHA256()
    }

    readonly exchangeValueEncoding = "mpint" as const
    private transientPrivateKey: KeyObject | undefined
    private transientPublicKey: Buffer | undefined
    private transientModulusBits: number | undefined
    private hostKey: Buffer | undefined
    private encryptedSecret: Buffer | undefined

    constructor() {
        super("sha256")
    }

    async generateTransientKey(): Promise<void> {
        const { publicKey, privateKey } = await new Promise<{
            publicKey: KeyObject
            privateKey: KeyObject
        }>((resolve, reject) => {
            generateKeyPair("rsa", { modulusLength: MINIMUM_MODULUS_BITS }, (error, pub, prv) =>
                error ? reject(error) : resolve({ publicKey: pub, privateKey: prv }),
            )
        })
        this.transientPrivateKey = privateKey
        this.transientPublicKey = PublicKey.fromPEM(
            publicKey.export({ format: "pem", type: "spki" }),
        ).serialize()
        this.transientModulusBits = MINIMUM_MODULUS_BITS
    }

    setServerKeys(hostKey: Buffer, transientKey: Buffer): void {
        const parsed = PublicKey.parse(transientKey)
        if (!(parsed.data.algorithm instanceof SSHRSAPublicKey)) {
            throw new KeyExchangeError("RFC 4432 transient key must be an RSA key")
        }
        const modulusBits = bitLength(parsed.data.algorithm.data.modulus)
        if (modulusBits < MINIMUM_MODULUS_BITS) {
            throw new KeyExchangeError("RFC 4432 transient RSA modulus is too small")
        }
        this.hostKey = Buffer.from(hostKey)
        this.transientPublicKey = Buffer.from(transientKey)
        this.transientModulusBits = modulusBits
    }

    setHostKey(hostKey: Buffer): void {
        this.hostKey = Buffer.from(hostKey)
    }

    getTransientPublicKey(): Buffer {
        assert(this.transientPublicKey, "Transient RSA key has not been generated")
        return Buffer.from(this.transientPublicKey)
    }

    generateSecret(): Buffer {
        assert(this.transientPublicKey, "Transient RSA key is unavailable")
        const transient = PublicKey.parse(this.transientPublicKey)
        assert(transient.data.algorithm instanceof SSHRSAPublicKey)
        const modulusBits = bitLength(transient.data.algorithm.data.modulus)
        const maximumSecretBits = modulusBits - 2 * HASH_LENGTH_BITS - 49
        assert(maximumSecretBits > 0)
        const secret = randomInteger(maximumSecretBits)
        const encodedSecret = serializeBuffer(serializeMpintBufferToBuffer(secret))
        this.encryptedSecret = publicEncrypt(
            {
                key: transient.data.algorithm.toPEM(),
                padding: constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: "sha256",
            },
            encodedSecret,
        )
        this.sharedSecret = secret
        return Buffer.from(this.encryptedSecret)
    }

    decryptSecret(encryptedSecret: Buffer): void {
        assert(this.transientPrivateKey, "Transient RSA private key is unavailable")
        let plaintext: Buffer
        try {
            plaintext = privateDecrypt(
                {
                    key: this.transientPrivateKey,
                    padding: constants.RSA_PKCS1_OAEP_PADDING,
                    oaepHash: "sha256",
                },
                encryptedSecret,
            )
        } catch (error) {
            throw new KeyExchangeError("Unable to decrypt RFC 4432 shared secret", {
                cause: error,
            })
        } finally {
            this.transientPrivateKey = undefined
        }
        const [secret, remaining] = readNextBuffer(plaintext)
        if (remaining.length !== 0 || !serializeMpintBufferToBuffer(secret).equals(secret)) {
            throw new KeyExchangeError("Invalid RFC 4432 shared-secret mpint")
        }
        assert(this.transientModulusBits)
        const maximumSecretBits = this.transientModulusBits - 2 * HASH_LENGTH_BITS - 49
        if (bitLength(secret) > maximumSecretBits) {
            throw new KeyExchangeError("RFC 4432 shared secret is outside the permitted range")
        }
        this.encryptedSecret = Buffer.from(encryptedSecret)
        this.sharedSecret = Buffer.from(secret)
    }

    computeExchangeHash(context: Readonly<KeyExchangeHashContext>): Buffer {
        return this.computeHash(
            context.clientVersion,
            context.serverVersion,
            context.clientKexInit,
            context.serverKexInit,
        )
    }

    override dispose(): void {
        this.transientPrivateKey = undefined
        this.hostKey = undefined
        this.transientPublicKey = undefined
        this.transientModulusBits = undefined
        this.encryptedSecret = undefined
        super.dispose()
    }

    private computeHash(
        clientVersion: string,
        serverVersion: string,
        clientKexInit: Buffer,
        serverKexInit: Buffer,
    ): Buffer {
        assert(this.hostKey && this.transientPublicKey && this.encryptedSecret && this.sharedSecret)
        return computeRSAKeyExchangeHash({
            clientVersion,
            serverVersion,
            clientKexInit,
            serverKexInit,
            hostKey: this.hostKey,
            transientKey: this.transientPublicKey,
            encryptedSecret: this.encryptedSecret,
            sharedSecret: this.sharedSecret,
        })
    }

    generateKeyPair(): void {
        throw new Error("RSA key exchange uses a server-generated transient key")
    }

    getPublicKey(): Buffer {
        return this.getTransientPublicKey()
    }

    computeSharedSecret(): void {
        throw new Error("RSA key exchange uses encrypted shared-secret methods")
    }
}

function bitLength(value: Buffer): number {
    let first = 0
    while (first < value.length && value[first] === 0) first++
    if (first === value.length) return 0
    return (value.length - first - 1) * 8 + (32 - Math.clz32(value[first]))
}

function randomInteger(bits: number): Buffer {
    const bytes = Math.ceil(bits / 8)
    const excessBits = bytes * 8 - bits
    const value = randomBytes(bytes)
    value[0] &= 0xff >>> excessBits
    return value
}
