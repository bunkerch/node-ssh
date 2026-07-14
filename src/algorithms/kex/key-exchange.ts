import { createHash } from "crypto"

import type {
    DerivedTransportKeys,
    KexAlgorithm,
    KeyExchangeHashContext,
    TransportKeyLengths,
} from "../../algorithms.js"
import type { KeyExchangeRole } from "../../algorithms.js"
import { serializeMpintBufferToBuffer } from "../../utils/mpint.js"

export type ExchangeValueEncoding = "mpint" | "string"

export class KeyExchangeError extends Error {
    name = "KeyExchangeError"
}

export default abstract class KeyExchange implements KexAlgorithm {
    abstract readonly exchangeValueEncoding: ExchangeValueEncoding

    protected readonly hashName: string
    protected sharedSecret: Buffer | undefined

    constructor(hashName: string) {
        this.hashName = hashName
    }

    abstract generateKeyPair(role?: KeyExchangeRole): void
    abstract getPublicKey(): Buffer
    abstract computeSharedSecret(peerPublicKey: Buffer): void
    abstract computeExchangeHash(context: Readonly<KeyExchangeHashContext>): Buffer

    getSharedSecret(): Buffer {
        if (!this.sharedSecret) throw new KeyExchangeError("Shared secret has not been computed")
        return Buffer.from(this.sharedSecret)
    }

    dispose(): void {
        this.sharedSecret?.fill(0)
        this.sharedSecret = undefined
    }

    deriveTransportKeys(
        exchangeHash: Buffer,
        sessionID: Buffer,
        lengths: TransportKeyLengths,
    ): DerivedTransportKeys {
        const [
            clientIV,
            serverIV,
            clientEncryption,
            serverEncryption,
            clientIntegrity,
            serverIntegrity,
        ] = this.deriveKeys(exchangeHash, sessionID, [
            lengths.clientIV,
            lengths.serverIV,
            lengths.clientEncryption,
            lengths.serverEncryption,
            lengths.clientIntegrity,
            lengths.serverIntegrity,
        ])
        return {
            clientIV,
            serverIV,
            clientEncryption,
            serverEncryption,
            clientIntegrity,
            serverIntegrity,
        }
    }

    protected hashFields(fields: readonly (Buffer | string)[]): Buffer {
        const hash = createHash(this.hashName)
        const length = Buffer.allocUnsafe(4)

        for (const field of fields) {
            const buffer = typeof field === "string" ? Buffer.from(field, "utf8") : field
            length.writeUInt32BE(buffer.length)
            hash.update(length)
            hash.update(buffer)
        }

        return hash.digest()
    }

    protected encodeSharedSecret(): Buffer {
        return serializeMpintBufferToBuffer(this.sharedSecret!)
    }

    protected requireExchangeValue(
        context: Readonly<KeyExchangeHashContext>,
        role: "client" | "server",
    ): Buffer {
        const value = role === "client" ? context.clientExchangeValue : context.serverExchangeValue
        if (!value) throw new KeyExchangeError(`${role} exchange value is unavailable`)
        return value
    }

    private deriveKeys(H: Buffer, sessionID: Buffer, keyLengths: number[]): Buffer[] {
        const K = this.encodeSharedSecret()
        const KLength = Buffer.allocUnsafe(4)
        KLength.writeUint32BE(K.length)

        const buffers = []
        for (let i = 0; i < 6; i++) {
            const hash = createHash(this.hashName)
            hash.update(KLength)
            hash.update(K)
            hash.update(H)
            hash.update(Buffer.from([65 + i]))
            hash.update(sessionID)

            let key = hash.digest()

            while (key.length < keyLengths[i]) {
                const hash = createHash(this.hashName)
                hash.update(KLength)
                hash.update(K)
                hash.update(H)
                hash.update(key)
                key = Buffer.concat([key, hash.digest()])
            }

            buffers.push(key.subarray(0, keyLengths[i]))
        }
        return buffers
    }
}
