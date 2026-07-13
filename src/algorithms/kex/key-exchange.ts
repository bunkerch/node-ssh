import { createHash } from "crypto"

import type { KexAlgorithm } from "../../algorithms.js"
import type Client from "../../Client.js"
import type ServerClient from "../../ServerClient.js"
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

    abstract generateKeyPair(): void
    abstract getPublicKey(): Buffer
    abstract computeSharedSecret(peerPublicKey: Buffer): void
    abstract computeHClient(client: Client, serverKexInit: Buffer): Buffer
    abstract computeHServer(client: ServerClient, clientKexInit: Buffer, hostKey: Buffer): Buffer

    deriveKeysClient(client: Client | ServerClient): void {
        const [
            ivClientToServer,
            ivServerToClient,
            encryptionKeyClientToServer,
            encryptionKeyServerToClient,
            integrityKeyClientToServer,
            integrityKeyServerToClient,
        ] = this.deriveKeys(client.H!, client.sessionID!, [
            client.clientEncryptionAlgorithm!.iv_length,
            client.serverEncryptionAlgorithm!.iv_length,
            client.clientEncryptionAlgorithm!.key_length,
            client.serverEncryptionAlgorithm!.key_length,
            client.clientMacAlgorithm?.key_length ?? 0,
            client.serverMacAlgorithm?.key_length ?? 0,
        ])
        client.ivClientToServer = ivClientToServer
        client.ivServerToClient = ivServerToClient
        client.encryptionKeyClientToServer = encryptionKeyClientToServer
        client.encryptionKeyServerToClient = encryptionKeyServerToClient
        client.integrityKeyClientToServer = integrityKeyClientToServer
        client.integrityKeyServerToClient = integrityKeyServerToClient
    }

    protected computeExchangeHash(fields: readonly (Buffer | string)[]): Buffer {
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

    private deriveKeys(H: Buffer, sessionID: Buffer, keyLengths: number[]): Buffer[] {
        const K = serializeMpintBufferToBuffer(this.sharedSecret!)
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
