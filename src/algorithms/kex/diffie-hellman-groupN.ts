import { KexAlgorithm } from "../../algorithms.js"
import { DiffieHellmanGroup, createDiffieHellmanGroup, createHash } from "crypto"

import Client from "../../Client.js"
import { serializeMpintBufferToBuffer } from "../../utils/mpint.js"

export default class DiffieHellmanGroupN implements KexAlgorithm {
    static requires_encryption = false
    static requires_signature = true

    groupName: string
    hashName: string

    keyPair: DiffieHellmanGroup | undefined
    sharedSecret: Buffer | undefined

    constructor(groupName: string, hashName: string) {
        this.groupName = groupName
        this.hashName = hashName
    }

    generateKeyPair() {
        this.keyPair = createDiffieHellmanGroup(this.groupName)
        this.keyPair.generateKeys()
    }

    deriveKeysClient(client: Client): void {
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
            client.clientMacAlgorithm!.key_length,
            client.serverMacAlgorithm!.key_length,
        ])
        client.ivClientToServer = ivClientToServer
        client.ivServerToClient = ivServerToClient
        client.encryptionKeyClientToServer = encryptionKeyClientToServer
        client.encryptionKeyServerToClient = encryptionKeyServerToClient
        client.integrityKeyClientToServer = integrityKeyClientToServer
        client.integrityKeyServerToClient = integrityKeyServerToClient
    }

    deriveKeys(H: Buffer, sessionID: Buffer, keyLengths: number[]): Buffer[] {
        // TODO: The keys seem wrong.
        const K = serializeMpintBufferToBuffer(this.sharedSecret!)
        const K_Len = Buffer.allocUnsafe(4)
        K_Len.writeUint32BE(K.length)

        const buffers = []
        for (let i = 0; i < 6; i++) {
            const hash = createHash(this.hashName)
            hash.update(K_Len)
            hash.update(K)

            hash.update(H)
            // A => F
            hash.update(Buffer.from([65 + i]))
            hash.update(sessionID)

            let key = hash.digest()

            while (key.length < keyLengths[i]) {
                const hash = createHash(this.hashName)
                hash.update(K_Len)
                hash.update(K)

                hash.update(H)

                hash.update(key)

                key = Buffer.concat([key, hash.digest()])
                console.log(this.hashName, i, key.length, keyLengths[i])
            }

            buffers.push(key.subarray(0, keyLengths[i]))
        }
        return buffers
    }

    computeHClient(client: Client, I_S: Buffer) {
        return this.computeH(
            // V_C
            client.options.protocolVersionExchange.toString().slice(0, -2),
            // V_S
            client.serverProtocolVersion!.toString().slice(0, -2),

            // I_C
            client.clientKexInit!.serialize(),
            // I_S
            I_S,

            // K_S
            client.serverKexDHReply!.data.K_S,

            // e
            serializeMpintBufferToBuffer(this.keyPair!.getPublicKey()),
            // f
            serializeMpintBufferToBuffer(client.serverKexDHReply!.data.f),
            // K
            serializeMpintBufferToBuffer(this.sharedSecret!),
        )
    }

    computeH(
        V_C: string,
        V_S: string,
        I_C: Buffer,
        I_S: Buffer,

        K_S: Buffer,

        e: Buffer,
        f: Buffer,
        K: Buffer,
    ) {
        const hash = createHash(this.hashName)

        const length = Buffer.allocUnsafe(4)
        for (const buf of [
            Buffer.from(V_C, "utf8"),
            Buffer.from(V_S, "utf8"),
            I_C,
            I_S,
            K_S,
            e,
            f,
            K,
        ]) {
            length.writeUInt32BE(buf.length)
            hash.update(length)
            hash.update(buf)
        }

        return hash.digest()
    }
}
