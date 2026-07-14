import { DiffieHellmanGroup, createDiffieHellmanGroup } from "crypto"
import assert from "assert"

import Client from "../../Client.js"
import { serializeMpintBufferToBuffer } from "../../utils/mpint.js"
import ServerClient from "../../ServerClient.js"
import KeyExchange from "./key-exchange.js"

export default class DiffieHellmanGroupN extends KeyExchange {
    static requires_encryption = false
    static requires_signature = true

    groupName: string
    readonly exchangeValueEncoding = "mpint" as const

    keyPair: DiffieHellmanGroup | undefined

    constructor(groupName: string, hashName: string) {
        super(hashName)
        this.groupName = groupName
    }

    generateKeyPair() {
        this.keyPair = createDiffieHellmanGroup(this.groupName)
        this.keyPair.generateKeys()
    }

    getPublicKey(): Buffer {
        return Buffer.from(this.keyPair!.getPublicKey())
    }

    computeSharedSecret(peerPublicKey: Buffer): void {
        assert(
            peerPublicKey.length === 0 || (peerPublicKey[0] & 0x80) === 0,
            "Diffie-Hellman public value must be a non-negative mpint",
        )
        this.sharedSecret = this.keyPair!.computeSecret(peerPublicKey)
    }

    computeHClient(client: Client, I_S: Buffer) {
        return this.computeExchangeHash([
            // V_C
            client.options.protocolVersionExchange.toString().slice(0, -2),
            // V_S
            client.serverProtocolVersion!.toString().slice(0, -2),

            // I_C
            client.clientKexInitPayload!,
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
        ])
    }

    computeHServer(client: ServerClient, I_C: Buffer, K_S: Buffer) {
        return this.computeExchangeHash([
            // V_C
            client.clientProtocolVersion!.toString().slice(0, -2),
            // V_S
            client.server.options.protocolVersionExchange!.toString().slice(0, -2),

            // I_C
            I_C,
            // I_S
            client.serverKexInitPayload!,

            // K_S
            K_S,

            // e
            serializeMpintBufferToBuffer(client.clientKexDHInit!.data.e),
            // f
            serializeMpintBufferToBuffer(this.keyPair!.getPublicKey()),
            // K
            serializeMpintBufferToBuffer(this.sharedSecret!),
        ])
    }
}
