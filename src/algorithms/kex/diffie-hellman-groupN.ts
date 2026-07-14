import {
    createDiffieHellman,
    createDiffieHellmanGroup,
    type DiffieHellman,
    type DiffieHellmanGroup,
} from "node:crypto"
import assert from "assert"

import Client from "../../Client.js"
import { serializeMpintBufferToBuffer } from "../../utils/mpint.js"
import { decodeBigIntBE } from "../../utils/BigInt.js"
import ServerClient from "../../ServerClient.js"
import KeyExchange, { KeyExchangeError } from "./key-exchange.js"
import {
    decodePositiveDHMPInt,
    keyExchangeErrorMessage,
    unsignedDHBuffer,
} from "./diffie-hellman-validation.js"

export default class DiffieHellmanGroupN extends KeyExchange {
    static requires_encryption = false
    static requires_signature = true

    readonly groupName: string
    readonly exchangeValueEncoding = "mpint" as const

    private keyPair: DiffieHellman | DiffieHellmanGroup | undefined
    private readonly privateKey: Buffer | undefined

    constructor(groupName: string, hashName: string, privateKey?: Buffer) {
        super(hashName)
        this.groupName = groupName
        this.privateKey = privateKey === undefined ? undefined : Buffer.from(privateKey)
    }

    generateKeyPair() {
        const group = createDiffieHellmanGroup(this.groupName)
        if (this.privateKey === undefined) {
            this.keyPair = group
        } else {
            const keyPair = createDiffieHellman(group.getPrime(), group.getGenerator())
            keyPair.setPrivateKey(this.privateKey)
            this.keyPair = keyPair
        }
        this.keyPair.generateKeys()
    }

    getPublicKey(): Buffer {
        return Buffer.from(this.keyPair!.getPublicKey())
    }

    computeSharedSecret(peerPublicKey: Buffer): Buffer {
        assert(this.keyPair, "Diffie-Hellman key pair was not generated")
        const peer = decodePositiveDHMPInt(peerPublicKey, "public value")
        const prime = decodeBigIntBE(this.keyPair.getPrime())
        if (peer <= 1n || peer >= prime - 1n) {
            throw new KeyExchangeError("Diffie-Hellman public value is outside (1, p-1)")
        }
        try {
            this.sharedSecret = Buffer.from(
                this.keyPair.computeSecret(unsignedDHBuffer(peerPublicKey)),
            )
        } catch (cause) {
            throw new KeyExchangeError(
                `Invalid Diffie-Hellman public value: ${keyExchangeErrorMessage(cause)}`,
            )
        }
        const sharedSecret = decodeBigIntBE(this.sharedSecret)
        if (sharedSecret <= 1n || sharedSecret >= prime - 1n) {
            throw new KeyExchangeError("Diffie-Hellman shared secret is outside (1, p-1)")
        }
        return Buffer.from(this.sharedSecret)
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
