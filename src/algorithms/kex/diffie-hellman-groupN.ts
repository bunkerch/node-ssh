import {
    createDiffieHellman,
    createDiffieHellmanGroup,
    type DiffieHellman,
    type DiffieHellmanGroup,
} from "node:crypto"
import assert from "assert"

import type { KeyExchangeHashContext } from "../../algorithms.js"
import { serializeMpintBufferToBuffer } from "../../utils/mpint.js"
import { decodeBigIntBE } from "../../utils/BigInt.js"
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
    private privateKey: Buffer | undefined
    private readonly parameters: Readonly<{ prime: Buffer; generator: Buffer }> | undefined

    constructor(
        groupName: string,
        hashName: string,
        privateKey?: Buffer,
        parameters?: Readonly<{ prime: Buffer; generator: Buffer }>,
    ) {
        super(hashName)
        this.groupName = groupName
        this.privateKey = privateKey === undefined ? undefined : Buffer.from(privateKey)
        this.parameters =
            parameters === undefined
                ? undefined
                : {
                      prime: Buffer.from(parameters.prime),
                      generator: Buffer.from(parameters.generator),
                  }
    }

    generateKeyPair() {
        try {
            if (this.parameters !== undefined) {
                const keyPair = createDiffieHellman(
                    this.parameters.prime,
                    this.parameters.generator,
                )
                if (this.privateKey !== undefined) keyPair.setPrivateKey(this.privateKey)
                this.keyPair = keyPair
            } else {
                const group = createDiffieHellmanGroup(this.groupName)
                if (this.privateKey === undefined) {
                    this.keyPair = group
                } else {
                    const keyPair = createDiffieHellman(group.getPrime(), group.getGenerator())
                    keyPair.setPrivateKey(this.privateKey)
                    this.keyPair = keyPair
                }
            }
            this.keyPair.generateKeys()
        } finally {
            this.privateKey?.fill(0)
            this.privateKey = undefined
        }
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

    computeExchangeHash(context: Readonly<KeyExchangeHashContext>): Buffer {
        return this.hashFields([
            // V_C
            context.clientVersion,
            // V_S
            context.serverVersion,

            // I_C
            context.clientKexInit,
            // I_S
            context.serverKexInit,

            // K_S
            context.serverHostKey,

            // e
            serializeMpintBufferToBuffer(this.requireExchangeValue(context, "client")),
            // f
            serializeMpintBufferToBuffer(this.requireExchangeValue(context, "server")),
            // K
            serializeMpintBufferToBuffer(this.sharedSecret!),
        ])
    }

    override dispose(): void {
        this.privateKey?.fill(0)
        this.privateKey = undefined
        this.keyPair = undefined
        super.dispose()
    }
}
