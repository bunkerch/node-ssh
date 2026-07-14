import assert from "assert"
import { randomBytes } from "crypto"
import nacl from "tweetnacl"

import type Client from "../../Client.js"
import type ServerClient from "../../ServerClient.js"
import { serializeMpintBufferToBuffer } from "../../utils/mpint.js"
import KeyExchange, { KeyExchangeError } from "./key-exchange.js"

export default class Curve25519SHA256 extends KeyExchange {
    static alg_name = "curve25519-sha256"
    static requires_encryption = false
    static requires_signature = true

    static instantiate(): Curve25519SHA256 {
        return new Curve25519SHA256()
    }

    readonly exchangeValueEncoding = "string" as const

    private configuredPrivateKey: Buffer | undefined
    private privateKey: Buffer | undefined
    private publicKey: Buffer | undefined

    constructor(privateKey?: Buffer) {
        super("sha256")
        if (privateKey !== undefined) {
            assert(privateKey.length === 32, "Curve25519 private keys must be 32 bytes")
            this.configuredPrivateKey = Buffer.from(privateKey)
        }
    }

    generateKeyPair(): void {
        this.privateKey = this.configuredPrivateKey ?? randomBytes(32)
        this.configuredPrivateKey = undefined
        this.publicKey = Buffer.from(nacl.scalarMult.base(this.privateKey))
    }

    getPublicKey(): Buffer {
        assert(this.publicKey, "Curve25519 key pair has not been generated")
        return Buffer.from(this.publicKey)
    }

    computeSharedSecret(peerPublicKey: Buffer): Buffer {
        if (peerPublicKey.length !== 32) {
            throw new KeyExchangeError("Curve25519 public keys must be 32 bytes")
        }
        assert(this.privateKey, "Curve25519 key pair has not been generated")

        const sharedSecret = Buffer.from(nacl.scalarMult(this.privateKey, peerPublicKey))
        this.privateKey.fill(0)
        this.privateKey = undefined

        let nonzero = 0
        for (const byte of sharedSecret) nonzero |= byte
        if (nonzero === 0) {
            throw new KeyExchangeError("Curve25519 shared secret must not be all zero")
        }

        this.sharedSecret = sharedSecret
        return Buffer.from(sharedSecret)
    }

    computeHClient(client: Client, serverKexInit: Buffer): Buffer {
        return this.computeExchangeHash([
            client.options.protocolVersionExchange.toString().slice(0, -2),
            client.serverProtocolVersion!.toString().slice(0, -2),
            client.clientKexInitPayload!,
            serverKexInit,
            client.serverKexDHReply!.data.K_S,
            this.getPublicKey(),
            client.serverKexDHReply!.data.f,
            serializeMpintBufferToBuffer(this.sharedSecret!),
        ])
    }

    computeHServer(client: ServerClient, clientKexInit: Buffer, hostKey: Buffer): Buffer {
        return this.computeExchangeHash([
            client.clientProtocolVersion!.toString().slice(0, -2),
            client.server.options.protocolVersionExchange!.toString().slice(0, -2),
            clientKexInit,
            client.serverKexInitPayload!,
            hostKey,
            client.clientKexDHInit!.data.e,
            this.getPublicKey(),
            serializeMpintBufferToBuffer(this.sharedSecret!),
        ])
    }
}

export class Curve25519SHA256LibSSH extends Curve25519SHA256 {
    static alg_name = "curve25519-sha256@libssh.org"

    static instantiate(): Curve25519SHA256LibSSH {
        return new Curve25519SHA256LibSSH()
    }
}
