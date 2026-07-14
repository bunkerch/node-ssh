import assert from "node:assert"
import { createHash, randomBytes } from "node:crypto"
import nacl from "tweetnacl"

import type Client from "../../Client.js"
import type ServerClient from "../../ServerClient.js"
import type { KeyExchangeRole } from "../../algorithms.js"
import {
    decapsulateSNTRUP761,
    encapsulateSNTRUP761,
    generateSNTRUP761KeyPair,
    SNTRUP761_CIPHERTEXT_BYTES,
    SNTRUP761_PUBLIC_KEY_BYTES,
    type SNTRUP761KeyPair,
} from "../../utils/SNTRUP761.js"
import KeyExchange, { KeyExchangeError } from "./key-exchange.js"

const X25519_KEY_BYTES = 32
const CLIENT_PUBLIC_KEY_BYTES = SNTRUP761_PUBLIC_KEY_BYTES + X25519_KEY_BYTES
const SERVER_PUBLIC_KEY_BYTES = SNTRUP761_CIPHERTEXT_BYTES + X25519_KEY_BYTES

export function combineSNTRUP761X25519Secrets(
    kemSharedSecret: Buffer,
    x25519SharedSecret: Buffer,
): Buffer {
    assert(kemSharedSecret.length === 32, "sntrup761 shared secrets must be 32 bytes")
    assert(x25519SharedSecret.length === 32, "X25519 shared secrets must be 32 bytes")
    return createHash("sha512").update(kemSharedSecret).update(x25519SharedSecret).digest()
}

export default class SNTRUP761X25519SHA512 extends KeyExchange {
    static alg_name = "sntrup761x25519-sha512"
    static requires_encryption = false
    static requires_signature = true

    static instantiate(): SNTRUP761X25519SHA512 {
        return new SNTRUP761X25519SHA512()
    }

    readonly exchangeValueEncoding = "string" as const

    private configuredX25519PrivateKey: Buffer | undefined
    private x25519PrivateKey: Buffer | undefined
    private x25519PublicKey: Buffer | undefined
    private kemKeyPair: SNTRUP761KeyPair | undefined
    private localPublicKey: Buffer | undefined
    private role: KeyExchangeRole | undefined

    constructor(x25519PrivateKey?: Buffer) {
        super("sha512")
        if (x25519PrivateKey !== undefined) {
            assert(x25519PrivateKey.length === 32, "X25519 private keys must be 32 bytes")
            this.configuredX25519PrivateKey = Buffer.from(x25519PrivateKey)
        }
    }

    generateKeyPair(role?: KeyExchangeRole): void {
        assert(role, "Hybrid key exchange requires an explicit client or server role")
        this.wipeEphemeralState()
        this.role = role
        this.x25519PrivateKey = this.configuredX25519PrivateKey ?? randomBytes(X25519_KEY_BYTES)
        this.configuredX25519PrivateKey = undefined
        this.x25519PublicKey = Buffer.from(nacl.scalarMult.base(this.x25519PrivateKey))
    }

    getPublicKey(): Buffer {
        assert(this.x25519PublicKey, "Hybrid key pair has not been generated")
        if (this.localPublicKey === undefined) {
            assert(this.role === "client", "Hybrid server public key is not available yet")
            this.kemKeyPair = generateSNTRUP761KeyPair()
            this.localPublicKey = Buffer.concat([this.kemKeyPair.publicKey, this.x25519PublicKey])
        }
        return Buffer.from(this.localPublicKey)
    }

    computeSharedSecret(peerPublicKey: Buffer): void {
        assert(this.x25519PrivateKey, "Hybrid key pair has not been generated")
        assert(this.x25519PublicKey, "Hybrid key pair has not been generated")
        let kemSharedSecret: Buffer
        let peerX25519PublicKey: Buffer
        if (this.role === "server") {
            if (peerPublicKey.length !== CLIENT_PUBLIC_KEY_BYTES) {
                throw new KeyExchangeError(
                    `Hybrid client public keys must be ${CLIENT_PUBLIC_KEY_BYTES} bytes`,
                )
            }
            const encapsulation = encapsulateSNTRUP761(
                peerPublicKey.subarray(0, SNTRUP761_PUBLIC_KEY_BYTES),
            )
            kemSharedSecret = encapsulation.sharedSecret
            peerX25519PublicKey = peerPublicKey.subarray(SNTRUP761_PUBLIC_KEY_BYTES)
            this.localPublicKey = Buffer.concat([encapsulation.ciphertext, this.x25519PublicKey])
        } else if (this.role === "client") {
            if (peerPublicKey.length !== SERVER_PUBLIC_KEY_BYTES) {
                throw new KeyExchangeError(
                    `Hybrid server public keys must be ${SERVER_PUBLIC_KEY_BYTES} bytes`,
                )
            }
            if (this.kemKeyPair === undefined) {
                throw new KeyExchangeError("Hybrid client public key was not generated")
            }
            kemSharedSecret = decapsulateSNTRUP761(
                peerPublicKey.subarray(0, SNTRUP761_CIPHERTEXT_BYTES),
                this.kemKeyPair.secretKey,
            )
            peerX25519PublicKey = peerPublicKey.subarray(SNTRUP761_CIPHERTEXT_BYTES)
        } else {
            throw new KeyExchangeError("Hybrid key exchange role is unavailable")
        }

        let x25519SharedSecret: Buffer | undefined
        try {
            x25519SharedSecret = Buffer.from(
                nacl.scalarMult(this.x25519PrivateKey, peerX25519PublicKey),
            )
            let nonzero = 0
            for (const byte of x25519SharedSecret) nonzero |= byte
            if (nonzero === 0) throw new Error("all-zero X25519 output")
            this.sharedSecret = combineSNTRUP761X25519Secrets(kemSharedSecret, x25519SharedSecret)
        } catch (error) {
            throw new KeyExchangeError("Hybrid X25519 shared secret must not be all zero", {
                cause: error,
            })
        } finally {
            kemSharedSecret.fill(0)
            x25519SharedSecret?.fill(0)
            this.x25519PrivateKey.fill(0)
            this.x25519PrivateKey = undefined
            this.kemKeyPair?.secretKey.fill(0)
            this.kemKeyPair = undefined
        }
    }

    computeHClient(client: Client, serverKexInit: Buffer): Buffer {
        assert(this.localPublicKey, "Hybrid client public key is unavailable")
        return this.computeExchangeHash([
            client.options.protocolVersionExchange.toString().slice(0, -2),
            client.serverProtocolVersion!.toString().slice(0, -2),
            client.clientKexInitPayload!,
            serverKexInit,
            client.serverKexDHReply!.data.K_S,
            this.localPublicKey,
            client.serverKexDHReply!.data.f,
            this.sharedSecret!,
        ])
    }

    computeHServer(client: ServerClient, clientKexInit: Buffer, hostKey: Buffer): Buffer {
        assert(this.localPublicKey, "Hybrid server public key is unavailable")
        return this.computeExchangeHash([
            client.clientProtocolVersion!.toString().slice(0, -2),
            client.server.options.protocolVersionExchange!.toString().slice(0, -2),
            clientKexInit,
            client.serverKexInitPayload!,
            hostKey,
            client.clientKexDHInit!.data.e,
            this.localPublicKey,
            this.sharedSecret!,
        ])
    }

    protected encodeSharedSecret(): Buffer {
        assert(this.sharedSecret, "Hybrid shared secret has not been computed")
        return this.sharedSecret
    }

    private wipeEphemeralState(): void {
        this.x25519PrivateKey?.fill(0)
        this.kemKeyPair?.secretKey.fill(0)
        this.sharedSecret?.fill(0)
        this.x25519PrivateKey = undefined
        this.x25519PublicKey = undefined
        this.kemKeyPair = undefined
        this.localPublicKey = undefined
        this.role = undefined
        this.sharedSecret = undefined
    }
}

export class SNTRUP761X25519SHA512OpenSSH extends SNTRUP761X25519SHA512 {
    static alg_name = "sntrup761x25519-sha512@openssh.com"

    static instantiate(): SNTRUP761X25519SHA512OpenSSH {
        return new SNTRUP761X25519SHA512OpenSSH()
    }
}
