import assert from "assert"
import { randomBytes } from "crypto"
import nacl from "tweetnacl"

import { KeyExchangeError } from "./key-exchange.js"
import RFC8731KeyExchange from "./rfc8731.js"

export default class Curve25519SHA256 extends RFC8731KeyExchange {
    static alg_name = "curve25519-sha256"
    static requires_encryption = false
    static requires_signature = true

    static instantiate(): Curve25519SHA256 {
        return new Curve25519SHA256()
    }

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
        this.privateKey?.fill(0)
        this.sharedSecret?.fill(0)
        this.sharedSecret = undefined
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

    override dispose(): void {
        this.configuredPrivateKey?.fill(0)
        this.privateKey?.fill(0)
        this.configuredPrivateKey = undefined
        this.privateKey = undefined
        this.publicKey = undefined
        super.dispose()
    }
}

export class Curve25519SHA256LibSSH extends Curve25519SHA256 {
    static alg_name = "curve25519-sha256@libssh.org"

    static instantiate(): Curve25519SHA256LibSSH {
        return new Curve25519SHA256LibSSH()
    }
}
