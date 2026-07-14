import assert from "node:assert"
import { randomBytes } from "node:crypto"
import { x448 } from "@noble/curves/ed448.js"
import { KeyExchangeError } from "./key-exchange.js"
import RFC8731KeyExchange from "./rfc8731.js"

const KEY_LENGTH = 56

export default class Curve448SHA512 extends RFC8731KeyExchange {
    static alg_name = "curve448-sha512"
    static requires_encryption = false
    static requires_signature = true

    static instantiate(): Curve448SHA512 {
        return new Curve448SHA512()
    }

    private configuredPrivateKey: Buffer | undefined
    private privateKey: Buffer | undefined
    private publicKey: Buffer | undefined

    constructor(privateKey?: Buffer) {
        super("sha512")
        if (privateKey !== undefined) {
            assert(privateKey.length === KEY_LENGTH, "Curve448 private keys must be 56 bytes")
            this.configuredPrivateKey = Buffer.from(privateKey)
        }
    }

    generateKeyPair(): void {
        this.privateKey?.fill(0)
        this.sharedSecret?.fill(0)
        this.sharedSecret = undefined
        this.privateKey = this.configuredPrivateKey ?? randomBytes(KEY_LENGTH)
        this.configuredPrivateKey = undefined
        this.publicKey = Buffer.from(x448.getPublicKey(this.privateKey))
    }

    getPublicKey(): Buffer {
        assert(this.publicKey, "Curve448 key pair has not been generated")
        return Buffer.from(this.publicKey)
    }

    computeSharedSecret(peerPublicKey: Buffer): Buffer {
        if (peerPublicKey.length !== KEY_LENGTH) {
            throw new KeyExchangeError("Curve448 public keys must be 56 bytes")
        }
        assert(this.privateKey, "Curve448 key pair has not been generated")

        let sharedSecret: Buffer
        try {
            sharedSecret = Buffer.from(x448.getSharedSecret(this.privateKey, peerPublicKey))
        } catch (error) {
            throw new KeyExchangeError("Curve448 shared secret must not be all zero", {
                cause: error,
            })
        } finally {
            this.privateKey.fill(0)
            this.privateKey = undefined
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
