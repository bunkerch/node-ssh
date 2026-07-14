import assert from "node:assert"
import { randomBytes } from "node:crypto"
import { ml_kem1024, ml_kem512, ml_kem768 } from "@noble/post-quantum/ml-kem.js"
import type { KEM } from "@noble/post-quantum/utils.js"

import type { KeyExchangeHashContext, KeyExchangeRole } from "../../algorithms.js"
import KeyExchange, { KeyExchangeError } from "./key-exchange.js"

type MLKEMHash = "sha256" | "sha384"

abstract class MLKEMKeyExchange extends KeyExchange {
    static requires_encryption = false
    static requires_signature = true

    readonly exchangeValueEncoding = "string" as const

    private readonly kem: KEM
    private role: KeyExchangeRole | undefined
    private kemSecretKey: Buffer | undefined
    private localPublicKey: Buffer | undefined

    protected constructor(hash: MLKEMHash, kem: KEM) {
        super(hash)
        this.kem = kem
    }

    generateKeyPair(role?: KeyExchangeRole): void {
        assert(role, "ML-KEM key exchange requires an explicit client or server role")
        this.wipeEphemeralState()
        this.role = role
    }

    getPublicKey(): Buffer {
        if (this.localPublicKey === undefined) {
            assert(this.role === "client", "ML-KEM server reply is not available yet")
            const seed = this.generateRandomBytes(64)
            try {
                const generated = this.kem.keygen(seed)
                this.kemSecretKey = Buffer.from(generated.secretKey)
                generated.secretKey.fill(0)
                this.localPublicKey = Buffer.from(generated.publicKey)
            } finally {
                seed.fill(0)
            }
        }
        return Buffer.from(this.localPublicKey)
    }

    computeSharedSecret(peerPublicKey: Buffer): void {
        const publicKeyBytes = this.kem.lengths.publicKey
        const ciphertextBytes = this.kem.lengths.cipherText
        assert(publicKeyBytes !== undefined && ciphertextBytes !== undefined)

        this.sharedSecret?.fill(0)
        this.sharedSecret = undefined

        try {
            if (this.role === "server") {
                if (peerPublicKey.length !== publicKeyBytes) {
                    throw new KeyExchangeError(
                        `ML-KEM client public keys must be ${publicKeyBytes} bytes`,
                    )
                }
                const seed = this.generateRandomBytes(32)
                try {
                    const encapsulation = this.kem.encapsulate(peerPublicKey, seed)
                    this.localPublicKey = Buffer.from(encapsulation.cipherText)
                    this.sharedSecret = Buffer.from(encapsulation.sharedSecret)
                    encapsulation.sharedSecret.fill(0)
                } catch (cause) {
                    throw new KeyExchangeError("Invalid ML-KEM encapsulation public key", { cause })
                } finally {
                    seed.fill(0)
                }
            } else if (this.role === "client") {
                if (peerPublicKey.length !== ciphertextBytes) {
                    throw new KeyExchangeError(
                        `ML-KEM server ciphertexts must be ${ciphertextBytes} bytes`,
                    )
                }
                if (this.kemSecretKey === undefined) {
                    throw new KeyExchangeError("ML-KEM client public key was not generated")
                }
                try {
                    const decapsulated = this.kem.decapsulate(peerPublicKey, this.kemSecretKey)
                    this.sharedSecret = Buffer.from(decapsulated)
                    decapsulated.fill(0)
                } catch (cause) {
                    throw new KeyExchangeError("Invalid ML-KEM ciphertext", { cause })
                }
            } else {
                throw new KeyExchangeError("ML-KEM key exchange role is unavailable")
            }
        } finally {
            this.kemSecretKey?.fill(0)
            this.kemSecretKey = undefined
        }
    }

    computeExchangeHash(context: Readonly<KeyExchangeHashContext>): Buffer {
        assert(this.localPublicKey, "ML-KEM local exchange value is unavailable")
        return this.hashFields([
            context.clientVersion,
            context.serverVersion,
            context.clientKexInit,
            context.serverKexInit,
            context.serverHostKey,
            this.requireExchangeValue(context, "client"),
            this.requireExchangeValue(context, "server"),
            this.sharedSecret!,
        ])
    }

    protected generateRandomBytes(length: number): Buffer {
        return randomBytes(length)
    }

    override dispose(): void {
        this.wipeEphemeralState()
    }

    private wipeEphemeralState(): void {
        this.kemSecretKey?.fill(0)
        this.sharedSecret?.fill(0)
        this.kemSecretKey = undefined
        this.localPublicKey = undefined
        this.role = undefined
        this.sharedSecret = undefined
    }
}

export class MLKEM512SHA256 extends MLKEMKeyExchange {
    static alg_name = "mlkem512-sha256"

    static instantiate(): MLKEM512SHA256 {
        return new MLKEM512SHA256()
    }

    constructor() {
        super("sha256", ml_kem512)
    }
}

export class MLKEM768SHA256 extends MLKEMKeyExchange {
    static alg_name = "mlkem768-sha256"

    static instantiate(): MLKEM768SHA256 {
        return new MLKEM768SHA256()
    }

    constructor() {
        super("sha256", ml_kem768)
    }
}

export class MLKEM1024SHA384 extends MLKEMKeyExchange {
    static alg_name = "mlkem1024-sha384"

    static instantiate(): MLKEM1024SHA384 {
        return new MLKEM1024SHA384()
    }

    constructor() {
        super("sha384", ml_kem1024)
    }
}
