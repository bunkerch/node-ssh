import assert from "node:assert"
import { createECDH, createHash, randomBytes, type ECDH } from "node:crypto"
import { ml_kem1024, ml_kem768 } from "@noble/post-quantum/ml-kem.js"
import type { KEM } from "@noble/post-quantum/utils.js"
import nacl from "tweetnacl"

import type { KeyExchangeHashContext, KeyExchangeRole } from "../../algorithms.js"
import KeyExchange, { KeyExchangeError } from "./key-exchange.js"

type HybridHash = "sha256" | "sha384"
type ClassicalCurve = "x25519" | "prime256v1" | "secp384r1"

export interface MLKEMHybridOptions {
    /** Deterministic test input. Production callers should leave this undefined. */
    classicalPrivateKey?: Buffer
    /** FIPS 203 d || z deterministic test input. Production callers should leave this undefined. */
    mlkemSeed?: Buffer
    /** FIPS 203 encapsulation input for tests. Production callers should leave this undefined. */
    encapsulationSeed?: Buffer
}

export function combineMLKEMHybridSecrets(
    hash: HybridHash,
    postQuantumSharedSecret: Buffer,
    classicalSharedSecret: Buffer,
): Buffer {
    assert(postQuantumSharedSecret.length === 32, "ML-KEM shared secrets must be 32 bytes")
    const expectedClassicalBytes = hash === "sha256" ? 32 : 48
    assert(
        classicalSharedSecret.length === expectedClassicalBytes,
        `${hash} hybrid classical shared secrets must be ${expectedClassicalBytes} bytes`,
    )
    return createHash(hash).update(postQuantumSharedSecret).update(classicalSharedSecret).digest()
}

abstract class MLKEMHybridKeyExchange extends KeyExchange {
    static requires_encryption = false
    static requires_signature = true

    readonly exchangeValueEncoding = "string" as const

    private readonly kem: KEM
    private readonly curve: ClassicalCurve
    private readonly classicalSharedSecretBytes: number
    private readonly classicalPublicKeyLengths: readonly number[]
    private configuredClassicalPrivateKey: Buffer | undefined
    private configuredMLKEMSeed: Buffer | undefined
    private configuredEncapsulationSeed: Buffer | undefined
    private role: KeyExchangeRole | undefined
    private x25519PrivateKey: Buffer | undefined
    private ecdh: ECDH | undefined
    private classicalPublicKey: Buffer | undefined
    private kemSecretKey: Buffer | undefined
    private localPublicKey: Buffer | undefined

    protected constructor(
        hash: HybridHash,
        kem: KEM,
        curve: ClassicalCurve,
        options: MLKEMHybridOptions = {},
    ) {
        super(hash)
        this.kem = kem
        this.curve = curve
        this.classicalSharedSecretBytes = curve === "secp384r1" ? 48 : 32
        this.classicalPublicKeyLengths =
            curve === "x25519" ? [32] : curve === "prime256v1" ? [33, 65] : [49, 97]
        if (options.classicalPrivateKey !== undefined) {
            assert(
                options.classicalPrivateKey.length === this.classicalSharedSecretBytes,
                `${curve} private keys must be ${this.classicalSharedSecretBytes} bytes`,
            )
            this.configuredClassicalPrivateKey = Buffer.from(options.classicalPrivateKey)
        }
        if (options.mlkemSeed !== undefined) {
            assert(options.mlkemSeed.length === 64, "ML-KEM key generation seeds must be 64 bytes")
            this.configuredMLKEMSeed = Buffer.from(options.mlkemSeed)
        }
        if (options.encapsulationSeed !== undefined) {
            assert(
                options.encapsulationSeed.length === 32,
                "ML-KEM encapsulation seeds must be 32 bytes",
            )
            this.configuredEncapsulationSeed = Buffer.from(options.encapsulationSeed)
        }
    }

    generateKeyPair(role?: KeyExchangeRole): void {
        assert(role, "Hybrid key exchange requires an explicit client or server role")
        this.wipeEphemeralState()
        this.role = role
        if (this.curve === "x25519") {
            this.x25519PrivateKey = this.configuredClassicalPrivateKey ?? randomBytes(32)
            this.configuredClassicalPrivateKey = undefined
            this.classicalPublicKey = Buffer.from(nacl.scalarMult.base(this.x25519PrivateKey))
            return
        }
        this.ecdh = createECDH(this.curve)
        const configuredPrivateKey = this.configuredClassicalPrivateKey
        this.configuredClassicalPrivateKey = undefined
        try {
            if (configuredPrivateKey === undefined) this.ecdh.generateKeys()
            else this.ecdh.setPrivateKey(configuredPrivateKey)
        } finally {
            configuredPrivateKey?.fill(0)
        }
        this.classicalPublicKey = Buffer.from(this.ecdh.getPublicKey(undefined, "uncompressed"))
    }

    getPublicKey(): Buffer {
        assert(this.classicalPublicKey, "Hybrid key pair has not been generated")
        if (this.localPublicKey === undefined) {
            assert(this.role === "client", "Hybrid server public key is not available yet")
            const seed = this.configuredMLKEMSeed ?? randomBytes(64)
            this.configuredMLKEMSeed = undefined
            try {
                const generated = this.kem.keygen(seed)
                this.kemSecretKey = Buffer.from(generated.secretKey)
                generated.secretKey.fill(0)
                this.localPublicKey = Buffer.concat([
                    Buffer.from(generated.publicKey),
                    this.classicalPublicKey,
                ])
            } finally {
                seed.fill(0)
            }
        }
        return Buffer.from(this.localPublicKey)
    }

    computeSharedSecret(peerPublicKey: Buffer): void {
        assert(this.classicalPublicKey, "Hybrid key pair has not been generated")
        const kemPublicKeyBytes = this.kem.lengths.publicKey
        const kemCiphertextBytes = this.kem.lengths.cipherText
        assert(kemPublicKeyBytes !== undefined && kemCiphertextBytes !== undefined)

        let postQuantumSharedSecret: Buffer | undefined
        let classicalSharedSecret: Buffer | undefined
        try {
            if (this.role === "server") {
                const peerClassicalKey = this.splitPeerPublicKey(
                    peerPublicKey,
                    kemPublicKeyBytes,
                    "client",
                )
                let encapsulation: ReturnType<KEM["encapsulate"]>
                const seed = this.configuredEncapsulationSeed ?? randomBytes(32)
                this.configuredEncapsulationSeed = undefined
                try {
                    encapsulation = this.kem.encapsulate(
                        peerPublicKey.subarray(0, kemPublicKeyBytes),
                        seed,
                    )
                } catch (error) {
                    throw new KeyExchangeError("Invalid ML-KEM encapsulation public key", {
                        cause: error,
                    })
                } finally {
                    seed.fill(0)
                }
                postQuantumSharedSecret = Buffer.from(encapsulation.sharedSecret)
                encapsulation.sharedSecret.fill(0)
                this.localPublicKey = Buffer.concat([
                    Buffer.from(encapsulation.cipherText),
                    this.classicalPublicKey,
                ])
                classicalSharedSecret = this.computeClassicalSharedSecret(peerClassicalKey)
            } else if (this.role === "client") {
                const peerClassicalKey = this.splitPeerPublicKey(
                    peerPublicKey,
                    kemCiphertextBytes,
                    "server",
                )
                if (this.kemSecretKey === undefined) {
                    throw new KeyExchangeError("Hybrid client public key was not generated")
                }
                try {
                    const decapsulated = this.kem.decapsulate(
                        peerPublicKey.subarray(0, kemCiphertextBytes),
                        this.kemSecretKey,
                    )
                    postQuantumSharedSecret = Buffer.from(decapsulated)
                    decapsulated.fill(0)
                } catch (error) {
                    throw new KeyExchangeError("Invalid ML-KEM ciphertext", { cause: error })
                }
                classicalSharedSecret = this.computeClassicalSharedSecret(peerClassicalKey)
            } else {
                throw new KeyExchangeError("Hybrid key exchange role is unavailable")
            }
            this.sharedSecret = combineMLKEMHybridSecrets(
                this.hashName as HybridHash,
                postQuantumSharedSecret,
                classicalSharedSecret,
            )
        } finally {
            postQuantumSharedSecret?.fill(0)
            classicalSharedSecret?.fill(0)
            this.x25519PrivateKey?.fill(0)
            this.x25519PrivateKey = undefined
            this.ecdh = undefined
            this.kemSecretKey?.fill(0)
            this.kemSecretKey = undefined
        }
    }

    computeExchangeHash(context: Readonly<KeyExchangeHashContext>): Buffer {
        assert(this.localPublicKey, "Hybrid client public key is unavailable")
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

    protected encodeSharedSecret(): Buffer {
        assert(this.sharedSecret, "Hybrid shared secret has not been computed")
        return this.sharedSecret
    }

    override dispose(): void {
        this.configuredClassicalPrivateKey?.fill(0)
        this.configuredMLKEMSeed?.fill(0)
        this.configuredEncapsulationSeed?.fill(0)
        this.configuredClassicalPrivateKey = undefined
        this.configuredMLKEMSeed = undefined
        this.configuredEncapsulationSeed = undefined
        this.wipeEphemeralState()
    }

    private splitPeerPublicKey(
        peerPublicKey: Buffer,
        postQuantumBytes: number,
        role: "client" | "server",
    ): Buffer {
        const classicalBytes = peerPublicKey.length - postQuantumBytes
        if (!this.classicalPublicKeyLengths.includes(classicalBytes)) {
            throw new KeyExchangeError(
                `Hybrid ${role} public keys have an invalid length (${peerPublicKey.length} bytes)`,
            )
        }
        return peerPublicKey.subarray(postQuantumBytes)
    }

    private computeClassicalSharedSecret(peerPublicKey: Buffer): Buffer {
        if (this.curve === "x25519") {
            assert(this.x25519PrivateKey, "Hybrid X25519 key pair has not been generated")
            const sharedSecret = Buffer.from(nacl.scalarMult(this.x25519PrivateKey, peerPublicKey))
            let nonzero = 0
            for (const byte of sharedSecret) nonzero |= byte
            if (nonzero === 0) {
                sharedSecret.fill(0)
                throw new KeyExchangeError("Hybrid X25519 shared secret must not be all zero")
            }
            return sharedSecret
        }
        assert(this.ecdh, "Hybrid ECDH key pair has not been generated")
        try {
            const sharedSecret = Buffer.from(this.ecdh.computeSecret(peerPublicKey))
            assert(sharedSecret.length === this.classicalSharedSecretBytes)
            return sharedSecret
        } catch (error) {
            throw new KeyExchangeError(`Invalid hybrid ${this.curve} ECDH public key`, {
                cause: error,
            })
        }
    }

    private wipeEphemeralState(): void {
        this.x25519PrivateKey?.fill(0)
        this.kemSecretKey?.fill(0)
        this.sharedSecret?.fill(0)
        this.x25519PrivateKey = undefined
        this.ecdh = undefined
        this.classicalPublicKey = undefined
        this.kemSecretKey = undefined
        this.localPublicKey = undefined
        this.role = undefined
        this.sharedSecret = undefined
    }
}

export class MLKEM768NISTP256SHA256 extends MLKEMHybridKeyExchange {
    static alg_name = "mlkem768nistp256-sha256"

    static instantiate(): MLKEM768NISTP256SHA256 {
        return new MLKEM768NISTP256SHA256()
    }

    constructor(options: MLKEMHybridOptions = {}) {
        super("sha256", ml_kem768, "prime256v1", options)
    }
}

export class MLKEM1024NISTP384SHA384 extends MLKEMHybridKeyExchange {
    static alg_name = "mlkem1024nistp384-sha384"

    static instantiate(): MLKEM1024NISTP384SHA384 {
        return new MLKEM1024NISTP384SHA384()
    }

    constructor(options: MLKEMHybridOptions = {}) {
        super("sha384", ml_kem1024, "secp384r1", options)
    }
}

export class MLKEM768X25519SHA256 extends MLKEMHybridKeyExchange {
    static alg_name = "mlkem768x25519-sha256"

    static instantiate(): MLKEM768X25519SHA256 {
        return new MLKEM768X25519SHA256()
    }

    constructor(options: MLKEMHybridOptions = {}) {
        super("sha256", ml_kem768, "x25519", options)
    }
}
