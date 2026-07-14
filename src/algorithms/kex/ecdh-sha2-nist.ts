import assert from "assert"
import { createECDH, type ECDH } from "crypto"

import type { KeyExchangeHashContext } from "../../algorithms.js"
import { serializeMpintBufferToBuffer } from "../../utils/mpint.js"
import KeyExchange, { KeyExchangeError } from "./key-exchange.js"

export default abstract class ECDHSHA2NIST extends KeyExchange {
    static requires_encryption = false
    static requires_signature = true

    readonly exchangeValueEncoding = "string" as const

    private readonly curveName: string
    private configuredPrivateKey: Buffer | undefined
    private keyPair: ECDH | undefined

    constructor(curveName: string, hashName: string, privateKey?: Buffer) {
        super(hashName)
        this.curveName = curveName
        this.configuredPrivateKey = privateKey === undefined ? undefined : Buffer.from(privateKey)
    }

    generateKeyPair(): void {
        this.keyPair = createECDH(this.curveName)
        if (this.configuredPrivateKey === undefined) this.keyPair.generateKeys()
        else this.keyPair.setPrivateKey(this.configuredPrivateKey)
        this.configuredPrivateKey?.fill(0)
        this.configuredPrivateKey = undefined
    }

    getPublicKey(): Buffer {
        assert(this.keyPair, "ECDH key pair has not been generated")
        return Buffer.from(this.keyPair.getPublicKey(undefined, "uncompressed"))
    }

    computeSharedSecret(peerPublicKey: Buffer): Buffer {
        assert(this.keyPair, "ECDH key pair has not been generated")
        try {
            this.sharedSecret = this.keyPair.computeSecret(peerPublicKey)
        } catch {
            throw new KeyExchangeError(`Invalid ${this.curveName} ECDH public key`)
        }
        return Buffer.from(this.sharedSecret)
    }

    computeExchangeHash(context: Readonly<KeyExchangeHashContext>): Buffer {
        return this.hashFields([
            context.clientVersion,
            context.serverVersion,
            context.clientKexInit,
            context.serverKexInit,
            context.serverHostKey,
            this.requireExchangeValue(context, "client"),
            this.requireExchangeValue(context, "server"),
            serializeMpintBufferToBuffer(this.sharedSecret!),
        ])
    }

    override dispose(): void {
        this.configuredPrivateKey?.fill(0)
        this.configuredPrivateKey = undefined
        this.keyPair = undefined
        super.dispose()
    }
}

export class ECDHSHA2NISTP256 extends ECDHSHA2NIST {
    static alg_name = "ecdh-sha2-nistp256"

    static instantiate(): ECDHSHA2NISTP256 {
        return new ECDHSHA2NISTP256()
    }

    constructor(privateKey?: Buffer) {
        super("prime256v1", "sha256", privateKey)
    }
}

export class ECDHSHA2NISTP384 extends ECDHSHA2NIST {
    static alg_name = "ecdh-sha2-nistp384"

    static instantiate(): ECDHSHA2NISTP384 {
        return new ECDHSHA2NISTP384()
    }

    constructor(privateKey?: Buffer) {
        super("secp384r1", "sha384", privateKey)
    }
}

export class ECDHSHA2NISTP521 extends ECDHSHA2NIST {
    static alg_name = "ecdh-sha2-nistp521"

    static instantiate(): ECDHSHA2NISTP521 {
        return new ECDHSHA2NISTP521()
    }

    constructor(privateKey?: Buffer) {
        super("secp521r1", "sha512", privateKey)
    }
}
