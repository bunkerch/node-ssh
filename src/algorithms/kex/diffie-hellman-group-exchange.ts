import {
    createDiffieHellman,
    createDiffieHellmanGroup,
    createHash,
    constants,
    type DiffieHellman,
    type DiffieHellmanGroup,
} from "node:crypto"

import type { KeyExchangeHashContext } from "../../algorithms.js"
import type { KexDHGexRequestData } from "../../packets/KexDHGexRequest.js"
import { decodeBigIntBE } from "../../utils/BigInt.js"
import { serializeBuffer, serializeUint32 } from "../../utils/Buffer.js"
import { serializeMpintBufferToBuffer } from "../../utils/mpint.js"
import KeyExchange, { KeyExchangeError } from "./key-exchange.js"
import {
    decodePositiveDHMPInt,
    keyExchangeErrorMessage,
    unsignedDHBuffer,
} from "./diffie-hellman-validation.js"

const supportedGroups = [
    { bits: 2048, name: "modp14" },
    { bits: 3072, name: "modp15" },
    { bits: 4096, name: "modp16" },
    { bits: 6144, name: "modp17" },
    { bits: 8192, name: "modp18" },
] as const

export const defaultGroupExchangeRequest = Object.freeze({
    min: 2048,
    preferred: 3072,
    max: 8192,
})

export interface GroupExchangeHashFields {
    hashName: "sha1" | "sha256"
    clientVersion: string
    serverVersion: string
    clientKexInit: Buffer
    serverKexInit: Buffer
    hostKey: Buffer
    request: KexDHGexRequestData | { preferred: number }
    prime: Buffer
    generator: Buffer
    clientPublicKey: Buffer
    serverPublicKey: Buffer
    sharedSecret: Buffer
}

export function computeGroupExchangeHash(fields: GroupExchangeHashFields): Buffer {
    const hash = createHash(fields.hashName)
    hash.update(serializeBuffer(Buffer.from(fields.clientVersion, "utf8")))
    hash.update(serializeBuffer(Buffer.from(fields.serverVersion, "utf8")))
    hash.update(serializeBuffer(fields.clientKexInit))
    hash.update(serializeBuffer(fields.serverKexInit))
    hash.update(serializeBuffer(fields.hostKey))
    if ("min" in fields.request) {
        hash.update(serializeUint32(fields.request.min))
        hash.update(serializeUint32(fields.request.preferred))
        hash.update(serializeUint32(fields.request.max))
    } else {
        hash.update(serializeUint32(fields.request.preferred))
    }
    hash.update(serializeBuffer(serializeMpintBufferToBuffer(fields.prime)))
    hash.update(serializeBuffer(serializeMpintBufferToBuffer(fields.generator)))
    hash.update(serializeBuffer(serializeMpintBufferToBuffer(fields.clientPublicKey)))
    hash.update(serializeBuffer(serializeMpintBufferToBuffer(fields.serverPublicKey)))
    hash.update(serializeBuffer(serializeMpintBufferToBuffer(fields.sharedSecret)))
    return hash.digest()
}

export class DiffieHellmanGroupExchange extends KeyExchange {
    static requires_encryption = false
    static requires_signature = true

    readonly exchangeValueEncoding = "mpint" as const

    private request: KexDHGexRequestData | undefined
    private oldRequest = false
    private keyPair: DiffieHellman | DiffieHellmanGroup | undefined
    private prime: Buffer | undefined
    private generator: Buffer | undefined

    constructor(hashName: "sha1" | "sha256") {
        super(hashName)
    }

    setRequest(request: KexDHGexRequestData): void {
        validateRequest(request)
        this.request = { ...request }
        this.oldRequest = false
    }

    setOldRequest(preferred: number): void {
        if (!Number.isInteger(preferred) || preferred < 2048 || preferred > 8192) {
            throw new KeyExchangeError(
                "Legacy Diffie-Hellman group request must be between 2048 and 8192 bits",
            )
        }
        this.request = { min: 2048, preferred, max: 8192 }
        this.oldRequest = true
    }

    selectServerGroup(): { p: Buffer; g: Buffer } {
        const request = this.requireRequest()
        const candidates = supportedGroups.filter(
            ({ bits }) => bits >= request.min && bits <= request.max,
        )
        if (candidates.length === 0) {
            throw new KeyExchangeError(
                "No supported Diffie-Hellman group is within the requested range",
            )
        }
        const selected =
            candidates.find(({ bits }) => bits >= request.preferred) ?? candidates.at(-1)!
        const keyPair = createDiffieHellmanGroup(selected.name)
        this.installKeyPair(keyPair)
        return {
            p: serializeMpintBufferToBuffer(this.prime!),
            g: serializeMpintBufferToBuffer(this.generator!),
        }
    }

    acceptServerGroup(p: Buffer, g: Buffer): void {
        const request = this.requireRequest()
        const prime = decodePositiveDHMPInt(p, "group prime")
        const generator = decodePositiveDHMPInt(g, "group generator")
        const bits = prime.toString(2).length
        if (bits < request.min || bits > request.max || bits < 2048 || bits > 8192) {
            throw new KeyExchangeError(
                `Diffie-Hellman group size ${bits} is outside the accepted range`,
            )
        }
        if (generator <= 1n || generator >= prime - 1n) {
            throw new KeyExchangeError("Diffie-Hellman group generator is outside its valid range")
        }
        let keyPair: DiffieHellman
        try {
            keyPair = createDiffieHellman(unsignedDHBuffer(p), unsignedDHBuffer(g))
        } catch (cause) {
            throw new KeyExchangeError(
                `Invalid Diffie-Hellman group: ${keyExchangeErrorMessage(cause)}`,
            )
        }
        // For a safe prime, every value except 1 and p-1 has order q or 2q, so OpenSSL's
        // narrow generator-suitability flag is not relevant. All prime-related flags remain fatal.
        if ((keyPair.verifyError & ~constants.DH_NOT_SUITABLE_GENERATOR) !== 0) {
            throw new KeyExchangeError("Diffie-Hellman group is not a valid safe-prime group")
        }
        this.installKeyPair(keyPair)
    }

    generateKeyPair(): void {
        if (!this.keyPair) throw new KeyExchangeError("Diffie-Hellman group was not selected")
        this.keyPair.generateKeys()
    }

    getPublicKey(): Buffer {
        if (!this.keyPair) throw new KeyExchangeError("Diffie-Hellman key pair was not generated")
        return Buffer.from(this.keyPair.getPublicKey())
    }

    computeSharedSecret(peerPublicKey: Buffer): void {
        if (!this.keyPair || !this.prime) {
            throw new KeyExchangeError("Diffie-Hellman group was not selected")
        }
        const peer = decodePositiveDHMPInt(peerPublicKey, "public value")
        const prime = decodeBigIntBE(this.prime)
        if (peer <= 1n || peer >= prime - 1n) {
            throw new KeyExchangeError("Diffie-Hellman public value is outside (1, p-1)")
        }

        try {
            this.sharedSecret = this.keyPair.computeSecret(unsignedDHBuffer(peerPublicKey))
        } catch (cause) {
            throw new KeyExchangeError(
                `Invalid Diffie-Hellman public value: ${keyExchangeErrorMessage(cause)}`,
            )
        }
        const sharedSecret = decodeBigIntBE(this.sharedSecret)
        if (sharedSecret <= 1n || sharedSecret >= prime - 1n) {
            throw new KeyExchangeError("Diffie-Hellman shared secret is outside (1, p-1)")
        }
    }

    computeExchangeHash(context: Readonly<KeyExchangeHashContext>): Buffer {
        return this.computeGroupExchangeHash(
            context.clientVersion,
            context.serverVersion,
            context.clientKexInit,
            context.serverKexInit,
            context.serverHostKey,
            this.requireExchangeValue(context, "client"),
            this.requireExchangeValue(context, "server"),
        )
    }

    override dispose(): void {
        this.keyPair = undefined
        super.dispose()
    }

    private installKeyPair(keyPair: DiffieHellman | DiffieHellmanGroup): void {
        this.keyPair = keyPair
        this.prime = keyPair.getPrime()
        this.generator = keyPair.getGenerator()
    }

    private computeGroupExchangeHash(
        clientVersion: string,
        serverVersion: string,
        clientKexInit: Buffer,
        serverKexInit: Buffer,
        hostKey: Buffer,
        clientPublicKey: Buffer,
        serverPublicKey: Buffer,
    ): Buffer {
        const request = this.requireRequest()
        if (!this.prime || !this.generator || !this.sharedSecret) {
            throw new KeyExchangeError("Diffie-Hellman exchange is incomplete")
        }
        return computeGroupExchangeHash({
            hashName: this.hashName as "sha1" | "sha256",
            clientVersion,
            serverVersion,
            clientKexInit,
            serverKexInit,
            hostKey,
            request: this.oldRequest ? { preferred: request.preferred } : request,
            prime: this.prime,
            generator: this.generator,
            clientPublicKey,
            serverPublicKey,
            sharedSecret: this.sharedSecret,
        })
    }

    private requireRequest(): KexDHGexRequestData {
        if (!this.request) throw new KeyExchangeError("Diffie-Hellman group request is unavailable")
        return this.request
    }
}

export default class DiffieHellmanGroupExchangeSHA256 extends DiffieHellmanGroupExchange {
    static alg_name = "diffie-hellman-group-exchange-sha256"
    static requires_encryption = DiffieHellmanGroupExchange.requires_encryption
    static requires_signature = DiffieHellmanGroupExchange.requires_signature

    static instantiate(): DiffieHellmanGroupExchangeSHA256 {
        return new DiffieHellmanGroupExchangeSHA256()
    }

    constructor() {
        super("sha256")
    }
}

export class DiffieHellmanGroupExchangeSHA1 extends DiffieHellmanGroupExchange {
    static alg_name = "diffie-hellman-group-exchange-sha1"
    static requires_encryption = DiffieHellmanGroupExchange.requires_encryption
    static requires_signature = DiffieHellmanGroupExchange.requires_signature

    static instantiate(): DiffieHellmanGroupExchangeSHA1 {
        return new DiffieHellmanGroupExchangeSHA1()
    }

    constructor() {
        super("sha1")
    }
}

function validateRequest({ min, preferred, max }: KexDHGexRequestData): void {
    if (
        !Number.isInteger(min) ||
        !Number.isInteger(preferred) ||
        !Number.isInteger(max) ||
        min < 2048 ||
        min > preferred ||
        preferred > max ||
        max > 8192
    ) {
        throw new KeyExchangeError(
            "Diffie-Hellman group request must satisfy 2048 <= min <= preferred <= max <= 8192",
        )
    }
}
