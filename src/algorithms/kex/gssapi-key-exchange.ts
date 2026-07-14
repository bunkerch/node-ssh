import { createHash } from "node:crypto"

import type Client from "../../Client.js"
import type {
    GSSAPIClientMechanism,
    GSSAPIKeyExchangeClientContext,
    GSSAPIKeyExchangeClientContextOptions,
    GSSAPIKeyExchangeServerContext,
    GSSAPIKeyExchangeServerContextOptions,
    GSSAPIServerMechanism,
} from "../../GSSAPI.js"
import type ServerClient from "../../ServerClient.js"
import type { KexAlgorithm, KexAlgorithmFactory, KeyExchangeRole } from "../../algorithms.js"
import { serializeMpintBufferToBuffer } from "../../utils/mpint.js"
import Curve25519SHA256 from "./curve25519-sha256.js"
import Curve448SHA512 from "./curve448-sha512.js"
import DiffieHellmanGroup14SHA256 from "./diffie-hellman-group14-sha256.js"
import DiffieHellmanGroup15SHA512 from "./diffie-hellman-group15-sha512.js"
import DiffieHellmanGroup16SHA512 from "./diffie-hellman-group16-sha512.js"
import DiffieHellmanGroup17SHA512 from "./diffie-hellman-group17-sha512.js"
import DiffieHellmanGroup18SHA512 from "./diffie-hellman-group18-sha512.js"
import { ECDHSHA2NISTP256, ECDHSHA2NISTP384, ECDHSHA2NISTP521 } from "./ecdh-sha2-nist.js"
import KeyExchange, { KeyExchangeError } from "./key-exchange.js"

type GSSAPIKeyExchangeMechanism = GSSAPIClientMechanism | GSSAPIServerMechanism

interface GSSAPIKeyExchangeFamily {
    readonly prefix: string
    readonly hashName: "sha256" | "sha384" | "sha512"
    create(): KexAlgorithm
}

const families: readonly GSSAPIKeyExchangeFamily[] = Object.freeze([
    {
        prefix: "gss-curve25519-sha256-",
        hashName: "sha256",
        create: () => new Curve25519SHA256(),
    },
    {
        prefix: "gss-nistp256-sha256-",
        hashName: "sha256",
        create: () => new ECDHSHA2NISTP256(),
    },
    {
        prefix: "gss-nistp384-sha384-",
        hashName: "sha384",
        create: () => new ECDHSHA2NISTP384(),
    },
    {
        prefix: "gss-nistp521-sha512-",
        hashName: "sha512",
        create: () => new ECDHSHA2NISTP521(),
    },
    {
        prefix: "gss-curve448-sha512-",
        hashName: "sha512",
        create: () => new Curve448SHA512(),
    },
    {
        prefix: "gss-group16-sha512-",
        hashName: "sha512",
        create: () => new DiffieHellmanGroup16SHA512(),
    },
    {
        prefix: "gss-group14-sha256-",
        hashName: "sha256",
        create: () => new DiffieHellmanGroup14SHA256(),
    },
    {
        prefix: "gss-group18-sha512-",
        hashName: "sha512",
        create: () => new DiffieHellmanGroup18SHA512(),
    },
    {
        prefix: "gss-group17-sha512-",
        hashName: "sha512",
        create: () => new DiffieHellmanGroup17SHA512(),
    },
    {
        prefix: "gss-group15-sha512-",
        hashName: "sha512",
        create: () => new DiffieHellmanGroup15SHA512(),
    },
])

export function gssapiKeyExchangeMethodNames(oid: Buffer): readonly string[] {
    const suffix = createHash("md5").update(oid).digest("base64")
    return Object.freeze(families.map(({ prefix }) => `${prefix}${suffix}`))
}

export function createGSSAPIKeyExchangeAlgorithms(
    mechanisms: readonly GSSAPIKeyExchangeMechanism[],
): ReadonlyMap<string, KexAlgorithmFactory> {
    const algorithms = new Map<string, KexAlgorithmFactory>()
    for (const mechanism of mechanisms) {
        if (mechanism.createKeyExchangeContext === undefined) continue
        const names = gssapiKeyExchangeMethodNames(mechanism.oid)
        for (let index = 0; index < families.length; index++) {
            const family = families[index]
            const methodName = names[index]
            class ConfiguredGSSAPIKeyExchange extends GSSAPIKeyExchange {
                static readonly alg_name = methodName
                static readonly requires_encryption = false
                static readonly requires_signature = false

                static instantiate(): ConfiguredGSSAPIKeyExchange {
                    return new ConfiguredGSSAPIKeyExchange()
                }

                constructor() {
                    super(methodName, family, mechanism)
                }
            }
            algorithms.set(methodName, ConfiguredGSSAPIKeyExchange)
        }
    }
    return algorithms
}

export default class GSSAPIKeyExchange extends KeyExchange {
    readonly exchangeValueEncoding: "mpint" | "string"
    readonly methodName: string
    readonly mechanismOID: Buffer
    readonly #mechanism: GSSAPIKeyExchangeMechanism
    readonly #keyAgreement: KexAlgorithm
    #role?: KeyExchangeRole
    #peerPublicKey?: Buffer
    #serverHostKey?: Buffer

    constructor(
        methodName: string,
        family: GSSAPIKeyExchangeFamily,
        mechanism: GSSAPIKeyExchangeMechanism,
    ) {
        super(family.hashName)
        this.methodName = methodName
        this.mechanismOID = Buffer.from(mechanism.oid)
        this.#mechanism = mechanism
        this.#keyAgreement = family.create()
        this.exchangeValueEncoding = this.#keyAgreement.exchangeValueEncoding
    }

    generateKeyPair(role?: KeyExchangeRole): void {
        if (!role) throw new KeyExchangeError("GSS-API key-exchange role is required")
        this.#role = role
        this.#keyAgreement.generateKeyPair(role)
    }

    getPublicKey(): Buffer {
        return Buffer.from(this.#keyAgreement.getPublicKey())
    }

    computeSharedSecret(peerPublicKey: Buffer): void {
        this.#keyAgreement.computeSharedSecret(peerPublicKey)
        this.#peerPublicKey = Buffer.from(peerPublicKey)
    }

    getSharedSecret(): Buffer {
        return this.#keyAgreement.getSharedSecret()
    }

    setServerHostKey(hostKey: Buffer): void {
        this.#serverHostKey = Buffer.from(hostKey)
    }

    createClientContext(
        options: Readonly<GSSAPIKeyExchangeClientContextOptions>,
    ): GSSAPIKeyExchangeClientContext | Promise<GSSAPIKeyExchangeClientContext> {
        const create = (this.#mechanism as GSSAPIClientMechanism).createKeyExchangeContext
        if (!create) throw new KeyExchangeError("GSS-API client key exchange is unavailable")
        return create(options)
    }

    createServerContext(
        options: Readonly<GSSAPIKeyExchangeServerContextOptions>,
    ): GSSAPIKeyExchangeServerContext | Promise<GSSAPIKeyExchangeServerContext> {
        const create = (this.#mechanism as GSSAPIServerMechanism).createKeyExchangeContext
        if (!create) throw new KeyExchangeError("GSS-API server key exchange is unavailable")
        return create(options)
    }

    computeHClient(client: Client, serverKexInit: Buffer): Buffer {
        if (this.#role !== "client" || !this.#peerPublicKey || !this.#serverHostKey) {
            throw new KeyExchangeError("GSS-API client key exchange is incomplete")
        }
        return this.#computeH(
            client.options.protocolVersionExchange.toString().slice(0, -2),
            client.serverProtocolVersion!.toString().slice(0, -2),
            client.clientKexInitPayload!,
            serverKexInit,
            this.#serverHostKey,
            this.getPublicKey(),
            this.#peerPublicKey,
        )
    }

    computeHServer(client: ServerClient, clientKexInit: Buffer, hostKey: Buffer): Buffer {
        if (this.#role !== "server" || !this.#peerPublicKey) {
            throw new KeyExchangeError("GSS-API server key exchange is incomplete")
        }
        this.#serverHostKey = Buffer.from(hostKey)
        return this.#computeH(
            client.clientProtocolVersion!.toString().slice(0, -2),
            client.server.options.protocolVersionExchange!.toString().slice(0, -2),
            clientKexInit,
            client.serverKexInitPayload!,
            hostKey,
            this.#peerPublicKey,
            this.getPublicKey(),
        )
    }

    deriveKeysClient(client: Client | ServerClient): void {
        this.#keyAgreement.deriveKeysClient(client)
    }

    #computeH(
        clientVersion: string,
        serverVersion: string,
        clientKexInit: Buffer,
        serverKexInit: Buffer,
        serverHostKey: Buffer,
        clientPublicKey: Buffer,
        serverPublicKey: Buffer,
    ): Buffer {
        return this.computeExchangeHash([
            clientVersion,
            serverVersion,
            clientKexInit,
            serverKexInit,
            serverHostKey,
            this.#encodeExchangeValue(clientPublicKey),
            this.#encodeExchangeValue(serverPublicKey),
            serializeMpintBufferToBuffer(this.getSharedSecret()),
        ])
    }

    #encodeExchangeValue(value: Buffer): Buffer {
        return this.exchangeValueEncoding === "mpint"
            ? serializeMpintBufferToBuffer(value)
            : Buffer.from(value)
    }
}
