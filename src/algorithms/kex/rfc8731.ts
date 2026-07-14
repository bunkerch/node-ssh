import type { KeyExchangeHashContext } from "../../algorithms.js"
import { serializeMpintBufferToBuffer } from "../../utils/mpint.js"
import KeyExchange from "./key-exchange.js"

/** Shared SSH framing for the RFC 8731 X25519 and X448 key exchanges. */
export default abstract class RFC8731KeyExchange extends KeyExchange {
    readonly exchangeValueEncoding = "string" as const

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
}
