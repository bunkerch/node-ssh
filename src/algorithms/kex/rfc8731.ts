import type Client from "../../Client.js"
import type ServerClient from "../../ServerClient.js"
import { serializeMpintBufferToBuffer } from "../../utils/mpint.js"
import KeyExchange from "./key-exchange.js"

/** Shared SSH framing for the RFC 8731 X25519 and X448 key exchanges. */
export default abstract class RFC8731KeyExchange extends KeyExchange {
    readonly exchangeValueEncoding = "string" as const

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
