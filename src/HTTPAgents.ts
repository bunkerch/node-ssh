import { Agent as HTTPAgent, type AgentOptions as HTTPAgentOptions } from "node:http"
import { Agent as HTTPSAgent, type AgentOptions as HTTPSAgentOptions } from "node:https"
import type { Duplex } from "node:stream"
import { connect as connectTLS, type ConnectionOptions as TLSConnectionOptions } from "node:tls"
import Client, { normalizeClientAuthenticationAgent, type ClientOptions } from "./Client.js"
import type {
    AlgorithmMatcher,
    ClientAlgorithmList,
    ClientAlgorithmOptions,
} from "./AlgorithmOptions.js"
import { normalizeDelayCompression } from "./DelayCompression.js"
import { normalizeGSSAPIClientMechanisms } from "./GSSAPI.js"
import ProtocolVersionExchange from "./ProtocolVersionExchange.js"
import type ClientTCPIPChannel from "./channels/ClientTCPIPChannel.js"

export interface SSHAgentOptions {
    /** Originator address reported in the RFC 4254 direct-tcpip request. */
    sourceHost?: string
    /** Originator port reported in the RFC 4254 direct-tcpip request. */
    sourcePort?: number
}

export type SSHHTTPAgentOptions = HTTPAgentOptions & SSHAgentOptions
export type SSHHTTPSAgentOptions = HTTPSAgentOptions & SSHAgentOptions

type ConnectionCallback = (error: Error | null, stream?: Duplex) => void
type ConnectionRequest = TLSConnectionOptions & {
    host?: string
    hostname?: string
    localAddress?: string
    localPort?: number
    port?: number | string
}

interface SocketCompatibleChannel extends ClientTCPIPChannel {
    setKeepAlive(enable?: boolean, initialDelay?: number): this
    setNoDelay(noDelay?: boolean): this
    setTimeout(timeout?: number, callback?: () => void): this
    ref(): this
    unref(): this
    destroySoon(): this
}

function snapshotMatcher(matcher: AlgorithmMatcher): AlgorithmMatcher {
    return matcher instanceof RegExp ? new RegExp(matcher.source, matcher.flags) : matcher
}

function snapshotAlgorithmList(
    list: ClientAlgorithmList | undefined,
): ClientAlgorithmList | undefined {
    if (list === undefined) return undefined
    if (Array.isArray(list)) return Object.freeze([...list])
    if (typeof list !== "object" || list === null) return list

    const snapshot = Object.create(Object.getPrototypeOf(list)) as Record<string, unknown>
    for (const [operation, value] of Object.entries(list)) {
        snapshot[operation] = Array.isArray(value)
            ? Object.freeze(value.map((matcher) => snapshotMatcher(matcher as AlgorithmMatcher)))
            : value instanceof RegExp
              ? snapshotMatcher(value)
              : value
    }
    return Object.freeze(snapshot) as ClientAlgorithmList
}

function snapshotAlgorithms(
    algorithms: ClientAlgorithmOptions | undefined,
): ClientAlgorithmOptions | undefined {
    if (algorithms === undefined) return undefined
    return Object.freeze({
        kex: snapshotAlgorithmList(algorithms.kex),
        serverHostKey: snapshotAlgorithmList(algorithms.serverHostKey),
        cipher: snapshotAlgorithmList(algorithms.cipher),
        hmac: snapshotAlgorithmList(algorithms.hmac),
        compress: snapshotAlgorithmList(algorithms.compress),
    })
}

function snapshotClientOptions(options: Readonly<ClientOptions>): Readonly<ClientOptions> {
    if (options.sock !== undefined) {
        throw new TypeError("SSH HTTP agents cannot reuse an already-connected transport")
    }
    const agent = normalizeClientAuthenticationAgent(options)
    return Object.freeze({
        ...options,
        ident: Buffer.isBuffer(options.ident) ? Buffer.from(options.ident) : options.ident,
        protocolVersionExchange:
            options.protocolVersionExchange === undefined
                ? undefined
                : new ProtocolVersionExchange(
                      options.protocolVersionExchange.protocol_version,
                      options.protocolVersionExchange.protocol_software,
                      options.protocolVersionExchange.comments,
                  ),
        algorithms: snapshotAlgorithms(options.algorithms),
        agent,
        privateKey: undefined,
        certificate: undefined,
        passphrase: undefined,
        hostbased:
            options.hostbased === undefined ? undefined : Object.freeze({ ...options.hostbased }),
        gssapi:
            options.gssapi === undefined
                ? undefined
                : normalizeGSSAPIClientMechanisms(options.gssapi),
        authenticationMethodsOrder:
            options.authenticationMethodsOrder === undefined
                ? undefined
                : Object.freeze([...options.authenticationMethodsOrder]),
        delayCompression:
            options.delayCompression === undefined
                ? undefined
                : normalizeDelayCompression(options.delayCompression),
        sock: undefined,
    })
}

function socketCompatible(channel: ClientTCPIPChannel): SocketCompatibleChannel {
    const socket = channel as SocketCompatibleChannel
    socket.setKeepAlive = () => socket
    socket.setNoDelay = () => socket
    socket.setTimeout = () => socket
    socket.ref = () => socket
    socket.unref = () => socket
    socket.destroySoon = () => {
        socket.end()
        return socket
    }
    return socket
}

function destination(options: ConnectionRequest): { host: string; port: number } {
    const host = options.hostname ?? options.host
    if (!host) throw new Error("HTTP request has no destination host")
    const port = Number(options.port)
    if (!Number.isInteger(port) || port < 1 || port > 65_535) {
        throw new RangeError("HTTP destination port must be between 1 and 65535")
    }
    return { host, port }
}

class SSHConnectionFactory {
    readonly clients = new Set<Client>()
    private readonly clientOptions: Readonly<ClientOptions>

    constructor(
        clientOptions: Readonly<ClientOptions>,
        private readonly sourceHost: string,
        private readonly sourcePort: number,
    ) {
        this.clientOptions = snapshotClientOptions(clientOptions)
    }

    create(options: ConnectionRequest, callback: ConnectionCallback, secure: boolean): void {
        let target: { host: string; port: number }
        try {
            target = destination(options)
        } catch (error) {
            queueMicrotask(() => callback(error as Error))
            return
        }

        const client = new Client({ ...this.clientOptions })
        this.clients.add(client)
        client.once("close", () => this.clients.delete(client))
        client.on("error", (error) => void error)
        const sourceHost = options.localAddress ?? this.sourceHost
        const sourcePort = options.localPort ?? this.sourcePort

        void (async () => {
            await client.connect()
            const channel = socketCompatible(
                await client.forwardOut(sourceHost, sourcePort, target.host, target.port),
            )
            channel.once("close", () => client.end())
            if (!secure) {
                callback(null, channel)
                return
            }
            callback(
                null,
                connectTLS({ ...options, host: target.host, port: target.port, socket: channel }),
            )
        })().catch((error: unknown) => {
            client.destroy()
            callback(error instanceof Error ? error : new Error(String(error)))
        })
    }

    destroy(): void {
        for (const client of this.clients) client.destroy()
        this.clients.clear()
    }
}

export class SSHHTTPAgent extends HTTPAgent {
    private readonly factory: SSHConnectionFactory

    constructor(clientOptions: Readonly<ClientOptions>, options: SSHHTTPAgentOptions = {}) {
        super(options)
        this.factory = new SSHConnectionFactory(
            clientOptions,
            options.sourceHost ?? "127.0.0.1",
            options.sourcePort ?? 0,
        )
        this.createConnection = SSHHTTPAgent.prototype.createConnection.bind(this)
    }

    override createConnection(options: ConnectionRequest, callback: ConnectionCallback): undefined {
        this.factory.create(options, callback, false)
        return undefined
    }

    override destroy(): void {
        this.factory.destroy()
        super.destroy()
    }
}

export class SSHHTTPSAgent extends HTTPSAgent {
    private readonly factory: SSHConnectionFactory

    constructor(clientOptions: Readonly<ClientOptions>, options: SSHHTTPSAgentOptions = {}) {
        super(options)
        this.factory = new SSHConnectionFactory(
            clientOptions,
            options.sourceHost ?? "127.0.0.1",
            options.sourcePort ?? 0,
        )
        this.createConnection = SSHHTTPSAgent.prototype.createConnection.bind(this)
    }

    override createConnection(options: ConnectionRequest, callback: ConnectionCallback): undefined {
        this.factory.create(options, callback, true)
        return undefined
    }

    override destroy(): void {
        this.factory.destroy()
        super.destroy()
    }
}
