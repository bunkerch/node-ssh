import { Agent as HTTPAgent, type AgentOptions as HTTPAgentOptions } from "node:http"
import { Agent as HTTPSAgent, type AgentOptions as HTTPSAgentOptions } from "node:https"
import type { Duplex } from "node:stream"
import { connect as connectTLS, type ConnectionOptions as TLSConnectionOptions } from "node:tls"
import Client, {
    normalizeClientAuthenticationAgent,
    type ClientHooker,
    type ClientOptions,
} from "./Client.js"
import type {
    AlgorithmMatcher,
    ClientAlgorithmList,
    ClientAlgorithmOptions,
} from "./AlgorithmOptions.js"
import { normalizeDelayCompression } from "./DelayCompression.js"
import { normalizeGSSAPIClientMechanisms } from "./GSSAPI.js"
import { copyProtocolVersionExchange } from "./ProtocolVersionExchange.js"
import type ClientTCPIPChannel from "./channels/ClientTCPIPChannel.js"
import { Hooker } from "./utils/Hooker.js"
import { normalizeOptionalTimeout } from "./utils/Timeout.js"

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
                : copyProtocolVersionExchange(options.protocolVersionExchange),
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
        authenticationSignatureAlgorithms:
            options.authenticationSignatureAlgorithms === undefined
                ? undefined
                : Object.freeze([...options.authenticationSignatureAlgorithms]),
        delayCompression:
            options.delayCompression === undefined
                ? undefined
                : normalizeDelayCompression(options.delayCompression),
        sock: undefined,
    })
}

function socketCompatible(channel: ClientTCPIPChannel): SocketCompatibleChannel {
    const socket = channel as SocketCompatibleChannel
    let timeout: NodeJS.Timeout | undefined
    let timeoutMilliseconds = 0

    const clearSocketTimeout = () => {
        if (timeout !== undefined) clearTimeout(timeout)
        timeout = undefined
    }
    const armSocketTimeout = () => {
        clearSocketTimeout()
        if (timeoutMilliseconds === 0 || socket.destroyed) return
        timeout = setTimeout(() => {
            timeout = undefined
            socket.emit("timeout")
        }, timeoutMilliseconds)
        timeout.unref()
    }
    const originalWrite = socket._write.bind(socket)
    socket._write = (data, encoding, callback) => {
        armSocketTimeout()
        originalWrite(data, encoding, callback)
    }

    socket.on("data", armSocketTimeout)
    socket.once("close", clearSocketTimeout)
    socket.setKeepAlive = () => socket
    socket.setNoDelay = () => socket
    socket.setTimeout = (milliseconds = 0, callback) => {
        normalizeOptionalTimeout(milliseconds, "SSH HTTP socket timeout")
        if (callback !== undefined) socket.once("timeout", callback)
        timeoutMilliseconds = milliseconds
        armSocketTimeout()
        return socket
    }
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
    private readonly clientOptions: Readonly<ClientOptions>
    readonly hooker = new Hooker<Pick<ClientHooker, "hostKey">>()
    private client?: Client
    private connecting?: Promise<Client>
    private generation = 0

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

        const sourceHost = options.localAddress ?? this.sourceHost
        const sourcePort = options.localPort ?? this.sourcePort

        void (async () => {
            const client = await this.connection()
            const channel = socketCompatible(
                await client.forwardOut(sourceHost, sourcePort, target.host, target.port),
            )
            if (!secure) {
                callback(null, channel)
                return
            }
            callback(
                null,
                connectTLS({ ...options, host: target.host, port: target.port, socket: channel }),
            )
        })().catch((error: unknown) => {
            callback(error instanceof Error ? error : new Error(String(error)))
        })
    }

    private connection(): Promise<Client> {
        if (this.client?.isConnected) return Promise.resolve(this.client)
        if (this.connecting) return this.connecting

        const generation = this.generation
        const client = new Client({ ...this.clientOptions })
        client.hooker.hook("hostKey", async (_hook, decision, key) => {
            if (!this.hooker.hasHooks("hostKey")) {
                decision.allowHostKey = true
                return
            }
            const policyCompleted = await this.hooker.triggerHookChecked("hostKey", decision, key)
            if (!policyCompleted) decision.allowHostKey = false
        })
        this.client = client
        client.on("error", (error) => void error)
        client.once("close", () => {
            if (this.client === client) this.client = undefined
        })

        const connecting = client.connect().then(
            () => {
                if (generation !== this.generation || this.client !== client) {
                    client.destroy()
                    throw new Error("SSH HTTP connection was destroyed during setup")
                }
                return client
            },
            (error: unknown) => {
                if (this.client === client) this.client = undefined
                client.destroy()
                throw error
            },
        )
        this.connecting = connecting
        const clearConnecting = () => {
            if (this.connecting === connecting) this.connecting = undefined
        }
        void connecting.then(clearConnecting, clearConnecting)
        return connecting
    }

    destroy(): void {
        this.generation++
        this.client?.destroy()
        this.client = undefined
        this.connecting = undefined
    }
}

export class SSHHTTPAgent extends HTTPAgent {
    private readonly factory: SSHConnectionFactory

    /** Persistent host-key policy applied to every underlying SSH connection. */
    get hooker(): Hooker<Pick<ClientHooker, "hostKey">> {
        return this.factory.hooker
    }

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

    /** Persistent host-key policy applied to every underlying SSH connection. */
    get hooker(): Hooker<Pick<ClientHooker, "hostKey">> {
        return this.factory.hooker
    }

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
