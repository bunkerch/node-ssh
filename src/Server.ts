// this causes issues with the Server#listen method.

import EventEmitter from "node:events"
import ProtocolVersionExchange, { copyProtocolVersionExchange } from "./ProtocolVersionExchange.js"
import net from "net"
import { isReadable, type Duplex } from "node:stream"
import ServerClient from "./ServerClient.js"
import { Hooker } from "./utils/Hooker.js"
import PrivateKey from "./utils/PrivateKey.js"
import PublicKey, { SSHCertificatePublicKey } from "./utils/PublicKey.js"
import EncodedSignature from "./utils/Signature.js"
import Channel from "./Channel.js"
import { SSHAuthenticationMethods } from "./constants.js"
import { DisconnectError } from "./packets/Disconnect.js"
import type { ChannelOpenError } from "./packets/ChannelOpenFailure.js"
import { parseKey } from "./KeyParsing.js"
import type ChannelRequest from "./packets/ChannelRequest.js"
import { MAX_PREAMBLE_LINE_LENGTH, MAX_PREAMBLE_LINES } from "./IdentificationParser.js"
import {
    resolveServerAlgorithmOptions,
    type ResolvedAlgorithmOptions,
    type ServerAlgorithmOptions,
} from "./AlgorithmOptions.js"
import {
    encryption_algorithms,
    compression_algorithms,
    host_key_algorithms,
    kex_algorithms,
    mac_algorithm_names,
    default_algorithm_names,
} from "./algorithms.js"
import { registerKeyExchanges } from "./KeyExchangeRegistry.js"
import { registerServerConfiguration } from "./ConnectionConfiguration.js"
import {
    DEFAULT_REKEY_BYTES,
    DEFAULT_REKEY_INTERVAL,
    validateRekeyBytes,
    validateRekeyInterval,
} from "./RekeyLimits.js"
import { normalizeGSSAPIServerMechanisms, type GSSAPIServerMechanism } from "./GSSAPI.js"
import { createGSSAPIKeyExchangeAlgorithms } from "./algorithms/kex/gssapi-key-exchange.js"
import { normalizeNoFlowControlPreference, type NoFlowControlPreference } from "./NoFlowControl.js"
import type { ElevationRequest } from "./Elevation.js"
import {
    normalizeDelayCompression,
    type DelayCompressionConfiguration,
    type NormalizedDelayCompression,
} from "./DelayCompression.js"
import { encodeSSHLanguageTag, encodeSSHUTF8 } from "./utils/SSHText.js"

export interface ServerOptions {
    protocolVersionExchange?: ProtocolVersionExchange
    /** Custom SSH software identifier and optional comments, without the `SSH-2.0-` prefix. */
    ident?: string | Buffer
    /** Informational text sent before the SSH identification. */
    greeting?: string
    algorithms?: ServerAlgorithmOptions
    hostKeys?: (PrivateKey | string | Buffer | ServerHostKeyInput)[]
    /** Public host certificates paired with matching entries in `hostKeys`. */
    hostCertificates?: (PublicKey | string | Buffer)[]
    // by default, the Server will send all available hostkeys
    // to the client after login (USERAUTH_SUCCESS)
    // this allows the client to save them and then to accept unknown
    // of them on the next login.
    // This is particularily useful when a transition in hostkeys
    // is happening (for example deprecating an host key)
    sendAllHostKeys?: boolean
    /** RFC 4252 banner sent once before authentication begins. */
    banner?: string
    /** RFC 3066 language tag sent with `banner`; empty means unspecified. */
    bannerLanguageTag?: string
    /** Milliseconds allowed through key exchange and user-auth service acceptance. Zero disables. */
    handshakeTimeout?: number
    /** Milliseconds allowed after accepting the user-authentication service. Zero disables. */
    authenticationTimeout?: number
    /** Maximum milliseconds for an ordered peer reply before the connection is closed. */
    replyTimeout?: number
    /** Maximum peer channel-open decisions allowed to remain pending per connection. */
    maxPendingChannelOpens?: number
    /** Maximum simultaneous active and pending SSH channels per connection. */
    maxChannels?: number
    /** Maximum rejected non-`none` authentication requests per connection. */
    maxAuthenticationAttempts?: number
    /** Milliseconds between authenticated per-connection SSH keepalive probes. Zero disables. */
    keepaliveInterval?: number
    /** Consecutive unanswered probes allowed before terminating a connection. */
    keepaliveCountMax?: number
    /** Protected wire bytes allowed per key in either direction. Zero disables this limit. */
    rekeyBytes?: number
    /** Milliseconds a transport key may remain active. Zero disables this limit. */
    rekeyInterval?: number
    /** RFC 4462 GSS-API mechanisms accepted by this server. */
    gssapi?: readonly GSSAPIServerMechanism[]
    /** RFC 8308 infinite channel windows. Both peers must opt in and one must prefer it. */
    noFlowControl?: NoFlowControlPreference
    /** RFC 8308 post-authentication compression renegotiation. */
    delayCompression?: DelayCompressionConfiguration
    /** Receive the same diagnostic arguments as the `debug` event. */
    debug?: (...message: unknown[]) => void
}
export interface ServerHostKeyInput {
    key: PrivateKey | string | Buffer
    passphrase?: string | Buffer
}

/** TCP endpoint metadata captured when a connection is admitted. */
export interface ServerConnectionInfo {
    readonly remoteAddress?: string
    readonly remoteFamily?: string
    readonly remotePort?: number
    readonly localAddress?: string
    readonly localFamily?: string
    readonly localPort?: number
}

/** Connected duplex transport accepted by an SSH server. */
export interface ServerTransport extends Duplex {
    readonly remoteAddress?: string
    readonly remoteFamily?: string
    readonly remotePort?: number
    readonly localAddress?: string
    readonly localFamily?: string
    readonly localPort?: number
    setNoDelay?(noDelay?: boolean): unknown
}

export interface ServerOptionsRequired
    extends Required<
        Omit<ServerOptions, "ident" | "algorithms" | "hostKeys" | "hostCertificates" | "debug">
    > {
    ident?: string | Buffer
    algorithms?: ServerAlgorithmOptions
    hostKeys: PrivateKey[]
    delayCompression: NormalizedDelayCompression
    hostCertificates?: (PublicKey | string | Buffer)[]
    debug?: (...message: unknown[]) => void
}

function normalizeGreeting(greeting: string): string {
    if (greeting.length === 0) return ""
    if (greeting.includes("\0") || /\r(?!\n)/u.test(greeting)) {
        throw new TypeError("SSH server greeting must not contain NUL or a bare CR")
    }
    const lines = greeting.split(/\r?\n/u)
    if (lines.at(-1) === "") lines.pop()
    if (lines.length > MAX_PREAMBLE_LINES) {
        throw new RangeError(`SSH server greeting must not exceed ${MAX_PREAMBLE_LINES} lines`)
    }
    for (const line of lines) {
        if (line.startsWith("SSH-")) {
            throw new TypeError("SSH server greeting lines must not begin with SSH-")
        }
        if (Buffer.byteLength(line, "utf8") + 2 > MAX_PREAMBLE_LINE_LENGTH) {
            throw new RangeError(
                `SSH server greeting lines must not exceed ${MAX_PREAMBLE_LINE_LENGTH} bytes`,
            )
        }
    }
    return lines.map((line) => `${line}\r\n`).join("")
}

export interface ServerEvents {
    debug: unknown[]
    close: []
    error: [error: Error]
    listening: []
    connection: [client: ServerClient, info: Readonly<ServerConnectionInfo>]
}

export interface ServerHookerPreconnectController {
    allowConnection: boolean
}
export type ServerHookerNoneAuthenticationContext = Readonly<{
    username: string
}>
export interface ServerHookerNoneAuthenticationController {
    allowLogin: boolean
}
export interface ServerAuthenticationContinuation {
    partialSuccess?: boolean
    authenticationMethods?: SSHAuthenticationMethods[]
}
export type ServerHookerPublicKeyAuthenticationContext = Readonly<{
    username: string
    publicKey: PublicKey
    /** Parsed certificate metadata when `publicKey` is a certificate. */
    certificate?: SSHCertificatePublicKey
    algorithm: string
    signature?: EncodedSignature
    signatureMessage: Buffer
    /** Whether the signed request binds the identity to this server host key. */
    hostbound: boolean
    serverHostKey?: PublicKey
}>
export interface ServerHookerPublicKeyAuthenticationController
    extends ServerAuthenticationContinuation {
    requestSignature: boolean
    allowLogin: boolean
}
export type ServerHookerHostbasedAuthenticationContext = Readonly<{
    username: string
    publicKey: PublicKey
    algorithm: string
    clientHostname: string
    clientUsername: string
    signature: EncodedSignature
    signatureMessage: Buffer
    remoteAddress?: string
    remotePort?: number
}>
export interface ServerHookerHostbasedAuthenticationController
    extends ServerAuthenticationContinuation {
    allowLogin: boolean
}
export type ServerHookerPasswordAuthenticationContext = Readonly<{
    username: string
    password: string
    newPassword?: string
}>
export interface ServerHookerPasswordAuthenticationController
    extends ServerAuthenticationContinuation {
    allowLogin: boolean
    requestPasswordChange?: {
        prompt: string
        languageTag?: string
    }
}
export interface ServerKeyboardInteractivePrompt {
    prompt: string
    echo: boolean
}
export type ServerHookerKeyboardInteractiveAuthenticationContext = Readonly<{
    username: string
    languageTag: string
    submethods: string
    responses?: readonly string[]
    round: number
}>
export interface ServerHookerKeyboardInteractiveAuthenticationController
    extends ServerAuthenticationContinuation {
    allowLogin: boolean
    name?: string
    instruction?: string
    languageTag?: string
    prompts?: ServerKeyboardInteractivePrompt[]
}
export type ServerHookerGSSAPIAuthenticationContext = Readonly<{
    username: string
    service: string
    mechanismOID: Buffer
    integrity: boolean
    peerIdentity?: unknown
    delegatedCredentials?: unknown
}>
export interface ServerHookerGSSAPIAuthenticationController
    extends ServerAuthenticationContinuation {
    allowLogin: boolean
}
export interface ServerHookerChannelOpenRequestController {
    allowOpen: boolean
    /** Validated failure metadata sent when this policy denies the channel. */
    rejection?: ChannelOpenError
}
export interface ServerHookerChannelRequestController {
    deny: boolean
    /** Marks an otherwise unknown request as handled by this hook. */
    handled?: boolean
    /** Success reply used when `handled` is true. */
    success?: boolean
}
export type ServerHookerTCPIPForwardContext = Readonly<{
    bindAddress: string
    bindPort: number
}>
export interface ServerHookerTCPIPForwardController {
    allow: boolean
}
export type ServerHookerStreamLocalForwardContext = Readonly<{
    socketPath: string
}>
export interface ServerHookerStreamLocalForwardController {
    allow: boolean
}
export type ServerHookerGlobalRequestContext = Readonly<{
    name: string
    args: Buffer
    wantReply: boolean
}>
export interface ServerHookerGlobalRequestController {
    success: boolean
    response?: Buffer
}
export type ServerHookerElevationContext = Readonly<{
    preference: ElevationRequest
    username: string
}>
export interface ServerHookerElevationController {
    /** Actual operating-system elevation state after policy completes. */
    elevated?: boolean
}
// eslint-disable-next-line @typescript-eslint/consistent-type-definitions
export type ServerHooker = {
    preconnect: [preconnectController: ServerHookerPreconnectController, client: ServerClient]
    noneAuthentication: [
        noneAuthenticationContext: Readonly<ServerHookerNoneAuthenticationContext>,
        noneAuthenticationController: ServerHookerNoneAuthenticationController,
        client: ServerClient,
    ]
    publicKeyAuthentication: [
        publicKeyAuthenticationContext: Readonly<ServerHookerPublicKeyAuthenticationContext>,
        publicKeyAuthenticationController: ServerHookerPublicKeyAuthenticationController,
        client: ServerClient,
    ]
    hostbasedAuthentication: [
        hostbasedAuthenticationContext: ServerHookerHostbasedAuthenticationContext,
        hostbasedAuthenticationController: ServerHookerHostbasedAuthenticationController,
        client: ServerClient,
    ]
    passwordAuthentication: [
        passwordAuthenticationContext: Readonly<ServerHookerPasswordAuthenticationContext>,
        passwordAuthenticationController: ServerHookerPasswordAuthenticationController,
        client: ServerClient,
    ]
    keyboardInteractiveAuthentication: [
        keyboardInteractiveAuthenticationContext: ServerHookerKeyboardInteractiveAuthenticationContext,
        keyboardInteractiveAuthenticationController: ServerHookerKeyboardInteractiveAuthenticationController,
        client: ServerClient,
    ]
    gssapiAuthentication: [
        gssapiAuthenticationContext: ServerHookerGSSAPIAuthenticationContext,
        gssapiAuthenticationController: ServerHookerGSSAPIAuthenticationController,
        client: ServerClient,
    ]
    elevation: [
        context: ServerHookerElevationContext,
        controller: ServerHookerElevationController,
        client: ServerClient,
    ]
    channelOpenRequest: [
        channel: Channel,
        channelOpenRequestController: ServerHookerChannelOpenRequestController,
        client: ServerClient,
    ]
    channelRequest: [
        channel: Channel,
        channelRequestController: ServerHookerChannelRequestController,
        client: ServerClient,
        request: ChannelRequest,
    ]
    tcpipForward: [
        context: ServerHookerTCPIPForwardContext,
        controller: ServerHookerTCPIPForwardController,
        client: ServerClient,
    ]
    streamLocalForward: [
        context: ServerHookerStreamLocalForwardContext,
        controller: ServerHookerStreamLocalForwardController,
        client: ServerClient,
    ]
    globalRequest: [
        context: ServerHookerGlobalRequestContext,
        controller: ServerHookerGlobalRequestController,
        client: ServerClient,
    ]
}

export default class Server extends EventEmitter<ServerEvents> {
    readonly #options: ServerOptionsRequired

    constructor(options: ServerOptions = {}) {
        super()
        this.#options = { ...options } as ServerOptionsRequired
        if (this.#options.debug !== undefined && typeof this.#options.debug !== "function") {
            throw new TypeError("SSH debug option must be a function")
        }
        if (
            this.#options.ident !== undefined &&
            this.#options.protocolVersionExchange !== undefined
        ) {
            throw new TypeError(
                "SSH ident and protocolVersionExchange options are mutually exclusive",
            )
        }
        this.#options.protocolVersionExchange =
            this.#options.ident === undefined
                ? copyProtocolVersionExchange(
                      this.#options.protocolVersionExchange ?? ProtocolVersionExchange.defaultValue,
                  )
                : ProtocolVersionExchange.fromIdent(this.#options.ident)
        this.#options.greeting = normalizeGreeting(this.#options.greeting ?? "")
        this.#options.hostKeys = (options.hostKeys ?? []).map((input) => {
            const wrapped =
                typeof input === "object" &&
                input !== null &&
                !(input instanceof PrivateKey) &&
                !Buffer.isBuffer(input)
            const keyInput = wrapped ? input.key : input
            const passphrase = wrapped ? input.passphrase : undefined
            if (keyInput instanceof PrivateKey && passphrase !== undefined) {
                throw new TypeError("SSH host-key passphrase is only valid for an encoded key")
            }
            const key = keyInput instanceof PrivateKey ? keyInput : parseKey(keyInput, passphrase)
            if (!(key instanceof PrivateKey)) {
                throw new TypeError("SSH hostKeys entries must contain private keys")
            }
            return key
        })
        for (const certificateInput of this.#options.hostCertificates ?? []) {
            const certificate =
                certificateInput instanceof PublicKey
                    ? certificateInput
                    : parseKey(certificateInput)
            if (!(certificate instanceof PublicKey)) {
                throw new TypeError("SSH host certificate must contain a public key")
            }
            const hostKey = this.#options.hostKeys.find((key) => {
                const publicKey = certificate.data.algorithm
                return (
                    publicKey instanceof SSHCertificatePublicKey &&
                    publicKey.publicKey.equals(key.data.publicKey)
                )
            })
            if (!hostKey) throw new TypeError("SSH host certificate does not match a host key")
            this.#options.hostKeys.push(hostKey.withCertificate(certificate))
        }
        this.#options.hostCertificates = undefined
        this.#options.sendAllHostKeys ??= true
        this.#options.gssapi = normalizeGSSAPIServerMechanisms(this.#options.gssapi ?? [])
        this.#options.noFlowControl = normalizeNoFlowControlPreference(this.#options.noFlowControl)
        this.#options.delayCompression = normalizeDelayCompression(this.#options.delayCompression)
        this.#options.banner ??= ""
        this.#options.bannerLanguageTag ??= ""
        if (typeof this.#options.banner !== "string") {
            throw new TypeError("SSH authentication banner must be a string")
        }
        if (typeof this.#options.bannerLanguageTag !== "string") {
            throw new TypeError("SSH authentication banner language tag must be a string")
        }
        if (this.#options.banner.length === 0 && this.#options.bannerLanguageTag.length > 0) {
            throw new TypeError("SSH authentication banner language tag requires a banner")
        }
        encodeSSHUTF8(this.#options.banner, "SSH authentication banner")
        encodeSSHLanguageTag(
            this.#options.bannerLanguageTag,
            "SSH authentication banner language tag",
        )
        this.#options.handshakeTimeout ??= 20_000
        this.#options.authenticationTimeout ??= 600_000
        this.#options.replyTimeout ??= 30_000
        this.#options.maxPendingChannelOpens ??= 64
        this.#options.maxChannels ??= 1024
        this.#options.maxAuthenticationAttempts ??= 20
        this.#options.keepaliveInterval ??= 0
        this.#options.keepaliveCountMax ??= 3
        this.#options.rekeyBytes ??= DEFAULT_REKEY_BYTES
        this.#options.rekeyInterval ??= DEFAULT_REKEY_INTERVAL
        if (
            !Number.isFinite(this.#options.handshakeTimeout) ||
            this.#options.handshakeTimeout < 0
        ) {
            throw new RangeError("SSH handshake timeout must be a non-negative number")
        }
        if (
            !Number.isFinite(this.#options.authenticationTimeout) ||
            this.#options.authenticationTimeout < 0
        ) {
            throw new RangeError("SSH authentication timeout must be a non-negative number")
        }
        if (!Number.isFinite(this.#options.replyTimeout) || this.#options.replyTimeout <= 0) {
            throw new RangeError("SSH reply timeout must be a positive number")
        }
        if (
            !Number.isSafeInteger(this.#options.maxPendingChannelOpens) ||
            this.#options.maxPendingChannelOpens < 0
        ) {
            throw new RangeError(
                "SSH maximum pending channel opens must be a non-negative safe integer",
            )
        }
        if (!Number.isSafeInteger(this.#options.maxChannels) || this.#options.maxChannels < 0) {
            throw new RangeError(
                "SSH maximum simultaneous channels must be a non-negative safe integer",
            )
        }
        if (
            !Number.isInteger(this.#options.maxAuthenticationAttempts) ||
            this.#options.maxAuthenticationAttempts < 1
        ) {
            throw new RangeError("SSH maximum authentication attempts must be a positive integer")
        }
        if (
            !Number.isFinite(this.#options.keepaliveInterval) ||
            this.#options.keepaliveInterval < 0
        ) {
            throw new RangeError("SSH keepalive interval must be a non-negative number")
        }
        if (
            !Number.isInteger(this.#options.keepaliveCountMax) ||
            this.#options.keepaliveCountMax < 0
        ) {
            throw new RangeError("SSH keepalive count maximum must be a non-negative integer")
        }
        validateRekeyBytes(this.#options.rekeyBytes)
        validateRekeyInterval(this.#options.rekeyInterval)
        const gssapiKeyExchangeAlgorithms = createGSSAPIKeyExchangeAlgorithms(this.#options.gssapi)
        const kexAlgorithms = registerKeyExchanges(this, [
            ...kex_algorithms,
            ...gssapiKeyExchangeAlgorithms,
        ])
        this.algorithmOffer = resolveServerAlgorithmOptions(
            this.#options.algorithms,
            {
                kex: [...kexAlgorithms.keys()],
                serverHostKey: [...host_key_algorithms.keys()],
                cipher: [...encryption_algorithms.keys()],
                hmac: [...mac_algorithm_names],
                compress: [...compression_algorithms.keys()],
            },
            {
                ...default_algorithm_names,
                kex: [...gssapiKeyExchangeAlgorithms.keys(), ...default_algorithm_names.kex],
            },
        )
        if (
            this.algorithmOffer.serverHostKey.includes("null") &&
            this.algorithmOffer.serverHostKey.length !== 1
        ) {
            throw new TypeError("SSH server null host key must be the only advertised host key")
        }
        if (
            this.algorithmOffer.serverHostKey[0] === "null" &&
            !this.algorithmOffer.kex.some((name) => gssapiKeyExchangeAlgorithms.has(name))
        ) {
            throw new TypeError("SSH server null host key requires a GSS-API key-exchange method")
        }
        this.server = net.createServer((socket) => void this.acceptSocket(socket))
        this.server.on("error", (error) => this.emit("error", error))
        this.server.on("listening", () => this.emit("listening"))
        this.server.on("close", () => {
            this.debug("Server closed")
            this.emit("close")
        })

        if (
            this.#options.hostKeys.length === 0 &&
            this.algorithmOffer.serverHostKey[0] !== "null"
        ) {
            console.warn(
                "[node-ssh] No host key supplied. Generating a temporary Ed25519 host key.",
            )
            this.hostKeysReady = PrivateKey.generate("ssh-ed25519").then((key) => {
                this.#options.hostKeys.push(key)
            })
        } else {
            this.hostKeysReady = Promise.resolve()
        }
        registerServerConfiguration(this, this.#options)
    }

    hooker = new Hooker<ServerHooker>()
    server: net.Server
    clients = new Set<ServerClient>()
    readonly algorithmOffer: ResolvedAlgorithmOptions
    private readonly hostKeysReady: Promise<void>
    private maximumConnections = Infinity
    private readonly transports = new Set<ServerTransport>()
    private listenRequested = false
    private listenRequestId = 0

    get maxConnections(): number {
        return this.maximumConnections
    }

    set maxConnections(value: number) {
        if (value !== Infinity && (!Number.isInteger(value) || value < 0)) {
            throw new RangeError(
                "SSH server maximum connections must be a non-negative integer or Infinity",
            )
        }
        this.maximumConnections = value
    }

    listen(port?: number, hostname?: string, backlog?: number): this
    listen(port?: number, backlog?: number): this
    listen(path: string, backlog?: number): this
    listen(options: net.ListenOptions): this
    listen(handle: unknown, backlog?: number): this
    listen(...args: unknown[]): this {
        if (args.some((argument) => typeof argument === "function")) {
            throw new TypeError("Server.listen does not accept callback listeners; use 'listening'")
        }
        if (this.listenRequested || this.server.listening) {
            throw new Error("SSH server is already starting or listening")
        }
        this.listenRequested = true
        const requestId = ++this.listenRequestId
        void this.hostKeysReady
            .then(() => {
                if (requestId !== this.listenRequestId) return
                try {
                    Reflect.apply(this.server.listen, this.server, args)
                } finally {
                    if (requestId === this.listenRequestId) this.listenRequested = false
                }
            })
            .catch((error: unknown) => {
                if (requestId !== this.listenRequestId) return
                this.listenRequested = false
                this.emit("error", error instanceof Error ? error : new Error(String(error)))
            })

        return this
    }

    injectSocket(socket: ServerTransport): this {
        if (!isReadable(socket) || !socket.writable || socket.destroyed) {
            throw new TypeError("SSH server transport must be open, readable, and writable")
        }
        if (!this.reserveTransport(socket)) return this
        void this.hostKeysReady
            .then(() => {
                if (!isReadable(socket) || !socket.writable || socket.destroyed) {
                    if (!socket.destroyed) socket.destroy()
                    return
                }
                return this.acceptSocket(socket, true)
            })
            .catch((error: unknown) => {
                const failure = error instanceof Error ? error : new Error(String(error))
                if (!socket.destroyed) socket.destroy(failure)
                this.emit("error", failure)
            })
        return this
    }

    address(): ReturnType<net.Server["address"]> {
        return this.server.address()
    }

    async getConnections(): Promise<number> {
        return this.transports.size
    }

    close(): Promise<void> {
        if (this.listenRequested && !this.server.listening) {
            this.listenRequested = false
            this.listenRequestId++
            this.debug("Server startup cancelled")
            this.emit("close")
            return Promise.resolve()
        }
        return new Promise((resolve, reject) => {
            this.server.close((error) => (error ? reject(error) : resolve()))
        })
    }

    ref(): this {
        this.server.ref()
        return this
    }

    unref(): this {
        this.server.unref()
        return this
    }

    private reserveTransport(socket: ServerTransport): boolean {
        if (this.transports.has(socket)) return false
        if (this.transports.size >= this.maxConnections) {
            this.debug(`Connection limit of ${this.maxConnections} reached`)
            socket.destroy()
            return false
        }
        this.transports.add(socket)
        socket.once("close", () => this.transports.delete(socket))
        return true
    }

    private async acceptSocket(socket: ServerTransport, reserved = false): Promise<void> {
        if (!reserved && !this.reserveTransport(socket)) return
        this.debug(`Connection from ${socket.remoteAddress?.toString() ?? "unknown"}`)
        const connectionInfo: Readonly<ServerConnectionInfo> = Object.freeze({
            remoteAddress: socket.remoteAddress,
            remoteFamily: socket.remoteFamily,
            remotePort: socket.remotePort,
            localAddress: socket.localAddress,
            localFamily: socket.localFamily,
            localPort: socket.localPort,
        })
        const client = new ServerClient(socket, this)
        try {
            if (this.hooker.hasHooks("preconnect")) {
                const controller: ServerHookerPreconnectController = { allowConnection: false }
                let removeCloseListener!: () => void
                const closed = new Promise<false>((resolve) => {
                    const onClose = (): void => resolve(false)
                    client.once("close", onClose)
                    removeCloseListener = () => client.off("close", onClose)
                })
                const policyCompleted = await Promise.race([
                    this.hooker.triggerHookChecked("preconnect", controller, client),
                    closed,
                ]).finally(removeCloseListener)
                if (
                    !policyCompleted ||
                    !controller.allowConnection ||
                    socket.destroyed ||
                    !isReadable(socket) ||
                    !socket.writable
                ) {
                    client.terminate()
                    return
                }
            }
            this.clients.add(client)
            client.once("close", () => this.clients.delete(client))
            this.emit("connection", client, connectionInfo)
            await client.connect()
        } catch (error) {
            client.debug("Error in client connection:", error)
            if (error instanceof DisconnectError) client.disconnect(error)
            else client.terminate()
        }
    }

    debug(...message: unknown[]): void {
        this.#options.debug?.(...message)
        this.emit("debug", ...message)
    }
}
