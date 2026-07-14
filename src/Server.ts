// this causes issues with the Server#listen method.

import EventEmitter from "node:events"
import ProtocolVersionExchange from "./ProtocolVersionExchange.js"
import net from "net"
import ServerClient from "./ServerClient.js"
import { Hooker } from "./utils/Hooker.js"
import PrivateKey from "./utils/PrivateKey.js"
import PublicKey from "./utils/PublicKey.js"
import EncodedSignature from "./utils/Signature.js"
import Channel from "./Channel.js"
import { SSHAuthenticationMethods } from "./constants.js"
import { DisconnectError } from "./packets/Disconnect.js"
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
    mac_algorithms,
} from "./algorithms.js"

export interface ServerOptions {
    protocolVersionExchange?: ProtocolVersionExchange
    /** Custom SSH software identifier and optional comments, without the `SSH-2.0-` prefix. */
    ident?: string | Buffer
    /** Informational text sent before the SSH identification. */
    greeting?: string
    algorithms?: ServerAlgorithmOptions
    hostKeys?: PrivateKey[]
    // by default, the Server will send all available hostkeys
    // to the client after login (USERAUTH_SUCCESS)
    // this allows the client to save them and then to accept unknown
    // of them on the next login.
    // This is particularily useful when a transition in hostkeys
    // is happening (for example deprecating an host key)
    sendAllHostKeys?: boolean
    /** RFC 4252 banner sent once before authentication begins. */
    banner?: string
    /** Milliseconds allowed after accepting the user-authentication service. Zero disables. */
    authenticationTimeout?: number
    /** Maximum rejected non-`none` authentication requests per connection. */
    maxAuthenticationAttempts?: number
}
export interface ServerOptionsRequired
    extends Required<Omit<ServerOptions, "ident" | "algorithms">> {
    ident?: string | Buffer
    algorithms?: ServerAlgorithmOptions
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
    connection: [client: ServerClient]
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
export interface ServerHookerChannelOpenRequestController {
    allowOpen: boolean
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
    options: ServerOptionsRequired

    constructor(options: ServerOptions = {}) {
        super()
        this.options = options as ServerOptionsRequired
        if (
            this.options.ident !== undefined &&
            this.options.protocolVersionExchange !== undefined
        ) {
            throw new TypeError(
                "SSH ident and protocolVersionExchange options are mutually exclusive",
            )
        }
        this.options.protocolVersionExchange =
            this.options.ident === undefined
                ? (this.options.protocolVersionExchange ?? ProtocolVersionExchange.defaultValue)
                : ProtocolVersionExchange.fromIdent(this.options.ident)
        this.options.greeting = normalizeGreeting(this.options.greeting ?? "")
        this.options.hostKeys ??= []
        this.options.sendAllHostKeys ??= true
        this.options.banner ??= ""
        this.options.authenticationTimeout ??= 600_000
        this.options.maxAuthenticationAttempts ??= 20
        if (
            !Number.isFinite(this.options.authenticationTimeout) ||
            this.options.authenticationTimeout < 0
        ) {
            throw new RangeError("SSH authentication timeout must be a non-negative number")
        }
        if (
            !Number.isInteger(this.options.maxAuthenticationAttempts) ||
            this.options.maxAuthenticationAttempts < 1
        ) {
            throw new RangeError("SSH maximum authentication attempts must be a positive integer")
        }
        this.algorithmOffer = resolveServerAlgorithmOptions(this.options.algorithms, {
            kex: [...kex_algorithms.keys()],
            serverHostKey: [...host_key_algorithms.keys()],
            cipher: [...encryption_algorithms.keys()],
            hmac: [...mac_algorithms.keys()],
            compress: [...compression_algorithms.keys()],
        })
        this.server = net.createServer((socket) => void this.acceptSocket(socket))
        this.server.on("error", (error) => this.emit("error", error))
        this.server.on("listening", () => this.emit("listening"))
        this.server.on("close", () => {
            this.debug("Server closed")
            this.emit("close")
        })

        if (this.options.hostKeys.length === 0) {
            console.warn(
                "[node-ssh] No host key supplied. Generating a temporary Ed25519 host key.",
            )
            this.hostKeysReady = PrivateKey.generate("ssh-ed25519").then((key) => {
                this.options.hostKeys.push(key)
            })
        } else {
            this.hostKeysReady = Promise.resolve()
        }
    }

    hooker = new Hooker<ServerHooker>()
    server: net.Server
    clients = new Set<ServerClient>()
    readonly algorithmOffer: ResolvedAlgorithmOptions
    private readonly hostKeysReady: Promise<void>

    listen(port?: number, hostname?: string, backlog?: number, listeningListener?: () => void): this
    listen(port?: number, hostname?: string, listeningListener?: () => void): this
    listen(port?: number, backlog?: number, listeningListener?: () => void): this
    listen(port?: number, listeningListener?: () => void): this
    listen(path: string, backlog?: number, listeningListener?: () => void): this
    listen(path: string, listeningListener?: () => void): this
    listen(options: net.ListenOptions, listeningListener?: () => void): this
    listen(handle: unknown, backlog?: number, listeningListener?: () => void): this
    listen(handle: unknown, listeningListener?: () => void): this
    listen(...args: unknown[]): this {
        void this.hostKeysReady.then(() => {
            Reflect.apply(this.server.listen, this.server, args)
        })

        return this
    }

    injectSocket(socket: net.Socket): this {
        void this.hostKeysReady.then(() => this.acceptSocket(socket))
        return this
    }

    address(): ReturnType<net.Server["address"]> {
        return this.server.address()
    }

    getConnections(callback: (error: Error | null, count: number) => void): this {
        queueMicrotask(() => callback(null, this.clients.size))
        return this
    }

    close(callback?: (error?: Error) => void): this {
        this.server.close(callback)
        return this
    }

    ref(): this {
        this.server.ref()
        return this
    }

    unref(): this {
        this.server.unref()
        return this
    }

    private async acceptSocket(socket: net.Socket): Promise<void> {
        this.debug(`Connection from ${socket.remoteAddress?.toString() ?? "unknown"}`)
        const client = new ServerClient(socket, this)
        try {
            if (this.hooker.hasHooks("preconnect")) {
                const controller: ServerHookerPreconnectController = { allowConnection: true }
                await this.hooker.triggerHook("preconnect", controller, client)
                if (!controller.allowConnection) {
                    client.terminate()
                    return
                }
            }
            this.clients.add(client)
            client.once("close", () => this.clients.delete(client))
            this.emit("connection", client)
            await client.connect()
        } catch (error) {
            client.debug("Error in client connection:", error)
            if (error instanceof DisconnectError) client.disconnect(error)
            else client.terminate()
        }
    }

    debug(...message: unknown[]): void {
        this.emit("debug", ...message)
    }
}
