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

export interface ServerOptions {
    protocolVersionExchange?: ProtocolVersionExchange
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
}
// eslint-disable-next-line @typescript-eslint/no-empty-object-type
export interface ServerOptionsRequired extends Required<ServerOptions> {}

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
    signature?: EncodedSignature
    signatureMessage: Buffer
}>
export interface ServerHookerPublicKeyAuthenticationController
    extends ServerAuthenticationContinuation {
    requestSignature: boolean
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
}

export default class Server extends EventEmitter<ServerEvents> {
    options: ServerOptionsRequired

    constructor(options: ServerOptions = {}) {
        super()
        this.options = options as ServerOptionsRequired
        this.options.protocolVersionExchange ??= ProtocolVersionExchange.defaultValue
        this.options.hostKeys ??= []
        this.options.sendAllHostKeys ??= true
        this.options.banner ??= ""
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
            client.terminate()
        }
    }

    debug(...message: unknown[]): void {
        this.emit("debug", ...message)
    }
}
