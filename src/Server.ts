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
}
// eslint-disable-next-line @typescript-eslint/no-empty-object-type
export interface ServerOptionsRequired extends Required<ServerOptions> {}

export interface ServerEvents {
    debug: unknown[]
    close: []
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
export type ServerHookerPublicKeyAuthenticationContext = Readonly<{
    username: string
    publicKey: PublicKey
    signature?: EncodedSignature
    signatureMessage: Buffer
}>
export interface ServerHookerPublicKeyAuthenticationController {
    requestSignature: boolean
    allowLogin: boolean
}
export type ServerHookerPasswordAuthenticationContext = Readonly<{
    username: string
    password: string
}>
export interface ServerHookerPasswordAuthenticationController {
    allowLogin: boolean
}
export interface ServerHookerChannelOpenRequestController {
    allowOpen: boolean
}
export interface ServerHookerChannelRequestController {
    deny: boolean
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
}

export default class Server extends EventEmitter<ServerEvents> {
    options: ServerOptionsRequired

    constructor(options: ServerOptions = {}) {
        super()
        this.options = options as ServerOptionsRequired
        this.options.protocolVersionExchange ??= ProtocolVersionExchange.defaultValue
        this.options.hostKeys ??= []
        this.options.sendAllHostKeys ??= true
    }

    hooker = new Hooker<ServerHooker>()
    server?: net.Server
    clients = new Set<ServerClient>()

    listen(port?: number, hostname?: string, backlog?: number, listeningListener?: () => void): this
    listen(port?: number, hostname?: string, listeningListener?: () => void): this
    listen(port?: number, backlog?: number, listeningListener?: () => void): this
    listen(port?: number, listeningListener?: () => void): this
    listen(path: string, backlog?: number, listeningListener?: () => void): this
    listen(path: string, listeningListener?: () => void): this
    listen(options: net.ListenOptions, listeningListener?: () => void): this
    listen(handle: unknown, backlog?: number, listeningListener?: () => void): this
    listen(handle: unknown, listeningListener?: () => void): this
    listen(): this {
        const server = net.createServer()

        // generate host keys if needed
        if (this.options.hostKeys.length === 0) {
            console.warn(
                `[node-ssh] No host key supplied inside ServerOptions. Consider generating some host keys and storing them. Generating temporary ones...`,
            )
            Promise.all(
                [
                    "ssh-ed25519",
                    // ssh-rsa seems to be disabled on recent openssh versions
                    // is it because of sha1 or something ?
                    // "ssh-rsa",
                ].map((algorithm) => PrivateKey.generate(algorithm)),
            ).then((keys) => {
                this.options.hostKeys.push(...keys)
                // eslint-disable-next-line prefer-rest-params
                server.listen(...arguments)
            })
        } else {
            // eslint-disable-next-line prefer-rest-params
            server.listen(...arguments)
        }

        server.on("close", () => {
            this.emit("debug", "Server closed")
            this.clients = new Set()
            this.emit("close")
        })
        server.on("connection", async (socket) => {
            this.emit("debug", `Connection from ${socket.remoteAddress?.toString() ?? "unknown"}`)

            const client = new ServerClient(socket, this)

            // if the server wants to deny the connection (based on ip/stuff ?)
            if (this.hooker.hasHooks("preconnect")) {
                const controller: ServerHookerPreconnectController = {
                    allowConnection: true,
                }
                await this.hooker.triggerHook("preconnect", controller, client)
                if (!controller.allowConnection) {
                    client.terminate()
                    return
                }
            }

            this.clients.add(client)

            this.emit("connection", client)

            client.on("close", () => {
                this.clients.delete(client)
            })

            client.connect().catch((error) => {
                client.debug("Error in client connection:", error)
                client.terminate()
            })
        })

        this.server = server

        return this
    }

    debug(...message: unknown[]): void {
        this.emit("debug", ...message)
    }
}
