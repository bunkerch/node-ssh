import EventEmitter from "node:events"
import TypedEmitter from "typed-emitter"
import ProtocolVersionExchange from "./ProtocolVersionExchange.js"
import net from "net"
import ServerClient from "./ServerClient.js"
import { Hooker } from "./utils/Hooker.js"
import PrivateKey, { SSHED25519PrivateKey } from "./utils/PrivateKey.js"

export interface ServerOptions {
    protocolVersionExchange?: ProtocolVersionExchange
    hostKeys?: PrivateKey[]
}
export interface ServerOptionsRequired extends Required<ServerOptions> {}

export type ServerEvents = {
    debug: (...message: any[]) => void
    close: () => void
}

export type ServerHookerPreconnectController = {
    allowConnection: boolean
}
export type ServerHooker = {
    preconnect: [preconnectController: ServerHookerPreconnectController, client: ServerClient]
}

export default class Server extends (EventEmitter as new () => TypedEmitter<ServerEvents>) {
    options: ServerOptionsRequired

    constructor(options: ServerOptions = {}) {
        super()
        this.options = options as ServerOptionsRequired
        this.options.protocolVersionExchange ??= ProtocolVersionExchange.defaultValue
        // generate a random host key if none is provided
        // one per algorithm, please
        this.options.hostKeys ??= [PrivateKey.generate(SSHED25519PrivateKey.alg_name)]
    }

    hooker: Hooker<ServerHooker> = new Hooker()
    server?: net.Server
    clients: Set<ServerClient> = new Set()

    listen(port?: number, hostname?: string, backlog?: number, listeningListener?: () => void): this
    listen(port?: number, hostname?: string, listeningListener?: () => void): this
    listen(port?: number, backlog?: number, listeningListener?: () => void): this
    listen(port?: number, listeningListener?: () => void): this
    listen(path: string, backlog?: number, listeningListener?: () => void): this
    listen(path: string, listeningListener?: () => void): this
    listen(options: net.ListenOptions, listeningListener?: () => void): this
    listen(handle: any, backlog?: number, listeningListener?: () => void): this
    listen(handle: any, listeningListener?: () => void): this
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    listen(opt1: any, opt2: any, opt3?: any, opt4?: any): this {
        const server = net.createServer()

        server.listen(...arguments)
        server.on("close", () => {
            this.emit("debug", "Server closed")
            this.clients = new Set()
            this.emit("close")
        })
        server.on("connection", async (socket) => {
            this.emit("debug", `Connection from ${socket.remoteAddress?.toString() ?? "unknown"}`)

            const client = new ServerClient(socket, this)

            // if the server wants to deny the connection
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

            client.connect()
        })

        this.server = server

        return this
    }

    debug(...message: any[]): void {
        this.emit("debug", ...message)
    }
}
