import EventEmitter, { once } from "node:events"
import { chmod } from "node:fs/promises"
import net, { type Server as NetServer, type Socket } from "node:net"
import type Client from "../Client.js"
import { Hooker } from "../utils/Hooker.js"
import {
    CONTROL_MULTIPLEX_VERSION,
    ControlMultiplexDecoder,
    ControlMultiplexMessageType,
    ControlMultiplexProtocolError,
    encodeControlMultiplexHello,
    encodeControlMultiplexReply,
    type ControlMultiplexRequest,
} from "./ControlMultiplexCodec.js"

export interface ControlMasterOptions {
    path: string
    /** Maximum simultaneous local control connections. Defaults to 64. */
    maxConnections?: number
}

export type ControlMasterPolicyRequest = Exclude<
    ControlMultiplexRequest,
    { readonly type: ControlMultiplexMessageType.Hello }
>

// eslint-disable-next-line @typescript-eslint/consistent-type-definitions
export type ControlMasterHooker = {
    request: [request: ControlMasterPolicyRequest, decision: ControlMasterRequestController]
}

export interface ControlMasterRequestController {
    /** Security-sensitive requests are denied unless an awaited hook sets this to true. */
    allow: boolean
    /** Optional denial text returned to the local client. */
    reason?: string
}

// eslint-disable-next-line @typescript-eslint/consistent-type-definitions
export type ControlMasterEvents = {
    listening: []
    close: []
    clientError: [error: Error]
}

interface ControlConnection {
    readonly socket: Socket
    readonly decoder: ControlMultiplexDecoder
    helloReceived: boolean
    queue: Promise<void>
}

export default class ControlMaster extends EventEmitter<ControlMasterEvents> {
    readonly hooker = new Hooker<ControlMasterHooker>()
    readonly path: string
    readonly maxConnections: number

    private server?: NetServer
    private readonly connections = new Set<ControlConnection>()
    private closing = false

    constructor(
        private readonly client: Client,
        options: Readonly<ControlMasterOptions>,
    ) {
        super()
        if (typeof options !== "object" || options === null) {
            throw new TypeError("SSH control master options must be an object")
        }
        if (
            typeof options.path !== "string" ||
            options.path.length === 0 ||
            options.path.includes("\0")
        ) {
            throw new TypeError("SSH control master path must be a non-empty socket path")
        }
        const maxConnections = options.maxConnections ?? 64
        if (!Number.isInteger(maxConnections) || maxConnections < 1 || maxConnections > 4096) {
            throw new RangeError("SSH control master maxConnections must be between 1 and 4096")
        }
        this.path = options.path
        this.maxConnections = maxConnections
    }

    get isListening(): boolean {
        return this.server?.listening === true
    }

    async listen(): Promise<void> {
        if (!this.client.isConnected) {
            throw new Error("SSH client must be connected before starting a control master")
        }
        if (this.server) throw new Error("SSH control master has already been started")
        this.closing = false
        const server = net.createServer({ allowHalfOpen: false }, (socket) => {
            this.accept(socket)
        })
        this.server = server
        server.on("error", (error) => this.reportClientError(error))
        server.listen(this.path)
        try {
            await once(server, "listening")
            await chmod(this.path, 0o600)
        } catch (error) {
            server.close()
            this.server = undefined
            throw error
        }
        this.emit("listening")
    }

    async stopListening(): Promise<void> {
        const server = this.server
        if (!server) return
        this.server = undefined
        if (!server.listening) return
        server.close()
        await once(server, "close")
    }

    async close(): Promise<void> {
        if (this.closing) return
        this.closing = true
        for (const connection of this.connections) connection.socket.destroy()
        await this.stopListening()
        this.closing = false
        this.emit("close")
    }

    private accept(socket: Socket): void {
        if (this.connections.size >= this.maxConnections) {
            socket.destroy()
            return
        }
        const connection: ControlConnection = {
            socket,
            decoder: new ControlMultiplexDecoder(),
            helloReceived: false,
            queue: Promise.resolve(),
        }
        this.connections.add(connection)
        socket.on("data", (chunk) => this.receive(connection, Buffer.from(chunk)))
        socket.on("error", (error) => this.reportClientError(error))
        socket.once("close", () => this.connections.delete(connection))
        socket.write(encodeControlMultiplexHello())
    }

    private receive(connection: ControlConnection, chunk: Buffer): void {
        let requests: readonly ControlMultiplexRequest[]
        try {
            requests = connection.decoder.push(chunk)
        } catch (error) {
            this.failConnection(connection, error)
            return
        }
        for (const request of requests) {
            connection.queue = connection.queue
                .then(() => this.handleRequest(connection, request))
                .catch((error: unknown) => this.failConnection(connection, error))
        }
    }

    private async handleRequest(
        connection: ControlConnection,
        request: ControlMultiplexRequest,
    ): Promise<void> {
        if (!connection.helloReceived) {
            if (!("version" in request) || request.type !== ControlMultiplexMessageType.Hello) {
                throw new ControlMultiplexProtocolError("Expected multiplex hello")
            }
            if (request.version !== CONTROL_MULTIPLEX_VERSION) {
                throw new ControlMultiplexProtocolError(
                    `Unsupported multiplex protocol version ${request.version}`,
                )
            }
            connection.helloReceived = true
            return
        }
        if ("version" in request) {
            throw new ControlMultiplexProtocolError("Duplicate multiplex hello")
        }
        if (request.type === ControlMultiplexMessageType.AliveCheck) {
            connection.socket.write(
                encodeControlMultiplexReply(
                    ControlMultiplexMessageType.Alive,
                    request.requestId,
                    process.pid,
                ),
            )
            return
        }

        const decision: ControlMasterRequestController = { allow: false }
        const completed = await this.hooker.triggerHookChecked("request", request, decision)
        if (!completed || !decision.allow) {
            connection.socket.write(
                encodeControlMultiplexReply(
                    ControlMultiplexMessageType.PermissionDenied,
                    request.requestId,
                    decision.reason ?? "Permission denied",
                ),
            )
            return
        }
        if (request.type === ControlMultiplexMessageType.StopListening) {
            connection.socket.end(
                encodeControlMultiplexReply(ControlMultiplexMessageType.Ok, request.requestId),
            )
            void this.stopListening().catch((error: unknown) => this.reportClientError(error))
            return
        }
        if (request.type === ControlMultiplexMessageType.Terminate) {
            connection.socket.end(
                encodeControlMultiplexReply(ControlMultiplexMessageType.Ok, request.requestId),
            )
            this.client.end()
            void this.close().catch((error: unknown) => this.reportClientError(error))
            return
        }
        connection.socket.write(
            encodeControlMultiplexReply(
                ControlMultiplexMessageType.Failure,
                request.requestId,
                "Unsupported control request",
            ),
        )
    }

    private failConnection(connection: ControlConnection, error: unknown): void {
        connection.socket.destroy()
        this.reportClientError(error)
    }

    private reportClientError(error: unknown): void {
        const normalized = error instanceof Error ? error : new Error(String(error))
        this.emit("clientError", normalized)
    }
}
