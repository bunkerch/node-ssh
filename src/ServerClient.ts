import net, { Socket } from "node:net"
import { PassThrough } from "node:stream"
import Server, {
    ServerHookerChannelOpenRequestController,
    ServerHookerNoneAuthenticationContext,
    ServerHookerNoneAuthenticationController,
    ServerHookerPasswordAuthenticationContext,
    ServerHookerPasswordAuthenticationController,
    ServerHookerPublicKeyAuthenticationContext,
    ServerHookerPublicKeyAuthenticationController,
    ServerHookerStreamLocalForwardContext,
    ServerHookerTCPIPForwardContext,
} from "./Server.js"
import ProtocolVersionExchange from "./ProtocolVersionExchange.js"
import crypto from "node:crypto"
import EventEmitter from "node:events"
import {
    SSHAuthenticationMethods,
    PacketNameToType,
    SSHServiceNames,
    SocketState,
    PacketType,
    PacketTypeToName,
} from "./constants.js"
import KexInit from "./packets/KexInit.js"
import {
    EncryptionAlgorithm,
    KexAlgorithm,
    MACAlgorithm,
    chooseAlgorithms,
    encryption_algorithms,
    kex_algorithms,
    mac_algorithms,
} from "./algorithms.js"
import PublicKey, { PublicKeyAlgoritm } from "./utils/PublicKey.js"
import KexDHReply from "./packets/KexDHReply.js"
import assert from "node:assert"
import Packet, { packets } from "./packet.js"
import Disconnect, { DisconnectError, DisconnectReason } from "./packets/Disconnect.js"
import DiffieHellmanGroupN from "./algorithms/kex/diffie-hellman-groupN.js"
import KexDHInit from "./packets/KexDHInit.js"
import NewKeys from "./packets/NewKeys.js"
import ServiceRequest from "./packets/ServiceRequest.js"
import ServiceAccept from "./packets/ServiceAccept.js"
import UserAuthRequest, { AuthMethod } from "./packets/UserAuthRequest.js"
import UserAuthFailure from "./packets/UserAuthFailure.js"
import PublicKeyAuthMethod from "./auth/publickey.js"
import UserAuthPKOK from "./packets/UserAuthPKOK.js"
import PasswordAuthMethod from "./auth/password.js"
import UserAuthSuccess from "./packets/UserAuthSuccess.js"
import { randomBase36 } from "./utils/base36.js"
import Debug from "./packets/Debug.js"
import Channel from "./Channel.js"
import GlobalRequest from "./packets/GlobalRequest.js"
import { readNextBuffer, readNextUint32, serializeBuffer, serializeUint32 } from "./utils/Buffer.js"
import RequestFailure from "./packets/RequestFailure.js"
import RequestSuccess from "./packets/RequestSuccess.js"
import ChannelOpen from "./packets/ChannelOpen.js"
import ChannelOpenFailure, {
    ChannelOpenError,
    ChannelOpenFailureReasonCodes,
} from "./packets/ChannelOpenFailure.js"
import { channelFromChannelOpenPacket } from "./channels.js"
import ChannelRequest from "./packets/ChannelRequest.js"
import { ActionQueue } from "./utils/ActionQueue.js"
import ChannelData from "./packets/ChannelData.js"
import ChannelExtendedData from "./packets/ChannelExtendedData.js"
import ChannelWindowAdjust from "./packets/ChannelWindowAdjust.js"
import ChannelEOF from "./packets/ChannelEOF.js"
import ChannelClose from "./packets/ChannelClose.js"
import ChannelOpenConfirmation from "./packets/ChannelOpenConfirmation.js"
import IdentificationParser from "./IdentificationParser.js"
import { BinaryPacketDecoder, BinaryPacketEncoder } from "./BinaryPacket.js"
import ForwardedTCPIPChannel from "./channels/ForwardedTCPIPChannel.js"
import ForwardedStreamLocalChannel from "./channels/ForwardedStreamLocalChannel.js"

interface RemoteForwardListener {
    server: net.Server
}

export interface ServerClientEvents {
    error: [error: Error]
    close: []
    connect: []
    debug: [...message: unknown[]]
    message: [message: Buffer]
    clientProtocolVersion: [version: ProtocolVersionExchange]
    tcpWrapperLog: [message: string]
    packet: [packet: Packet]
    clientKexInit: [kexInit: KexInit, payload: Buffer]
    clientNewKeys: []
    serverNewKeys: []

    channelOpenRequest: [packet: ChannelOpen]
    channelRequest: [packet: ChannelRequest]
    channelData: [packet: ChannelData]
    channel: [channel: Channel]
}

export default class ServerClient extends EventEmitter<ServerClientEvents> {
    private socket: Socket
    connectionId: string
    server: Server

    queue = new ActionQueue<string>()

    constructor(socket: Socket, server: Server) {
        super()
        this.socket = socket
        this.server = server
        this.connectionId = randomBase36(9)

        this.socket.on("data", (data) => {
            try {
                this.onMessage(data)
            } catch (err) {
                this.emit("error", err as Error)
                this.terminate()
            }
        })

        this.socket.on("error", (error) => {
            this.emit("error", error)
        })

        this.socket.on("close", () => {
            this.state = SocketState.Disconnected
            for (const forwarding of this.remoteForwardListeners.values()) forwarding.server.close()
            this.remoteForwardListeners.clear()
            for (const forwarding of this.remoteStreamLocalListeners.values()) {
                forwarding.server.close()
            }
            this.remoteStreamLocalListeners.clear()
            for (const channel of this.channels.values()) channel.abort()
            this.channels.clear()
            this.emit("close")
        })
    }

    private buffering: Buffer = Buffer.alloc(0)
    private identificationParser = new IdentificationParser({ allowPreamble: false })
    private packetDecoder = new BinaryPacketDecoder()
    private packetEncoder = new BinaryPacketEncoder()
    private packetProcessingPaused = false

    clientProtocolVersion?: ProtocolVersionExchange
    clientKexDHInit?: KexDHInit
    // TODO: Assess if these should be private properties
    clientKexInit?: KexInit
    serverKexInit?: KexInit
    kexAlgorithm?: KexAlgorithm
    hostKeyAlgorithm?: typeof PublicKeyAlgoritm
    clientEncryptionAlgorithm?: typeof EncryptionAlgorithm
    serverEncryptionAlgorithm?: typeof EncryptionAlgorithm
    clientEncryption?: EncryptionAlgorithm
    serverEncryption?: EncryptionAlgorithm
    clientMacAlgorithm?: typeof MACAlgorithm
    serverMacAlgorithm?: typeof MACAlgorithm
    clientMac?: MACAlgorithm
    serverMac?: MACAlgorithm

    // TODO: Set those as private properties (Need to be accessed by the algorithms only)
    H?: Buffer
    sessionID?: Buffer
    ivClientToServer?: Buffer
    ivServerToClient?: Buffer
    encryptionKeyClientToServer?: Buffer
    encryptionKeyServerToClient?: Buffer
    integrityKeyClientToServer?: Buffer
    integrityKeyServerToClient?: Buffer

    hasReceivedNewKeys = false
    hasSentNewKeys = false
    hasAuthenticated = false
    credentials: UserAuthRequest | undefined

    localChannelIndex = 0
    channels = new Map<number, Channel>()
    private readonly remoteForwardListeners = new Map<string, RemoteForwardListener>()
    private readonly remoteStreamLocalListeners = new Map<string, RemoteForwardListener>()

    state = SocketState.Closed
    get isConnected(): boolean {
        return this.state === SocketState.Connected
    }

    get remoteAddress() {
        return this.socket.remoteAddress
    }

    disconnect() {
        this.socket.end()
        this.state = SocketState.Disconnected
    }

    terminate() {
        this.socket.destroy()
        this.state = SocketState.Disconnected
    }

    async connect(): Promise<void> {
        this.state = SocketState.Connecting
        const clientProtocolVersionPromise = this.waitEvent("clientProtocolVersion")
        const clientKexInitPromise = this.waitEvent("clientKexInit")
        const clientNewKeysPromise = this.waitEvent("clientNewKeys")

        this.debug(`Socket connected, sending protocol version exchange packet...`)
        this.socket.write(this.server.options.protocolVersionExchange.toString())
        if (this.buffering.length > 0) {
            this.onMessage(Buffer.alloc(0))
        }

        const [clientProtocolVersion] = await clientProtocolVersionPromise
        this.debug("Client protocol version:", clientProtocolVersion)

        this.serverKexInit = new KexInit({
            cookie: crypto.getRandomValues(Buffer.alloc(16)),
            kex_algorithms: [...kex_algorithms.keys()],
            server_host_key_algorithms: [
                // remove duplicates
                ...new Set(this.server.options.hostKeys.map((e) => e.data.alg)),
            ],
            encryption_algorithms_client_to_server: [...encryption_algorithms.keys()],
            encryption_algorithms_server_to_client: [...encryption_algorithms.keys()],
            mac_algorithms_client_to_server: [...mac_algorithms.keys()],
            mac_algorithms_server_to_client: [...mac_algorithms.keys()],
            // we don't support compression yet
            compression_algorithms_client_to_server: ["none"],
            compression_algorithms_server_to_client: ["none"],
            languages_client_to_server: [],
            languages_server_to_client: [],
            // TODO: Determine what this field does
            first_kex_packet_follows: false,
        })
        this.sendPacket(this.serverKexInit)

        const [clientKexInit, clientKexInitBuffer] = await clientKexInitPromise
        this.clientKexInit = clientKexInit
        this.debug("Client KexInit:", clientKexInit)
        chooseAlgorithms(this)

        if (this.kexAlgorithm instanceof DiffieHellmanGroupN) {
            this.debug(
                "Using DiffieHellmanGroupN key exchange algorithm",
                (this.kexAlgorithm.constructor as typeof KexAlgorithm).alg_name,
            )
            const [clientKexDHInit] = (await this.waitEvent("packet")) as [KexDHInit]
            assert(clientKexDHInit instanceof KexDHInit, "Invalid packet type")
            this.debug("Client KexDHInit:", clientKexDHInit)
            this.clientKexDHInit = clientKexDHInit

            this.kexAlgorithm!.generateKeyPair()
            this.kexAlgorithm!.sharedSecret = this.kexAlgorithm!.keyPair!.computeSecret(
                clientKexDHInit.data.e,
            )

            const hostKey = this.server.options.hostKeys.find(
                (key) => key.data.alg === this.hostKeyAlgorithm!.alg_name,
            )
            assert(hostKey, "No host key found")
            const publicKey = hostKey.data.publicKey.serialize()

            const h = this.kexAlgorithm!.computeHServer(this, clientKexInitBuffer, publicKey)

            this.sendPacket(
                new KexDHReply({
                    K_S: publicKey,
                    f: this.kexAlgorithm!.keyPair!.getPublicKey(),
                    H_sig: hostKey.data.algorithm.sign(h).serialize(),
                }),
            )

            this.H = h
            this.sessionID = h
        } else {
            throw new Error("Unsupported key exchange algorithm (Not Implemented in ServerClient)")
        }

        this.kexAlgorithm.deriveKeysClient(this)
        this.debug("Derived keys:", {
            ivClientToServer: this.ivClientToServer,
            ivServerToClient: this.ivServerToClient,
            encryptionKeyClientToServer: this.encryptionKeyClientToServer,
            encryptionKeyServerToClient: this.encryptionKeyServerToClient,
            integrityKeyClientToServer: this.integrityKeyClientToServer,
            integrityKeyServerToClient: this.integrityKeyServerToClient,
        })

        this.clientEncryption = this.clientEncryptionAlgorithm!.instantiate(
            this.encryptionKeyClientToServer!,
            this.ivClientToServer!,
        )
        this.serverEncryption = this.serverEncryptionAlgorithm!.instantiate(
            this.encryptionKeyServerToClient!,
            this.ivServerToClient!,
        )
        this.clientMac = this.clientMacAlgorithm!.instantiate(this.integrityKeyClientToServer!)
        this.serverMac = this.serverMacAlgorithm!.instantiate(this.integrityKeyServerToClient!)
        this.resumePacketProcessing()

        await clientNewKeysPromise

        this.sendPacket(new NewKeys({}))
        this.hasSentNewKeys = true
        this.packetEncoder.setProtection({
            cipher: this.serverEncryption,
            mac: this.serverMac,
            blockSize: this.serverEncryptionAlgorithm!.block_size,
            macLength: this.serverMacAlgorithm!.digest_length,
        })
        this.emit("serverNewKeys")

        this.debug("Keys exchanged, encryption and MAC algorithms set up")
        this.debug("Starting authentication...")

        const [serviceRequest] = (await this.waitEvent("packet")) as [ServiceRequest]
        assert(serviceRequest instanceof ServiceRequest, "Invalid packet type")
        this.debug("Client requested service:", serviceRequest.data.service_name)
        assert(
            serviceRequest.data.service_name === SSHServiceNames.UserAuth,
            "Invalid service received from client",
        )

        this.sendPacket(
            new ServiceAccept({
                service_name: SSHServiceNames.UserAuth,
            }),
        )

        await this.handleAuthentication()
        // user is logged in!
        this.state = SocketState.Connected
        // emit the event
        this.emit("connect")

        // now that we have received USERAUTH_SUCCESS, we need
        // to handle GLOBAL_REQUEST.

        this.on("packet", (packet) => {
            if (!(packet instanceof GlobalRequest)) return
            void this.queue
                .queueAction("globalRequest", () => this.handleGlobalRequest(packet))
                .catch((error: Error) => {
                    this.emit("error", error)
                    this.terminate()
                })
        })

        if (this.server.options.sendAllHostKeys) {
            // we can send every host key we have
            // https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL?annotate=HEAD
            // section 2.5 (ctrl + f search for "hostkeys-00@openssh.com")
            this.sendPacket(
                new GlobalRequest({
                    request_name: "hostkeys-00@openssh.com",
                    want_reply: false,
                    args: Buffer.concat(
                        this.server.options.hostKeys.map((key) => {
                            return serializeBuffer(key.data.publicKey.serialize())
                        }),
                    ),
                }),
            )
        }

        this.on("channelOpenRequest", async (packet) => {
            this.debug(`ChannelOpenRequest`, packet)

            const lock = await this.queue.obtainLock("channelOpenRequest")
            try {
                const channel = channelFromChannelOpenPacket(packet, this)
                const controller: ServerHookerChannelOpenRequestController = {
                    allowOpen: false,
                }

                await this.server.hooker.triggerHook(
                    "channelOpenRequest",
                    channel,
                    controller,
                    this,
                )

                if (!controller.allowOpen) {
                    throw new ChannelOpenError(
                        ChannelOpenFailureReasonCodes.SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
                        packet.data.sender_channel_id,
                        "Opening channel type not allowed by the server.",
                    )
                }

                this.debug(`Opening channel`, channel)
                this.channels.set(channel.localId, channel)
                this.sendPacket(channel.getChannelOpenConfirmationPacket())
                this.emit("channel", channel)
            } catch (err) {
                this.debug(`ChannelOpenRequest failed:`, err)

                if (err instanceof ChannelOpenError) {
                    this.sendPacket(err.getOpenFailurePacket())
                } else {
                    this.debug(`An error occured:`, err)
                    this.sendPacket(
                        new ChannelOpenFailure({
                            reason_code: ChannelOpenFailureReasonCodes.SSH_OPEN_CONNECT_FAILED,
                            description: "An error occured on the server",
                            language_tag: "",
                            recipient_channel_id: packet.data.sender_channel_id,
                        }),
                    )
                }
            } finally {
                lock.release()
            }
        })
        this.on("channelRequest", async (packet) => {
            const channel = this.channels.get(packet.data.recipient_channel_id)
            if (!channel) {
                const error = new DisconnectError(
                    DisconnectReason.SSH_DISCONNECT_PROTOCOL_ERROR,
                    "Invalid channel id received.",
                )
                this.emit("error", error)
                this.terminate()
                return
            }

            // make sure pty request is handled before exec/shell, etc
            const lock = await this.queue.obtainLock(`channel:${packet.data.recipient_channel_id}`)
            try {
                const deny = await channel.preHandleChannelRequest(packet)
                if (deny) return

                await channel.handleChannelRequest(packet)
            } catch (err) {
                this.debug(
                    `An error occured in the Channel Request handler. This could be due to a faulty request or an implementation bug.`,
                    err,
                )
                // the base method will send a channel failure.
                await Channel.prototype.handleChannelRequest.call(channel, packet)
            } finally {
                lock.release()
            }
        })
    }

    private async handleGlobalRequest(packet: GlobalRequest): Promise<void> {
        this.debug(`Received global request packet:`, packet)

        switch (packet.data.request_name) {
            case "hostkeys-prove-00@openssh.com":
                this.handleHostKeysProof(packet)
                return
            case "tcpip-forward":
                await this.handleTCPIPForward(packet)
                return
            case "cancel-tcpip-forward":
                await this.handleCancelTCPIPForward(packet)
                return
            case "streamlocal-forward@openssh.com":
                await this.handleStreamLocalForward(packet)
                return
            case "cancel-streamlocal-forward@openssh.com":
                await this.handleCancelStreamLocalForward(packet)
                return
            default:
                this.debug(`Unknown global request name: ${packet.data.request_name}`)
                if (packet.data.want_reply) this.sendPacket(new RequestFailure({}))
        }
    }

    private handleHostKeysProof(packet: GlobalRequest): void {
        const hostkeys = []
        let raw = packet.data.args
        while (raw.length !== 0) {
            let arg: Buffer
            ;[arg, raw] = readNextBuffer(raw)

            try {
                hostkeys.push(PublicKey.parse(arg))
            } catch (error) {
                this.debug(`Error while trying to parse host key:`, error)
            }
        }

        this.debug(`Client asked us to prove ownership of`, hostkeys.length, `keys.`)
        const signatures = []
        for (const publicKey of hostkeys) {
            const hostKey = this.server.options.hostKeys.find((privateKey) =>
                privateKey.data.publicKey.equals(publicKey),
            )
            if (!hostKey) {
                this.debug(`Client requested proof for a public key the server does not control`)
                if (packet.data.want_reply) this.sendPacket(new RequestFailure({}))
                return
            }

            const message = Buffer.concat([
                serializeBuffer(Buffer.from("hostkeys-prove-00@openssh.com", "utf8")),
                serializeBuffer(this.sessionID!),
                serializeBuffer(publicKey.serialize()),
            ])
            signatures.push(serializeBuffer(hostKey.sign(message).serialize()))
        }

        if (packet.data.want_reply) {
            this.sendPacket(new RequestSuccess({ args: Buffer.concat(signatures) }))
        }
    }

    private async handleTCPIPForward(packet: GlobalRequest): Promise<void> {
        try {
            const context = this.parseTCPIPForwardArgs(packet.data.args)
            const controller = { allow: false }
            await this.server.hooker.triggerHook("tcpipForward", context, controller, this)
            if (!controller.allow) {
                if (packet.data.want_reply) this.sendPacket(new RequestFailure({}))
                return
            }

            const listener = net.createServer((socket) => {
                void this.handleForwardedTCPIPConnection(context.bindAddress, socket)
            })
            const actualPort = await new Promise<number>((resolve, reject) => {
                listener.once("error", reject)
                listener.listen(
                    { host: context.bindAddress || undefined, port: context.bindPort },
                    () => {
                        listener.removeListener("error", reject)
                        const address = listener.address()
                        if (!address || typeof address === "string") {
                            reject(new Error("TCP forwarding listener has no IP address"))
                            return
                        }
                        resolve(address.port)
                    },
                )
            })
            listener.on("error", (error) => {
                this.debug(`Remote forwarding listener error:`, error)
            })
            if (!this.isConnected) {
                listener.close()
                return
            }

            const key = this.remoteForwardingKey(context.bindAddress, actualPort)
            this.remoteForwardListeners.set(key, { server: listener })
            listener.once("close", () => {
                if (this.remoteForwardListeners.get(key)?.server === listener) {
                    this.remoteForwardListeners.delete(key)
                }
            })
            if (packet.data.want_reply) {
                this.sendPacket(
                    new RequestSuccess({
                        args:
                            context.bindPort === 0 ? serializeUint32(actualPort) : Buffer.alloc(0),
                    }),
                )
            }
        } catch (error) {
            this.debug(`Could not establish remote forwarding listener:`, error)
            if (packet.data.want_reply) this.sendPacket(new RequestFailure({}))
        }
    }

    private async handleCancelTCPIPForward(packet: GlobalRequest): Promise<void> {
        try {
            const context = this.parseTCPIPForwardArgs(packet.data.args)
            const key = this.remoteForwardingKey(context.bindAddress, context.bindPort)
            const forwarding = this.remoteForwardListeners.get(key)
            if (!forwarding) {
                if (packet.data.want_reply) this.sendPacket(new RequestFailure({}))
                return
            }

            forwarding.server.close()
            this.remoteForwardListeners.delete(key)
            if (packet.data.want_reply)
                this.sendPacket(new RequestSuccess({ args: Buffer.alloc(0) }))
        } catch (error) {
            this.debug(`Could not cancel remote forwarding listener:`, error)
            if (packet.data.want_reply) this.sendPacket(new RequestFailure({}))
        }
    }

    private parseTCPIPForwardArgs(args: Buffer): ServerHookerTCPIPForwardContext {
        const [bindAddress, afterAddress] = readNextBuffer(args)
        const [bindPort, remaining] = readNextUint32(afterAddress)
        assert(remaining.length === 0, "TCP forwarding request has trailing data")
        assert(bindPort <= 65_535, "TCP forwarding port exceeds 65535")
        return Object.freeze({ bindAddress: bindAddress.toString("utf8"), bindPort })
    }

    private async handleStreamLocalForward(packet: GlobalRequest): Promise<void> {
        try {
            const context = this.parseStreamLocalForwardArgs(packet.data.args)
            const controller = { allow: false }
            await this.server.hooker.triggerHook("streamLocalForward", context, controller, this)
            if (!controller.allow || this.remoteStreamLocalListeners.has(context.socketPath)) {
                if (packet.data.want_reply) this.sendPacket(new RequestFailure({}))
                return
            }

            const listener = net.createServer((socket) => {
                void this.handleForwardedStreamLocalConnection(context.socketPath, socket)
            })
            await new Promise<void>((resolve, reject) => {
                listener.once("error", reject)
                listener.listen(context.socketPath, () => {
                    listener.removeListener("error", reject)
                    resolve()
                })
            })
            listener.on("error", (error) => {
                this.debug(`Remote stream-local forwarding listener error:`, error)
            })
            if (!this.isConnected) {
                listener.close()
                return
            }

            this.remoteStreamLocalListeners.set(context.socketPath, { server: listener })
            listener.once("close", () => {
                if (this.remoteStreamLocalListeners.get(context.socketPath)?.server === listener) {
                    this.remoteStreamLocalListeners.delete(context.socketPath)
                }
            })
            if (packet.data.want_reply) {
                this.sendPacket(new RequestSuccess({ args: Buffer.alloc(0) }))
            }
        } catch (error) {
            this.debug(`Could not establish remote stream-local forwarding listener:`, error)
            if (packet.data.want_reply) this.sendPacket(new RequestFailure({}))
        }
    }

    private async handleCancelStreamLocalForward(packet: GlobalRequest): Promise<void> {
        try {
            const context = this.parseStreamLocalForwardArgs(packet.data.args)
            const forwarding = this.remoteStreamLocalListeners.get(context.socketPath)
            if (!forwarding) {
                if (packet.data.want_reply) this.sendPacket(new RequestFailure({}))
                return
            }

            forwarding.server.close()
            this.remoteStreamLocalListeners.delete(context.socketPath)
            if (packet.data.want_reply) {
                this.sendPacket(new RequestSuccess({ args: Buffer.alloc(0) }))
            }
        } catch (error) {
            this.debug(`Could not cancel remote stream-local forwarding listener:`, error)
            if (packet.data.want_reply) this.sendPacket(new RequestFailure({}))
        }
    }

    private parseStreamLocalForwardArgs(args: Buffer): ServerHookerStreamLocalForwardContext {
        const [socketPath, remaining] = readNextBuffer(args)
        assert(remaining.length === 0, "Stream-local forwarding request has trailing data")
        assert(socketPath.length > 0, "Stream-local forwarding path is empty")
        return Object.freeze({ socketPath: socketPath.toString("utf8") })
    }

    private remoteForwardingKey(bindAddress: string, bindPort: number): string {
        return `${bindAddress}\0${bindPort}`
    }

    private async handleForwardedTCPIPConnection(
        bindAddress: string,
        socket: Socket,
    ): Promise<void> {
        const localAddress = socket.localAddress ?? bindAddress
        const localPort = socket.localPort ?? 0
        const channel = new ForwardedTCPIPChannel(this, {
            destinationHost: bindAddress || localAddress,
            destinationPort: localPort,
            sourceHost: socket.remoteAddress ?? "",
            sourcePort: socket.remotePort ?? 0,
        })
        await this.connectForwardedChannel(socket, channel)
    }

    private async handleForwardedStreamLocalConnection(
        socketPath: string,
        socket: Socket,
    ): Promise<void> {
        await this.connectForwardedChannel(
            socket,
            new ForwardedStreamLocalChannel(this, socketPath),
        )
    }

    private async connectForwardedChannel(socket: Socket, channel: Channel): Promise<void> {
        const stream =
            channel instanceof ForwardedTCPIPChannel ||
            channel instanceof ForwardedStreamLocalChannel
                ? channel.stream
                : undefined
        assert(stream, "Forwarded channel has no stream")
        const pendingInput = new PassThrough()
        socket.pipe(pendingInput)
        this.channels.set(channel.localId, channel)
        socket.on("error", () => channel.terminate())
        socket.on("close", () => channel.close())

        try {
            this.sendPacket(channel.getChannelOpenPacket())
            await channel.waitUntilOpen()
            if (socket.destroyed) {
                pendingInput.destroy()
                channel.close()
                return
            }
            stream.on("error", () => socket.destroy())
            stream.on("close", () => socket.destroy())
            pendingInput.pipe(stream)
            stream.pipe(socket)
        } catch (error) {
            this.channels.delete(channel.localId)
            channel.abort(error as Error)
            pendingInput.destroy()
            socket.destroy(error as Error)
        }
    }

    async handleAuthentication() {
        let allowLogin = false
        let authRequest: Packet
        authentication: {
            const userAuthFailure = new UserAuthFailure({
                auth_methods: [
                    SSHAuthenticationMethods.PublicKey,
                    SSHAuthenticationMethods.Password,
                ],
                // TODO: Figure out when and when not to set this to true (if it's even needed?)
                partial_success: false,
            })
            while (true) {
                // TODO: iirc from the spec, one client can batch all their pubkeys at once
                // and the server should be able to handle them. This current implementation
                // does not respect that and waits sequencially.
                this.debug("Waiting for authentication request...")
                ;[authRequest] = (await this.waitEvent("packet")) as [Packet]
                assert(authRequest instanceof UserAuthRequest, "Invalid packet type")

                this.debug(`Received authentication request:`, authRequest)

                switch ((authRequest.data.method.constructor as typeof AuthMethod).method_name) {
                    case SSHAuthenticationMethods.None: {
                        const context: ServerHookerNoneAuthenticationContext = {
                            username: authRequest.data.username,
                        }
                        const controller: ServerHookerNoneAuthenticationController = {
                            allowLogin: false,
                        }

                        await this.server.hooker.triggerHook(
                            "noneAuthentication",
                            Object.freeze(context),
                            controller,
                            this,
                        )

                        if (controller.allowLogin) {
                            allowLogin = true
                            break authentication
                        }

                        this.sendPacket(userAuthFailure)
                        break
                    }
                    case SSHAuthenticationMethods.PublicKey: {
                        const method = authRequest.data.method as PublicKeyAuthMethod

                        const context: ServerHookerPublicKeyAuthenticationContext = {
                            username: authRequest.data.username,
                            publicKey: method.data.publicKey,
                            signature: method.data.signature,
                            signatureMessage: authRequest.serializeForSignature(this),
                        }
                        const controller: ServerHookerPublicKeyAuthenticationController = {
                            // both are independant since you can also allowLogin without checking the signature
                            // would sucks tho !
                            requestSignature: false,
                            allowLogin: false,
                        }

                        await this.server.hooker.triggerHook(
                            "publicKeyAuthentication",
                            Object.freeze(context),
                            controller,
                            this,
                        )

                        if (controller.allowLogin && controller.requestSignature) {
                            console.warn(
                                `[node-ssh] Hook "publicKeyAuthentication" returned "allowLogin" and "requestSignature" to true at the same time. You should not set both to true, but rather the correct one, depending if the request is signed.`,
                            )
                            if (method.data.signature) {
                                controller.requestSignature = false
                            } else {
                                controller.allowLogin = false
                            }
                        }

                        if (controller.allowLogin) {
                            allowLogin = true
                            break authentication
                        } else if (controller.requestSignature) {
                            // ask the client for a signed request
                            this.sendPacket(
                                new UserAuthPKOK({
                                    publicKey: method.data.publicKey,
                                }),
                            )
                            break
                        }

                        this.sendPacket(userAuthFailure)
                        break
                    }
                    case SSHAuthenticationMethods.Password: {
                        const method = authRequest.data.method as PasswordAuthMethod

                        assert(
                            method.data.change_password === false,
                            "Client requested a password change. Not implemented.",
                        )

                        const context: ServerHookerPasswordAuthenticationContext = {
                            username: authRequest.data.username,
                            password: method.data.password,
                        }
                        const controller: ServerHookerPasswordAuthenticationController = {
                            allowLogin: false,
                        }

                        await this.server.hooker.triggerHook(
                            "passwordAuthentication",
                            Object.freeze(context),
                            controller,
                            this,
                        )

                        if (controller.allowLogin) {
                            allowLogin = true
                            break authentication
                        }

                        this.sendPacket(userAuthFailure)
                        break
                    }
                }
            }
        }

        // redo the assert for type checking, otherwise it should
        // never throw.
        assert(authRequest instanceof UserAuthRequest, "Invalid packet type")
        this.credentials = authRequest

        if (allowLogin) {
            this.sendPacket(new UserAuthSuccess({}))
            this.hasAuthenticated = true
        } else {
            throw new DisconnectError(
                DisconnectReason.SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE,
                "No auth methods were successful.",
            )
        }
    }

    waitEvent<event extends keyof ServerClientEvents>(
        event: event,
    ): Promise<ServerClientEvents[event]> {
        return new Promise((resolve, reject) => {
            const onError = (error: Error) => {
                cleanup()
                reject(error)
            }
            const handler = (...values: ServerClientEvents[event]) => {
                resolve(values)
                cleanup()
            }
            const cleanup = () => {
                // @ts-expect-error the function definition makes sure this is respected
                this.off(event, handler)
                this.off("error", onError)
            }
            // @ts-expect-error the function definition makes sure this is respected
            this.once(event, handler)
            this.once("error", onError)
        })
    }

    sendPacket(packet: Packet): number {
        this.debug("Sending packet:", packet)
        const encoded = this.packetEncoder.encode(packet.serialize())
        this.socket!.write(encoded.data)
        return encoded.sequenceNumber
    }

    debug(...message: unknown[]): void {
        this.server.debug(`[${this.connectionId}]`, ...message)
    }

    private scheduleMessageProcessing(message: Buffer): void {
        queueMicrotask(() => {
            try {
                this.onMessage(message)
            } catch (error) {
                this.emit("error", error as Error)
                this.terminate()
            }
        })
    }

    private resumePacketProcessing(): void {
        this.packetProcessingPaused = false
        if (this.packetDecoder.bufferedLength > 0) {
            this.scheduleMessageProcessing(Buffer.alloc(0))
        }
    }

    onMessage(message: Buffer): void {
        if (this.state === SocketState.Closed) {
            // wait for server to accept connection
            this.buffering = Buffer.concat([this.buffering, message])
            return
        }
        message = Buffer.concat([this.buffering, message])
        this.buffering = Buffer.alloc(0)
        if (!this.clientProtocolVersion) {
            const result = this.identificationParser.push(message)
            if (!result.version || !result.identification) return

            this.emit("message", result.identification)
            this.clientProtocolVersion = result.version
            this.emit("clientProtocolVersion", result.version)
            this.debug("Client protocol version:", result.version)

            if (result.remainder.length > 0) {
                this.scheduleMessageProcessing(result.remainder)
            }
            return
        }

        this.packetDecoder.push(message)
        if (this.packetProcessingPaused) return

        const decoded = this.packetDecoder.read()
        if (!decoded) {
            if (this.packetDecoder.bufferedLength > 0) {
                this.debug("Partial message, buffering...")
            }
            return
        }

        const { payload } = decoded
        this.emit("message", decoded.data)

        const packetType = payload[0] as PacketType
        this.debug("Receiving packet:", packetType)

        if (!(packetType in PacketTypeToName)) {
            throw new Error("Invalid packet type: " + packetType)
        }
        const packetName = PacketTypeToName[packetType]
        if (!(packetName in packets)) {
            throw new Error("Not implemented: " + packetName)
        }
        const packet = packets[packetName as keyof typeof packets]

        const p = packet.parse(payload)
        this.emit("packet", p)
        this.debug("Parsing packet:", p)

        switch (packet.type) {
            case PacketNameToType.SSH_MSG_DISCONNECT: {
                const disconnect = p as Disconnect
                this.debug(
                    "Client disconnected:",
                    DisconnectReason[disconnect.data.reason_code],
                    disconnect.data.description,
                    disconnect.data.language_tag,
                )
                // TODO: Handle disconnect
                break
            }

            case PacketNameToType.SSH_MSG_IGNORE:
                this.debug(`Received Ignore packet. Ignoring.`)
                break

            case PacketNameToType.SSH_MSG_DEBUG: {
                const debug = p as Debug
                this.debug(`Received debug packet:`, [debug.data.message])
                break
            }

            case PacketNameToType.SSH_MSG_KEXINIT:
                // handle key exchange
                this.emit("clientKexInit", p as KexInit, payload)
                break

            case PacketNameToType.SSH_MSG_KEXDH_INIT:
                this.packetProcessingPaused = true
                break

            case PacketNameToType.SSH_MSG_NEWKEYS:
                this.hasReceivedNewKeys = true
                this.packetDecoder.setProtection({
                    cipher: this.clientEncryption!,
                    mac: this.clientMac!,
                    blockSize: this.clientEncryptionAlgorithm!.block_size,
                    macLength: this.clientMacAlgorithm!.digest_length,
                })
                this.emit("clientNewKeys")
                break

            case PacketNameToType.SSH_MSG_CHANNEL_OPEN:
                this.emit("channelOpenRequest", p as ChannelOpen)
                break
            case PacketNameToType.SSH_MSG_CHANNEL_OPEN_CONFIRMATION: {
                const confirmation = p as ChannelOpenConfirmation
                const channel = this.channels.get(confirmation.data.recipient_channel_id)
                if (!channel) {
                    throw new DisconnectError(
                        DisconnectReason.SSH_DISCONNECT_PROTOCOL_ERROR,
                        `Received confirmation for unknown SSH channel ${confirmation.data.recipient_channel_id}`,
                    )
                }
                channel.confirmOpen(confirmation)
                break
            }
            case PacketNameToType.SSH_MSG_CHANNEL_OPEN_FAILURE: {
                const failure = p as ChannelOpenFailure
                const channel = this.channels.get(failure.data.recipient_channel_id)
                if (!channel) {
                    throw new DisconnectError(
                        DisconnectReason.SSH_DISCONNECT_PROTOCOL_ERROR,
                        `Received failure for unknown SSH channel ${failure.data.recipient_channel_id}`,
                    )
                }
                channel.failOpen(failure)
                this.channels.delete(channel.localId)
                break
            }
            case PacketNameToType.SSH_MSG_CHANNEL_REQUEST:
                this.emit("channelRequest", p as ChannelRequest)
                break
            case PacketNameToType.SSH_MSG_CHANNEL_WINDOW_ADJUST: {
                const adjust = p as ChannelWindowAdjust
                this.queueChannelAction(adjust.data.recipient_channel_id, (channel) => {
                    channel.receiveWindowAdjust(adjust.data.bytes_to_add)
                })
                break
            }
            case PacketNameToType.SSH_MSG_CHANNEL_DATA: {
                const data = p as ChannelData
                this.emit("channelData", data)
                this.queueChannelAction(data.data.recipient_channel_id, (channel) => {
                    channel.receiveData(data.data.data)
                })
                break
            }
            case PacketNameToType.SSH_MSG_CHANNEL_EXTENDED_DATA: {
                const data = p as ChannelExtendedData
                this.queueChannelAction(data.data.recipient_channel_id, (channel) => {
                    channel.receiveExtendedData(data.data.data_type_code, data.data.data)
                })
                break
            }
            case PacketNameToType.SSH_MSG_CHANNEL_EOF: {
                const eof = p as ChannelEOF
                this.queueChannelAction(eof.data.recipient_channel_id, (channel) => {
                    channel.receiveEOF()
                })
                break
            }
            case PacketNameToType.SSH_MSG_CHANNEL_CLOSE: {
                const close = p as ChannelClose
                this.queueChannelAction(close.data.recipient_channel_id, (channel) => {
                    channel.receiveClose()
                    if (channel.isFullyClosed) this.channels.delete(channel.localId)
                })
                break
            }
        }

        if (this.packetDecoder.bufferedLength > 0) {
            this.scheduleMessageProcessing(Buffer.alloc(0))
        }
    }

    private queueChannelAction(localId: number, action: (channel: Channel) => void): void {
        void this.queue
            .queueAction(`channel:${localId}`, async () => {
                const channel = this.channels.get(localId)
                if (!channel) {
                    throw new DisconnectError(
                        DisconnectReason.SSH_DISCONNECT_PROTOCOL_ERROR,
                        `Received a packet for unknown SSH channel ${localId}`,
                    )
                }
                action(channel)
            })
            .catch((error: Error) => {
                this.emit("error", error)
                this.terminate()
            })
    }
}
