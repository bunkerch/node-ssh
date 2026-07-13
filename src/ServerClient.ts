import net, { Socket } from "node:net"
import { PassThrough } from "node:stream"
import Server, {
    ServerHookerChannelOpenRequestController,
    ServerHookerNoneAuthenticationContext,
    ServerHookerNoneAuthenticationController,
    ServerHookerPasswordAuthenticationContext,
    ServerHookerPasswordAuthenticationController,
    ServerHookerKeyboardInteractiveAuthenticationContext,
    ServerHookerKeyboardInteractiveAuthenticationController,
    ServerAuthenticationContinuation,
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
    createInboundPacketProtection,
    createOutboundPacketProtection,
    createPacketCompressor,
    createPacketDecompressor,
    describeNegotiatedAlgorithms,
    host_key_algorithms,
    type CompressionAlgorithm,
    type HostKeyAlgorithm,
} from "./algorithms.js"
import type { NegotiatedAlgorithms } from "./AlgorithmOptions.js"
import PublicKey from "./utils/PublicKey.js"
import KexDHReply from "./packets/KexDHReply.js"
import assert from "node:assert"
import Packet, { packets } from "./packet.js"
import Disconnect, { DisconnectError, DisconnectReason } from "./packets/Disconnect.js"
import KexDHInit from "./packets/KexDHInit.js"
import KexDHGexGroup from "./packets/KexDHGexGroup.js"
import KexDHGexInit from "./packets/KexDHGexInit.js"
import KexDHGexReply from "./packets/KexDHGexReply.js"
import KexDHGexRequest from "./packets/KexDHGexRequest.js"
import KexDHGexRequestOld from "./packets/KexDHGexRequestOld.js"
import { DiffieHellmanGroupExchange } from "./algorithms/kex/diffie-hellman-group-exchange.js"
import NewKeys from "./packets/NewKeys.js"
import ExtInfo from "./packets/ExtInfo.js"
import { KeyExchangeError } from "./algorithms/kex/key-exchange.js"
import ServiceRequest from "./packets/ServiceRequest.js"
import ServiceAccept from "./packets/ServiceAccept.js"
import UserAuthRequest from "./packets/UserAuthRequest.js"
import AuthMethod from "./auth/AuthMethod.js"
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
import ForwardedAgentChannel from "./channels/ForwardedAgentChannel.js"
import ForwardedX11Channel from "./channels/ForwardedX11Channel.js"
import KeyboardInteractiveAuthMethod from "./auth/keyboard-interactive.js"
import UserAuthInfoRequest from "./packets/UserAuthInfoRequest.js"
import UserAuthInfoResponse from "./packets/UserAuthInfoResponse.js"
import UserAuthPasswordChangeRequest from "./packets/UserAuthPasswordChangeRequest.js"
import UserAuthBanner from "./packets/UserAuthBanner.js"

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
    clientKexDHInit: [kexDHInit: KexDHInit]
    clientKexDHGexRequest: [request: KexDHGexRequest | KexDHGexRequestOld]
    clientKexDHGexInit: [init: KexDHGexInit]
    clientNewKeys: []
    serverNewKeys: []
    handshake: [negotiated: Readonly<NegotiatedAlgorithms>]
    rekey: []

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
            this.x11Forwardings.clear()
            this.agentForwardingEnabled = false
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
    private keyExchangeInProgress = false
    private readonly packetsQueuedDuringKeyExchange: Packet[] = []

    clientProtocolVersion?: ProtocolVersionExchange
    clientKexDHInit?: KexDHInit
    // TODO: Assess if these should be private properties
    clientKexInit?: KexInit
    serverKexInit?: KexInit
    kexAlgorithm?: KexAlgorithm
    hostKeyAlgorithm?: HostKeyAlgorithm
    clientEncryptionAlgorithm?: typeof EncryptionAlgorithm
    serverEncryptionAlgorithm?: typeof EncryptionAlgorithm
    clientEncryption?: EncryptionAlgorithm
    serverEncryption?: EncryptionAlgorithm
    clientMacAlgorithm?: typeof MACAlgorithm
    serverMacAlgorithm?: typeof MACAlgorithm
    clientMac?: MACAlgorithm
    serverMac?: MACAlgorithm
    clientCompressionAlgorithm?: CompressionAlgorithm
    serverCompressionAlgorithm?: CompressionAlgorithm

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
    private readonly x11Forwardings = new Map<number, { single: boolean }>()
    agentForwardingEnabled = false
    private noMoreSessionsRequested = false

    get noMoreSessions(): boolean {
        return this.noMoreSessionsRequested
    }

    state = SocketState.Closed
    get isConnected(): boolean {
        return this.state === SocketState.Connected
    }

    async openssh_forwardAgent(): Promise<ForwardedAgentChannel> {
        if (!this.isConnected) throw new Error("SSH connection is not open")
        if (!this.agentForwardingEnabled) {
            throw new Error("The SSH client has not authorized agent forwarding")
        }
        const channel = new ForwardedAgentChannel(this)
        this.channels.set(channel.localId, channel)
        try {
            this.sendPacket(channel.getChannelOpenPacket())
            await channel.waitUntilOpen()
            return channel
        } catch (error) {
            this.channels.delete(channel.localId)
            channel.abort(error as Error)
            throw error
        }
    }

    registerX11Forwarding(sessionId: number, single: boolean): void {
        this.x11Forwardings.set(sessionId, { single })
    }

    unregisterX11Forwarding(sessionId: number): void {
        this.x11Forwardings.delete(sessionId)
    }

    async x11(originatorAddress: string, originatorPort: number): Promise<ForwardedX11Channel> {
        if (!this.isConnected) throw new Error("SSH connection is not open")
        if (
            !Number.isSafeInteger(originatorPort) ||
            originatorPort < 0 ||
            originatorPort > 65_535
        ) {
            throw new RangeError("X11 originator port must be between 0 and 65535")
        }
        const authorizations = [...this.x11Forwardings.entries()]
        const authorization =
            authorizations.find(([, candidate]) => !candidate.single) ?? authorizations[0]
        if (!authorization) throw new Error("The SSH client has not authorized X11 forwarding")
        if (authorization[1].single) this.x11Forwardings.delete(authorization[0])

        const channel = new ForwardedX11Channel(this, { originatorAddress, originatorPort })
        this.channels.set(channel.localId, channel)
        try {
            this.sendPacket(channel.getChannelOpenPacket())
            await channel.waitUntilOpen()
            return channel
        } catch (error) {
            this.channels.delete(channel.localId)
            channel.abort(error as Error)
            throw error
        }
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

    setNoDelay(noDelay = true): this {
        this.socket.setNoDelay(noDelay)
        return this
    }

    rekey(): Promise<void>
    rekey(callback: (error?: Error) => void): this
    rekey(callback?: (error?: Error) => void): Promise<void> | this {
        if (!this.isConnected || !this.hasAuthenticated) {
            const error = new Error("Cannot rekey before the SSH connection is ready")
            if (!callback) return Promise.reject(error)
            queueMicrotask(() => callback(error))
            return this
        }
        if (this.keyExchangeInProgress) {
            const error = new Error("SSH key exchange is already in progress")
            if (!callback) return Promise.reject(error)
            queueMicrotask(() => callback(error))
            return this
        }
        const operation = this.performKeyExchange().catch((error: unknown) => {
            this.terminate()
            throw error
        })
        if (!callback) return operation
        operation.then(
            () => callback(),
            (error: Error) => callback(error),
        )
        return this
    }

    private createKexInit(): KexInit {
        return new KexInit({
            cookie: crypto.getRandomValues(Buffer.alloc(16)),
            kex_algorithms: [
                ...this.server.algorithmOffer.kex,
                ...(this.sessionID === undefined ? ["ext-info-s"] : []),
            ],
            server_host_key_algorithms: [
                ...this.server.algorithmOffer.serverHostKey.filter((name) => {
                    const algorithm = host_key_algorithms.get(name)
                    return this.server.options.hostKeys.some(
                        (key) => key.data.alg === algorithm?.key_format,
                    )
                }),
            ],
            encryption_algorithms_client_to_server: [...this.server.algorithmOffer.cipher],
            encryption_algorithms_server_to_client: [...this.server.algorithmOffer.cipher],
            mac_algorithms_client_to_server: [...this.server.algorithmOffer.hmac],
            mac_algorithms_server_to_client: [...this.server.algorithmOffer.hmac],
            compression_algorithms_client_to_server: [...this.server.algorithmOffer.compress],
            compression_algorithms_server_to_client: [...this.server.algorithmOffer.compress],
            languages_client_to_server: [],
            languages_server_to_client: [],
            first_kex_packet_follows: false,
        })
    }

    private async performKeyExchange(
        received?: readonly [packet: KexInit, payload: Buffer],
    ): Promise<void> {
        if (this.keyExchangeInProgress) {
            throw new Error("SSH key exchange is already in progress")
        }
        const isRekey = this.sessionID !== undefined
        this.keyExchangeInProgress = true
        this.hasReceivedNewKeys = false
        this.hasSentNewKeys = false

        try {
            this.serverKexInit = this.createKexInit()
            this.sendPacket(this.serverKexInit)
            const [clientKexInit, clientKexInitBuffer] =
                received ?? (await this.waitEvent("clientKexInit"))
            this.clientKexInit = clientKexInit
            chooseAlgorithms(this)

            const kexAlgorithm = this.kexAlgorithm
            assert(kexAlgorithm, "No key exchange algorithm was negotiated")
            if (kexAlgorithm instanceof DiffieHellmanGroupExchange) {
                const [request] = await this.waitEvent("clientKexDHGexRequest")
                if (request instanceof KexDHGexRequestOld) {
                    kexAlgorithm.setOldRequest(request.data.preferred)
                } else {
                    kexAlgorithm.setRequest(request.data)
                }
                const group = kexAlgorithm.selectServerGroup()
                kexAlgorithm.generateKeyPair()
                this.sendPacket(new KexDHGexGroup(group))
                const [init] = await this.waitEvent("clientKexDHGexInit")
                kexAlgorithm.computeSharedSecret(init.data.e)
            } else {
                const [clientKexDHInit] = await this.waitEvent("clientKexDHInit")
                this.clientKexDHInit = clientKexDHInit
                kexAlgorithm.generateKeyPair()
                kexAlgorithm.computeSharedSecret(clientKexDHInit.data.e)
            }

            const hostKey = this.server.options.hostKeys.find(
                (key) => key.data.alg === this.hostKeyAlgorithm!.key_format,
            )
            assert(hostKey, "No host key found for the negotiated algorithm")
            const publicKey = hostKey.data.publicKey.serialize()
            const h = kexAlgorithm.computeHServer(this, clientKexInitBuffer, publicKey)
            const reply = {
                K_S: publicKey,
                f: kexAlgorithm.getPublicKey(),
                H_sig: hostKey.sign(h, this.hostKeyAlgorithm!.signature_algorithm).serialize(),
            }
            this.sendPacket(
                kexAlgorithm instanceof DiffieHellmanGroupExchange
                    ? new KexDHGexReply(reply)
                    : new KexDHReply({
                          ...reply,
                          encoding: kexAlgorithm.exchangeValueEncoding,
                      }),
            )

            this.H = h
            this.sessionID ??= h
            kexAlgorithm.deriveKeysClient(this)
            this.clientEncryption = this.clientEncryptionAlgorithm!.instantiate(
                this.encryptionKeyClientToServer!,
                this.ivClientToServer!,
            )
            this.serverEncryption = this.serverEncryptionAlgorithm!.instantiate(
                this.encryptionKeyServerToClient!,
                this.ivServerToClient!,
            )
            this.clientMac = this.clientMacAlgorithm?.instantiate(this.integrityKeyClientToServer!)
            this.serverMac = this.serverMacAlgorithm?.instantiate(this.integrityKeyServerToClient!)
            this.resumePacketProcessing()

            if (!this.hasReceivedNewKeys) await this.waitEvent("clientNewKeys")
            this.sendPacket(new NewKeys({}))
            this.hasSentNewKeys = true
            this.packetEncoder.setProtection(
                createOutboundPacketProtection(
                    this.serverEncryptionAlgorithm!,
                    this.serverEncryption,
                    this.serverMacAlgorithm,
                    this.serverMac,
                ),
            )
            this.installOutboundCompression()
            if (!isRekey && clientKexInit.data.kex_algorithms.includes("ext-info-c")) {
                this.sendPacket(
                    new ExtInfo({
                        extensions: [
                            {
                                name: "server-sig-algs",
                                value: Buffer.from(
                                    [...host_key_algorithms.keys()].join(","),
                                    "ascii",
                                ),
                            },
                        ],
                    }),
                )
            }
            while (this.packetsQueuedDuringKeyExchange.length > 0) {
                this.writePacket(this.packetsQueuedDuringKeyExchange.shift()!)
            }
            this.emit("serverNewKeys")
            this.emit("handshake", describeNegotiatedAlgorithms(this))
            if (isRekey) this.emit("rekey")
        } catch (error) {
            if (error instanceof KeyExchangeError && this.socket.writable) {
                this.sendPacket(
                    new Disconnect({
                        reason_code: DisconnectReason.SSH_DISCONNECT_KEY_EXCHANGE_FAILED,
                        description: error.message,
                        language_tag: "",
                    }),
                )
                this.socket.end()
            }
            throw error
        } finally {
            this.keyExchangeInProgress = false
        }
    }

    async connect(): Promise<void> {
        this.state = SocketState.Connecting
        const clientProtocolVersionPromise = this.waitEvent("clientProtocolVersion")

        this.debug(`Socket connected, sending protocol version exchange packet...`)
        this.socket.write(
            this.server.options.greeting + this.server.options.protocolVersionExchange.toString(),
        )
        if (this.buffering.length > 0) {
            this.onMessage(Buffer.alloc(0))
        }

        const [clientProtocolVersion] = await clientProtocolVersionPromise
        this.debug("Client protocol version:", clientProtocolVersion)

        await this.performKeyExchange()

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

        if (this.server.options.banner) {
            this.sendPacket(
                new UserAuthBanner({
                    message: this.server.options.banner,
                    languageTag: "",
                }),
            )
        }

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
                if (this.noMoreSessionsRequested && packet.data.channel_type === "session") {
                    throw new ChannelOpenError(
                        ChannelOpenFailureReasonCodes.SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
                        packet.data.sender_channel_id,
                        "Additional SSH session channels have been disabled",
                    )
                }
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
            case "no-more-sessions@openssh.com":
                this.handleNoMoreSessions(packet)
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

    private handleNoMoreSessions(packet: GlobalRequest): void {
        if (packet.data.args.length !== 0) {
            if (packet.data.want_reply) this.sendPacket(new RequestFailure({}))
            return
        }
        this.noMoreSessionsRequested = true
        if (packet.data.want_reply) this.sendPacket(new RequestSuccess({ args: Buffer.alloc(0) }))
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
        let authRequest: UserAuthRequest | undefined
        let pendingAuthRequest: UserAuthRequest | undefined
        const authenticationMethods: SSHAuthenticationMethods[] = []
        if (this.server.hooker.hasHooks("publicKeyAuthentication")) {
            authenticationMethods.push(SSHAuthenticationMethods.PublicKey)
        }
        if (this.server.hooker.hasHooks("passwordAuthentication")) {
            authenticationMethods.push(SSHAuthenticationMethods.Password)
        }
        if (this.server.hooker.hasHooks("keyboardInteractiveAuthentication")) {
            authenticationMethods.push(SSHAuthenticationMethods.KeyboardInteractive)
        }
        const userAuthFailure = new UserAuthFailure({
            auth_methods: authenticationMethods,
            partial_success: false,
        })
        const sendAuthenticationFailure = (
            continuation: ServerAuthenticationContinuation = {},
            completedMethod?: SSHAuthenticationMethods,
        ): void => {
            const requestedMethods =
                continuation.authenticationMethods ??
                (continuation.partialSuccess
                    ? authenticationMethods.filter((method) => method !== completedMethod)
                    : authenticationMethods)
            const methods = [
                ...new Set(
                    requestedMethods.filter(
                        (method) =>
                            method !== SSHAuthenticationMethods.None &&
                            UserAuthRequest.auth_methods.has(method),
                    ),
                ),
            ]
            this.sendPacket(
                new UserAuthFailure({
                    auth_methods: methods,
                    partial_success: continuation.partialSuccess === true,
                }),
            )
        }

        authentication: {
            while (true) {
                this.debug("Waiting for authentication request...")
                if (pendingAuthRequest) {
                    authRequest = pendingAuthRequest
                    pendingAuthRequest = undefined
                } else {
                    const [packet] = await this.waitEvent("packet")
                    assert(packet instanceof UserAuthRequest, "Invalid packet type")
                    authRequest = packet
                }

                this.debug(`Received authentication request:`, this.packetForDebug(authRequest))

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
                            algorithm: method.data.algorithm!,
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
                                    algorithm: method.data.algorithm,
                                }),
                            )
                            break
                        }

                        sendAuthenticationFailure(controller, SSHAuthenticationMethods.PublicKey)
                        break
                    }
                    case SSHAuthenticationMethods.Password: {
                        const method = authRequest.data.method as PasswordAuthMethod

                        const context: ServerHookerPasswordAuthenticationContext = {
                            username: authRequest.data.username,
                            password: method.data.password,
                            newPassword: method.data.newPassword,
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

                        if (controller.partialSuccess) {
                            sendAuthenticationFailure(controller, SSHAuthenticationMethods.Password)
                            break
                        }

                        if (controller.requestPasswordChange) {
                            this.sendPacket(
                                new UserAuthPasswordChangeRequest({
                                    prompt: controller.requestPasswordChange.prompt,
                                    languageTag: controller.requestPasswordChange.languageTag ?? "",
                                }),
                            )
                            break
                        }

                        sendAuthenticationFailure(controller)
                        break
                    }
                    case SSHAuthenticationMethods.KeyboardInteractive: {
                        const method = authRequest.data.method as KeyboardInteractiveAuthMethod
                        let responses: readonly string[] | undefined
                        let round = 0

                        keyboardInteractive: while (true) {
                            const context: ServerHookerKeyboardInteractiveAuthenticationContext = {
                                username: authRequest.data.username,
                                languageTag: method.data.languageTag,
                                submethods: method.data.submethods,
                                responses,
                                round,
                            }
                            const controller: ServerHookerKeyboardInteractiveAuthenticationController =
                                {
                                    allowLogin: false,
                                }
                            await this.server.hooker.triggerHook(
                                "keyboardInteractiveAuthentication",
                                Object.freeze(context),
                                controller,
                                this,
                            )

                            if (controller.allowLogin) {
                                allowLogin = true
                                break authentication
                            }
                            if (controller.partialSuccess) {
                                sendAuthenticationFailure(
                                    controller,
                                    SSHAuthenticationMethods.KeyboardInteractive,
                                )
                                break keyboardInteractive
                            }
                            if (controller.prompts === undefined) {
                                sendAuthenticationFailure(controller)
                                break keyboardInteractive
                            }

                            const request = new UserAuthInfoRequest({
                                name: controller.name ?? "",
                                instruction: controller.instruction ?? "",
                                languageTag: controller.languageTag ?? "",
                                prompts: controller.prompts,
                            })
                            this.sendPacket(request)
                            const [packet] = await this.waitEvent("packet")
                            if (packet instanceof UserAuthRequest) {
                                pendingAuthRequest = packet
                                break keyboardInteractive
                            }
                            assert(packet instanceof UserAuthInfoResponse, "Invalid packet type")
                            if (packet.data.responses.length !== request.data.prompts.length) {
                                sendAuthenticationFailure()
                                break keyboardInteractive
                            }
                            responses = Object.freeze([...packet.data.responses])
                            round++
                        }
                        break
                    }
                    default:
                        sendAuthenticationFailure()
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
            this.enableDelayedCompression()
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
        const type = (packet.constructor as typeof Packet).type
        if (
            this.keyExchangeInProgress &&
            (type >= 50 ||
                type === PacketNameToType.SSH_MSG_SERVICE_REQUEST ||
                type === PacketNameToType.SSH_MSG_SERVICE_ACCEPT)
        ) {
            this.packetsQueuedDuringKeyExchange.push(packet)
            return -1
        }
        return this.writePacket(packet)
    }

    private writePacket(packet: Packet): number {
        this.debug("Sending packet:", this.packetForDebug(packet))
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

    private installOutboundCompression(): void {
        assert(this.serverCompressionAlgorithm, "Server compression algorithm not selected")
        this.packetEncoder.setCompression(
            createPacketCompressor(this.serverCompressionAlgorithm, this.hasAuthenticated),
        )
    }

    private installInboundCompression(): void {
        assert(this.clientCompressionAlgorithm, "Client compression algorithm not selected")
        this.packetDecoder.setCompression(
            createPacketDecompressor(this.clientCompressionAlgorithm, this.hasAuthenticated),
        )
    }

    private enableDelayedCompression(): void {
        if (this.serverCompressionAlgorithm?.delayed) this.installOutboundCompression()
        if (this.clientCompressionAlgorithm?.delayed) this.installInboundCompression()
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
        const packet =
            packetType === PacketNameToType.SSH_MSG_KEXDH_INIT &&
            this.kexAlgorithm instanceof DiffieHellmanGroupExchange
                ? KexDHGexRequestOld
                : packets[packetName as keyof typeof packets]

        const p = packet.parse(payload)
        this.emit("packet", p)
        this.debug("Parsing packet:", this.packetForDebug(p))

        switch (packet.type) {
            case PacketNameToType.SSH_MSG_DISCONNECT: {
                const disconnect = p as Disconnect
                this.debug(
                    "Client disconnected:",
                    DisconnectReason[disconnect.data.reason_code],
                    disconnect.data.description,
                    disconnect.data.language_tag,
                )
                this.terminate()
                return
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
                if (this.state === SocketState.Connected && !this.keyExchangeInProgress) {
                    void this.performKeyExchange([p as KexInit, payload]).catch((error: Error) => {
                        this.emit("error", error)
                        this.terminate()
                    })
                }
                this.emit("clientKexInit", p as KexInit, payload)
                break

            case PacketNameToType.SSH_MSG_KEXDH_INIT:
                if (p instanceof KexDHGexRequestOld) {
                    this.emit("clientKexDHGexRequest", p)
                } else {
                    this.emit("clientKexDHInit", p as KexDHInit)
                    this.packetProcessingPaused = true
                }
                break

            case PacketNameToType.SSH_MSG_KEX_DH_GEX_REQUEST:
                if (!(this.kexAlgorithm instanceof DiffieHellmanGroupExchange)) {
                    throw new Error("Received a group request for another key exchange")
                }
                this.emit("clientKexDHGexRequest", p as KexDHGexRequest)
                break

            case PacketNameToType.SSH_MSG_KEX_DH_GEX_INIT:
                if (!(this.kexAlgorithm instanceof DiffieHellmanGroupExchange)) {
                    throw new Error("Received a group-exchange init for another key exchange")
                }
                this.emit("clientKexDHGexInit", p as KexDHGexInit)
                this.packetProcessingPaused = true
                break

            case PacketNameToType.SSH_MSG_NEWKEYS:
                this.hasReceivedNewKeys = true
                this.packetDecoder.setProtection(
                    createInboundPacketProtection(
                        this.clientEncryptionAlgorithm!,
                        this.clientEncryption!,
                        this.clientMacAlgorithm,
                        this.clientMac,
                    ),
                )
                this.installInboundCompression()
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

    private packetForDebug(packet: Packet): unknown {
        if (packet instanceof UserAuthRequest) {
            return {
                type: "SSH_MSG_USERAUTH_REQUEST",
                username: packet.data.username,
                serviceName: packet.data.service_name,
                method: packet.data.method.method_name,
            }
        }
        if (packet instanceof UserAuthInfoResponse) {
            return {
                type: "SSH_MSG_USERAUTH_INFO_RESPONSE",
                responseCount: packet.data.responses.length,
                responses: "<redacted>",
            }
        }
        return packet
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
