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
    ServerHookerHostbasedAuthenticationContext,
    ServerHookerHostbasedAuthenticationController,
    ServerHookerGlobalRequestContext,
    ServerHookerGlobalRequestController,
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
import PublicKey, { SSHCertificatePublicKey } from "./utils/PublicKey.js"
import KexDHReply from "./packets/KexDHReply.js"
import assert from "node:assert"
import Packet, { packets } from "./packet.js"
import Disconnect, {
    DisconnectError,
    DisconnectReason,
    PeerDisconnectError,
    peerDisconnectInfo,
    type PeerDisconnectInfo,
} from "./packets/Disconnect.js"
import KexDHInit from "./packets/KexDHInit.js"
import KexDHGexGroup from "./packets/KexDHGexGroup.js"
import KexDHGexInit from "./packets/KexDHGexInit.js"
import KexDHGexReply from "./packets/KexDHGexReply.js"
import KexDHGexRequest from "./packets/KexDHGexRequest.js"
import KexDHGexRequestOld from "./packets/KexDHGexRequestOld.js"
import { DiffieHellmanGroupExchange } from "./algorithms/kex/diffie-hellman-group-exchange.js"
import NewKeys from "./packets/NewKeys.js"
import ExtInfo, { copySSHExtensions, type SSHExtension } from "./packets/ExtInfo.js"
import Ping from "./packets/Ping.js"
import Pong from "./packets/Pong.js"
import { KeyExchangeError } from "./algorithms/kex/key-exchange.js"
import RSA2048SHA256 from "./algorithms/kex/rsa2048-sha256.js"
import KexRSAPublicKey from "./packets/KexRSAPublicKey.js"
import KexRSASecret from "./packets/KexRSASecret.js"
import KexRSADone from "./packets/KexRSADone.js"
import ServiceRequest from "./packets/ServiceRequest.js"
import ServiceAccept from "./packets/ServiceAccept.js"
import UserAuthRequest from "./packets/UserAuthRequest.js"
import AuthMethod from "./auth/AuthMethod.js"
import UserAuthFailure from "./packets/UserAuthFailure.js"
import PublicKeyAuthMethod from "./auth/publickey.js"
import { HostboundPublicKeyAuthMethod } from "./auth/publickey.js"
import UserAuthPKOK from "./packets/UserAuthPKOK.js"
import PasswordAuthMethod from "./auth/password.js"
import UserAuthSuccess from "./packets/UserAuthSuccess.js"
import { randomBase36 } from "./utils/base36.js"
import Debug, { protocolDebugMessage, type ProtocolDebugMessage } from "./packets/Debug.js"
import Ignore from "./packets/Ignore.js"
import Unimplemented from "./packets/Unimplemented.js"
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
import ChannelSuccess from "./packets/ChannelSuccess.js"
import ChannelFailure from "./packets/ChannelFailure.js"
import IdentificationParser from "./IdentificationParser.js"
import { BinaryPacketDecoder, BinaryPacketEncoder } from "./BinaryPacket.js"
import {
    isStrictKeyExchangePacket,
    negotiatesStrictKeyExchange,
    STRICT_KEX_SERVER_MARKERS,
} from "./StrictKeyExchange.js"
import ForwardedTCPIPChannel from "./channels/ForwardedTCPIPChannel.js"
import ForwardedStreamLocalChannel from "./channels/ForwardedStreamLocalChannel.js"
import ForwardedAgentChannel from "./channels/ForwardedAgentChannel.js"
import ForwardedX11Channel from "./channels/ForwardedX11Channel.js"
import KeyboardInteractiveAuthMethod from "./auth/keyboard-interactive.js"
import HostbasedAuthMethod from "./auth/hostbased.js"
import UserAuthInfoRequest from "./packets/UserAuthInfoRequest.js"
import UserAuthInfoResponse from "./packets/UserAuthInfoResponse.js"
import UserAuthPasswordChangeRequest from "./packets/UserAuthPasswordChangeRequest.js"
import UserAuthBanner from "./packets/UserAuthBanner.js"
import { createHostKeysProofMessage } from "./utils/HostKeysProof.js"

interface RemoteForwardListener {
    server: net.Server
}

export type ServerForwardCallback<T extends Channel> = (
    error: Error | undefined,
    channel?: T,
) => void
export type ServerGlobalRequestCallback = (error: Error | undefined, response?: Buffer) => void

export class ServerGlobalRequestError extends Error {
    name = "ServerGlobalRequestError"
}

interface PendingGlobalRequest {
    name: string
    resolve: (response: Buffer) => void
    reject: (error: Error) => void
}

export interface ServerClientEvents {
    error: [error: Error]
    close: []
    /** Terminal disconnect received from the peer. */
    disconnect: [info: Readonly<PeerDisconnectInfo>]
    /** Human-readable transport diagnostic sent by the peer. */
    protocolDebug: [info: Readonly<ProtocolDebugMessage>]
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
    clientKexRSASecret: [secret: KexRSASecret]
    clientNewKeys: []
    serverNewKeys: []
    handshake: [negotiated: Readonly<NegotiatedAlgorithms>]
    rekey: []
    /** Complete client extension set received at the RFC 8308 opportunity. */
    clientExtensions: [extensions: readonly Readonly<SSHExtension>[]]

    channelOpenRequest: [packet: ChannelOpen]
    channelRequest: [packet: ChannelRequest]
    channelData: [packet: ChannelData]
    channel: [channel: Channel]
}

export default class ServerClient extends EventEmitter<ServerClientEvents> {
    private socket: Socket
    connectionId: string
    peerDisconnect?: Readonly<PeerDisconnectInfo>
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
                this.handleMessageError(err as Error)
            }
        })

        this.socket.on("error", (error) => {
            this.emit("error", error)
        })

        this.socket.on("close", () => {
            this.state = SocketState.Disconnected
            const closeError = this.connectionClosedError("SSH connection closed")
            for (const forwarding of this.remoteForwardListeners.values()) forwarding.server.close()
            this.remoteForwardListeners.clear()
            for (const forwarding of this.remoteStreamLocalListeners.values()) {
                forwarding.server.close()
            }
            this.remoteStreamLocalListeners.clear()
            this.x11Forwardings.clear()
            this.agentForwardingEnabled = false
            for (const channel of this.channels.values()) channel.abort(closeError)
            this.channels.clear()
            this.remoteChannelIds.clear()
            while (this.pendingGlobalRequests.length > 0) {
                const request = this.pendingGlobalRequests.shift()!
                request.reject(
                    this.connectionClosedError(
                        `SSH connection closed during global request ${request.name}`,
                    ),
                )
            }
            this.emit("close")
        })
    }

    private buffering: Buffer = Buffer.alloc(0)
    private identificationParser = new IdentificationParser({ allowPreamble: false })
    private packetDecoder = new BinaryPacketDecoder()
    private packetEncoder = new BinaryPacketEncoder()
    private packetProcessingPaused = false
    private awaitingServiceRequest = false
    private strictKeyExchange = false
    private strictInitialExchange = false
    private readonly strictInitialPackets = new Set<PacketType>()
    private negotiatedClientExtensions: readonly Readonly<SSHExtension>[] = Object.freeze([])
    private initialClientNewKeysReceived = false
    private clientExtInfoAfterNewKeys = false
    private keyExchangeInProgress = false
    private readonly packetsQueuedDuringKeyExchange: Packet[] = []
    private readonly remoteChannelIds = new Set<number>()

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
    private authenticationExpired = false
    private authenticationInProgress = false
    private readonly pendingGlobalRequests: PendingGlobalRequest[] = []

    get noMoreSessions(): boolean {
        return this.noMoreSessionsRequested
    }

    get clientExtensions(): readonly Readonly<SSHExtension>[] {
        return copySSHExtensions(this.negotiatedClientExtensions)
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

    forwardOut(
        boundAddress: string,
        boundPort: number,
        remoteAddress: string,
        remotePort: number,
    ): Promise<ForwardedTCPIPChannel>
    forwardOut(
        boundAddress: string,
        boundPort: number,
        remoteAddress: string,
        remotePort: number,
        callback: ServerForwardCallback<ForwardedTCPIPChannel>,
    ): this
    forwardOut(
        boundAddress: string,
        boundPort: number,
        remoteAddress: string,
        remotePort: number,
        callback?: ServerForwardCallback<ForwardedTCPIPChannel>,
    ): Promise<ForwardedTCPIPChannel> | this {
        const operation = this.openForwardedTCPIPChannel(
            boundAddress,
            boundPort,
            remoteAddress,
            remotePort,
        )
        return this.withOptionalForwardCallback(operation, callback)
    }

    openssh_forwardOutStreamLocal(socketPath: string): Promise<ForwardedStreamLocalChannel>
    openssh_forwardOutStreamLocal(
        socketPath: string,
        callback: ServerForwardCallback<ForwardedStreamLocalChannel>,
    ): this
    openssh_forwardOutStreamLocal(
        socketPath: string,
        callback?: ServerForwardCallback<ForwardedStreamLocalChannel>,
    ): Promise<ForwardedStreamLocalChannel> | this {
        const operation = this.openForwardedStreamLocalChannel(socketPath)
        return this.withOptionalForwardCallback(operation, callback)
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

    disconnect(error?: DisconnectError) {
        if (error && this.socket.writable) {
            this.sendPacket(
                new Disconnect({
                    reason_code: error.reason_code,
                    description: error.message,
                    language_tag: "",
                }),
            )
        }
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

    sendDebug(message: string, alwaysDisplay = false, languageTag = ""): this {
        if (!this.isConnected) throw new Error("Cannot send SSH debug output before connection")
        this.sendPacket(
            new Debug({
                always_display: alwaysDisplay,
                message,
                language_tag: languageTag,
            }),
        )
        return this
    }

    sendIgnore(data: Buffer): this {
        if (!this.isConnected) throw new Error("Cannot send SSH ignore data before connection")
        if (!Buffer.isBuffer(data)) throw new TypeError("SSH ignore data must be a buffer")
        this.sendPacket(new Ignore({ data }))
        return this
    }

    globalRequest(name: string, args?: Buffer): Promise<Buffer>
    globalRequest(name: string, callback: ServerGlobalRequestCallback): this
    globalRequest(name: string, args: Buffer, callback: ServerGlobalRequestCallback): this
    globalRequest(
        name: string,
        argsOrCallback: Buffer | ServerGlobalRequestCallback = Buffer.alloc(0),
        callback?: ServerGlobalRequestCallback,
    ): Promise<Buffer> | this {
        const args = typeof argsOrCallback === "function" ? Buffer.alloc(0) : argsOrCallback
        callback = typeof argsOrCallback === "function" ? argsOrCallback : callback
        let operation: Promise<Buffer>
        try {
            this.validateGlobalRequest(name, args)
            if (!this.isConnected || !this.hasAuthenticated) {
                throw new Error("Cannot send an SSH global request before authentication")
            }
            operation = new Promise<Buffer>((resolve, reject) => {
                this.pendingGlobalRequests.push({ name, resolve, reject })
                try {
                    this.sendPacket(
                        new GlobalRequest({
                            request_name: name,
                            want_reply: true,
                            args: Buffer.from(args),
                        }),
                    )
                } catch (error) {
                    this.pendingGlobalRequests.pop()
                    reject(error as Error)
                }
            })
        } catch (error) {
            operation = Promise.reject(error as Error)
        }
        if (!callback) return operation
        operation.then(
            (response) => callback(undefined, response),
            (error: Error) => callback(error),
        )
        return this
    }

    private validateGlobalRequest(name: string, args: Buffer): void {
        if (!/^[\x21-\x7e]+$/u.test(name)) {
            throw new TypeError("SSH global request name must be non-empty printable ASCII")
        }
        if (!Buffer.isBuffer(args)) {
            throw new TypeError("SSH global request arguments must be a buffer")
        }
    }

    private routeGlobalRequestReply(packet: Packet): void {
        if (!(packet instanceof RequestSuccess) && !(packet instanceof RequestFailure)) return
        const request = this.pendingGlobalRequests.shift()
        if (!request) throw new Error("Received an unexpected SSH global request response")
        if (packet instanceof RequestSuccess) {
            request.resolve(Buffer.from(packet.data.args))
        } else {
            request.reject(
                new ServerGlobalRequestError(`SSH global request ${request.name} failed`),
            )
        }
    }

    private createKexInit(): KexInit {
        return new KexInit({
            cookie: crypto.getRandomValues(Buffer.alloc(16)),
            kex_algorithms: [
                ...this.server.algorithmOffer.kex,
                ...(this.sessionID === undefined
                    ? ["ext-info-s", ...STRICT_KEX_SERVER_MARKERS]
                    : []),
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
        this.strictInitialExchange = !isRekey
        if (!isRekey) this.strictInitialPackets.clear()
        this.keyExchangeInProgress = true
        this.hasReceivedNewKeys = false
        this.hasSentNewKeys = false

        try {
            this.serverKexInit = this.createKexInit()
            this.sendPacket(this.serverKexInit)
            const [clientKexInit, clientKexInitBuffer] =
                received ?? (await this.waitEvent("clientKexInit"))
            this.clientKexInit = clientKexInit
            this.strictKeyExchange ||= negotiatesStrictKeyExchange(
                clientKexInit.data.kex_algorithms,
                this.serverKexInit.data.kex_algorithms,
            )
            chooseAlgorithms(this)

            const kexAlgorithm = this.kexAlgorithm
            assert(kexAlgorithm, "No key exchange algorithm was negotiated")
            const hostKey = this.server.options.hostKeys.find(
                (key) => key.data.alg === this.hostKeyAlgorithm!.key_format,
            )
            assert(hostKey, "No host key found for the negotiated algorithm")
            const publicKey = hostKey.data.publicKey.serialize()
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
            } else if (kexAlgorithm instanceof RSA2048SHA256) {
                await kexAlgorithm.generateTransientKey()
                kexAlgorithm.setHostKey(publicKey)
                this.sendPacket(
                    new KexRSAPublicKey({
                        hostKey: publicKey,
                        transientKey: kexAlgorithm.getTransientPublicKey(),
                    }),
                )
                const [secret] = await this.waitEvent("clientKexRSASecret")
                kexAlgorithm.decryptSecret(secret.data.encryptedSecret)
            } else {
                const [clientKexDHInit] = await this.waitEvent("clientKexDHInit")
                this.clientKexDHInit = clientKexDHInit
                kexAlgorithm.generateKeyPair()
                kexAlgorithm.computeSharedSecret(clientKexDHInit.data.e)
            }

            const h = kexAlgorithm.computeHServer(this, clientKexInitBuffer, publicKey)
            const hostSignature = hostKey
                .sign(h, this.hostKeyAlgorithm!.signature_algorithm)
                .serialize()
            if (kexAlgorithm instanceof RSA2048SHA256) {
                this.sendPacket(new KexRSADone({ signature: hostSignature }))
            } else {
                const reply = {
                    K_S: publicKey,
                    f: kexAlgorithm.getPublicKey(),
                    H_sig: hostSignature,
                }
                this.sendPacket(
                    kexAlgorithm instanceof DiffieHellmanGroupExchange
                        ? new KexDHGexReply(reply)
                        : new KexDHReply({
                              ...reply,
                              encoding: kexAlgorithm.exchangeValueEncoding,
                          }),
                )
            }

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
            if (this.strictKeyExchange) this.packetEncoder.resetSequenceNumber()
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
                            { name: "ping@openssh.com", value: Buffer.from("0", "ascii") },
                            ...(this.server.hooker.hasHooks("publicKeyAuthentication")
                                ? [
                                      {
                                          name: "publickey-hostbound@openssh.com",
                                          value: Buffer.from("0", "ascii"),
                                      },
                                  ]
                                : []),
                        ],
                    }),
                )
            }
            while (this.packetsQueuedDuringKeyExchange.length > 0) {
                this.writePacket(this.packetsQueuedDuringKeyExchange.shift()!)
            }
            this.keyExchangeInProgress = false
            this.strictInitialExchange = false
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
            this.strictInitialExchange = false
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

        this.awaitingServiceRequest = true
        const serviceRequest = await this.waitForHigherLayerPacket()
        this.awaitingServiceRequest = false
        if (!(serviceRequest instanceof ServiceRequest)) {
            throw new DisconnectError(
                DisconnectReason.SSH_DISCONNECT_PROTOCOL_ERROR,
                "SSH client sent application data before requesting a service",
            )
        }
        this.debug("Client requested service:", serviceRequest.data.service_name)
        if (serviceRequest.data.service_name !== SSHServiceNames.UserAuth) {
            throw new DisconnectError(
                DisconnectReason.SSH_DISCONNECT_SERVICE_NOT_AVAILABLE,
                `SSH service is not available: ${serviceRequest.data.service_name}`,
            )
        }

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

        this.authenticationInProgress = true
        try {
            await this.handleAuthenticationWithinLimits()
        } finally {
            this.authenticationInProgress = false
        }
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
            let accepted = false
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
                accepted = true
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
                if (!accepted) this.remoteChannelIds.delete(packet.data.sender_channel_id)
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
            const lock = await this.queue.obtainLock(
                `channelRequest:${packet.data.recipient_channel_id}`,
            )
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
                await this.handleApplicationGlobalRequest(packet)
        }
    }

    private async handleApplicationGlobalRequest(packet: GlobalRequest): Promise<void> {
        const context: ServerHookerGlobalRequestContext = Object.freeze({
            name: packet.data.request_name,
            args: Buffer.from(packet.data.args),
            wantReply: packet.data.want_reply,
        })
        const controller: ServerHookerGlobalRequestController = { success: false }
        await this.server.hooker.triggerHook("globalRequest", context, controller, this)
        if (!packet.data.want_reply) return
        if (!controller.success) {
            this.sendPacket(new RequestFailure({}))
            return
        }
        if (controller.response !== undefined && !Buffer.isBuffer(controller.response)) {
            throw new TypeError("SSH global request response must be a buffer")
        }
        this.sendPacket(
            new RequestSuccess({ args: Buffer.from(controller.response ?? Buffer.alloc(0)) }),
        )
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

            const message = createHostKeysProofMessage(this.sessionID!, publicKey)
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

    private async openForwardedTCPIPChannel(
        boundAddress: string,
        boundPort: number,
        remoteAddress: string,
        remotePort: number,
    ): Promise<ForwardedTCPIPChannel> {
        this.validateForwardingPort(boundPort, "forwarded TCP bound port")
        this.validateForwardingPort(remotePort, "forwarded TCP originator port")
        if (!this.remoteForwardListeners.has(this.remoteForwardingKey(boundAddress, boundPort))) {
            throw new Error(
                `The SSH client did not request forwarding for ${boundAddress}:${boundPort}`,
            )
        }
        return this.openForwardedChannel(
            new ForwardedTCPIPChannel(this, {
                destinationHost: boundAddress,
                destinationPort: boundPort,
                sourceHost: remoteAddress,
                sourcePort: remotePort,
            }),
        )
    }

    private async openForwardedStreamLocalChannel(
        socketPath: string,
    ): Promise<ForwardedStreamLocalChannel> {
        if (socketPath.length === 0 || socketPath.includes("\0")) {
            throw new Error("SSH stream-local forwarding path must be non-empty and contain no NUL")
        }
        if (!this.remoteStreamLocalListeners.has(socketPath)) {
            throw new Error(
                `The SSH client did not request stream-local forwarding for ${socketPath}`,
            )
        }
        return this.openForwardedChannel(new ForwardedStreamLocalChannel(this, socketPath))
    }

    private async openForwardedChannel<
        T extends ForwardedTCPIPChannel | ForwardedStreamLocalChannel,
    >(channel: T): Promise<T> {
        if (!this.isConnected || !this.hasAuthenticated) {
            throw new Error("Cannot open a forwarded channel before authentication completes")
        }
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

    private withOptionalForwardCallback<T extends Channel>(
        operation: Promise<T>,
        callback?: ServerForwardCallback<T>,
    ): Promise<T> | this {
        if (!callback) return operation
        operation.then(
            (channel) => callback(undefined, channel),
            (error: Error) => callback(error),
        )
        return this
    }

    private validateForwardingPort(port: number, name: string): void {
        if (!Number.isSafeInteger(port) || port < 0 || port > 65_535) {
            throw new RangeError(`${name} must be between 0 and 65535`)
        }
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

    private async handleAuthenticationWithinLimits(): Promise<void> {
        const timeout = this.server.options.authenticationTimeout
        if (timeout === 0) {
            await this.handleAuthentication()
            return
        }

        let timer: NodeJS.Timeout | undefined
        const deadline = new Promise<never>((_resolve, reject) => {
            timer = setTimeout(() => {
                this.authenticationExpired = true
                reject(
                    new DisconnectError(
                        DisconnectReason.SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE,
                        "Authentication timed out",
                    ),
                )
            }, timeout)
            timer.unref()
        })
        try {
            await Promise.race([this.handleAuthentication(), deadline])
        } finally {
            if (timer) clearTimeout(timer)
        }
    }

    private assertAuthenticationActive(): void {
        if (this.authenticationExpired) {
            throw new DisconnectError(
                DisconnectReason.SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE,
                "Authentication timed out",
            )
        }
    }

    async handleAuthentication() {
        let allowLogin = false
        let authRequest: UserAuthRequest | undefined
        let pendingAuthRequest: UserAuthRequest | undefined
        let failedAttempts = 0
        const authenticationMethods: SSHAuthenticationMethods[] = []
        if (this.server.hooker.hasHooks("publicKeyAuthentication")) {
            authenticationMethods.push(SSHAuthenticationMethods.PublicKey)
        }
        if (this.server.hooker.hasHooks("hostbasedAuthentication")) {
            authenticationMethods.push(SSHAuthenticationMethods.Hostbased)
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
            if (!continuation.partialSuccess) {
                failedAttempts++
                if (failedAttempts >= this.server.options.maxAuthenticationAttempts) {
                    throw new DisconnectError(
                        DisconnectReason.SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE,
                        "Too many authentication failures",
                    )
                }
            }
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
                    const packet = await this.waitForHigherLayerPacket()
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
                        this.assertAuthenticationActive()

                        if (controller.allowLogin) {
                            allowLogin = true
                            break authentication
                        }

                        this.sendPacket(userAuthFailure)
                        break
                    }
                    case SSHAuthenticationMethods.PublicKey:
                    case SSHAuthenticationMethods.HostboundPublicKey: {
                        const method = authRequest.data.method as
                            | PublicKeyAuthMethod
                            | HostboundPublicKeyAuthMethod
                        const hostbound = method instanceof HostboundPublicKeyAuthMethod
                        let boundServerHostKey: PublicKey | undefined
                        if (hostbound) {
                            const hostKey = this.server.options.hostKeys.find(
                                (key) => key.data.alg === this.hostKeyAlgorithm!.key_format,
                            )
                            assert(hostKey, "Negotiated server host key is unavailable")
                            if (
                                !method.data.serverHostKey.equals(
                                    hostKey.data.publicKey.serialize(),
                                )
                            ) {
                                sendAuthenticationFailure({}, SSHAuthenticationMethods.PublicKey)
                                break
                            }
                            boundServerHostKey = PublicKey.parse(method.data.serverHostKey)
                        }
                        const signatureMessage = authRequest.serializeForSignature(this)
                        if (
                            method.data.signature &&
                            !method.data.publicKey.verifySignature(
                                signatureMessage,
                                method.data.signature,
                            )
                        ) {
                            sendAuthenticationFailure({}, SSHAuthenticationMethods.PublicKey)
                            break
                        }
                        const certificateAlgorithm = method.data.publicKey.data.algorithm
                        const certificate =
                            certificateAlgorithm instanceof SSHCertificatePublicKey
                                ? certificateAlgorithm
                                : undefined
                        if (certificate) {
                            const now = BigInt(Math.floor(Date.now() / 1000))
                            if (
                                certificate.data.role !== "user" ||
                                now < certificate.data.validAfter ||
                                now >= certificate.data.validBefore ||
                                !certificate.verifyCertificateSignature()
                            ) {
                                sendAuthenticationFailure({}, SSHAuthenticationMethods.PublicKey)
                                break
                            }
                        }
                        const context: ServerHookerPublicKeyAuthenticationContext = {
                            username: authRequest.data.username,
                            publicKey: method.data.publicKey,
                            certificate,
                            algorithm: method.data.algorithm!,
                            signature: method.data.signature,
                            signatureMessage,
                            hostbound,
                            serverHostKey: boundServerHostKey,
                        }
                        const controller: ServerHookerPublicKeyAuthenticationController = {
                            requestSignature: false,
                            allowLogin: false,
                        }
                        await this.server.hooker.triggerHook(
                            "publicKeyAuthentication",
                            Object.freeze(context),
                            controller,
                            this,
                        )
                        this.assertAuthenticationActive()
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
                        if (controller.allowLogin && !method.data.signature) {
                            controller.allowLogin = false
                            controller.requestSignature = true
                        }
                        if (controller.allowLogin) {
                            allowLogin = true
                            break authentication
                        } else if (controller.requestSignature) {
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
                    case SSHAuthenticationMethods.Hostbased: {
                        const method = authRequest.data.method as HostbasedAuthMethod
                        const signatureMessage = authRequest.serializeForSignature(this)
                        if (
                            !method.data.publicKey.verifySignature(
                                signatureMessage,
                                method.data.signature,
                            )
                        ) {
                            sendAuthenticationFailure({}, SSHAuthenticationMethods.Hostbased)
                            break
                        }
                        const context: ServerHookerHostbasedAuthenticationContext = {
                            username: authRequest.data.username,
                            publicKey: method.data.publicKey,
                            algorithm: method.data.algorithm,
                            clientHostname: method.data.clientHostname,
                            clientUsername: method.data.clientUsername,
                            signature: method.data.signature,
                            signatureMessage,
                            remoteAddress: this.socket.remoteAddress,
                            remotePort: this.socket.remotePort,
                        }
                        const controller: ServerHookerHostbasedAuthenticationController = {
                            allowLogin: false,
                        }
                        await this.server.hooker.triggerHook(
                            "hostbasedAuthentication",
                            Object.freeze(context),
                            controller,
                            this,
                        )
                        this.assertAuthenticationActive()
                        if (controller.allowLogin) {
                            allowLogin = true
                            break authentication
                        }
                        sendAuthenticationFailure(controller, SSHAuthenticationMethods.Hostbased)
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
                        this.assertAuthenticationActive()

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

                        sendAuthenticationFailure(controller, SSHAuthenticationMethods.Password)
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
                            this.assertAuthenticationActive()

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
                                sendAuthenticationFailure(
                                    controller,
                                    SSHAuthenticationMethods.KeyboardInteractive,
                                )
                                break keyboardInteractive
                            }

                            const request = new UserAuthInfoRequest({
                                name: controller.name ?? "",
                                instruction: controller.instruction ?? "",
                                languageTag: controller.languageTag ?? "",
                                prompts: controller.prompts,
                            })
                            this.sendPacket(request)
                            const packet = await this.waitForHigherLayerPacket()
                            if (packet instanceof UserAuthRequest) {
                                pendingAuthRequest = packet
                                break keyboardInteractive
                            }
                            assert(packet instanceof UserAuthInfoResponse, "Invalid packet type")
                            if (packet.data.responses.length !== request.data.prompts.length) {
                                sendAuthenticationFailure(
                                    {},
                                    SSHAuthenticationMethods.KeyboardInteractive,
                                )
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
            if (this.state === SocketState.Disconnected || this.socket.destroyed) {
                reject(
                    this.connectionClosedError(`SSH connection closed while waiting for ${event}`),
                )
                return
            }
            const onError = (error: Error) => {
                cleanup()
                reject(error)
            }
            const onClose = () => {
                cleanup()
                reject(
                    this.connectionClosedError(`SSH connection closed while waiting for ${event}`),
                )
            }
            const handler = (...values: ServerClientEvents[event]) => {
                resolve(values)
                cleanup()
            }
            const cleanup = () => {
                // @ts-expect-error the function definition makes sure this is respected
                this.off(event, handler)
                this.off("error", onError)
                this.off("close", onClose)
            }
            // @ts-expect-error the function definition makes sure this is respected
            this.once(event, handler)
            this.once("error", onError)
            this.once("close", onClose)
        })
    }

    private async waitForHigherLayerPacket(): Promise<Packet> {
        while (true) {
            const [packet] = await this.waitEvent("packet")
            const type = (packet.constructor as typeof Packet).type
            if (
                type <= PacketNameToType.SSH_MSG_DEBUG ||
                type === PacketNameToType.SSH_MSG_EXT_INFO ||
                (type >= PacketNameToType.SSH_MSG_KEXINIT && type < 50)
            ) {
                continue
            }
            return packet
        }
    }

    sendPacket(packet: Packet): number {
        const type = (packet.constructor as typeof Packet).type
        if (
            this.keyExchangeInProgress &&
            (type >= 50 ||
                type === PacketNameToType.SSH_MSG_PING ||
                type === PacketNameToType.SSH_MSG_PONG ||
                type === PacketNameToType.SSH_MSG_IGNORE ||
                type === PacketNameToType.SSH_MSG_DEBUG ||
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
                this.handleMessageError(error as Error)
            }
        })
    }

    private handleMessageError(error: Error): void {
        if (error instanceof DisconnectError) this.disconnect(error)
        else this.terminate()
        this.emit("error", error)
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

        this.validateClientExtInfoPosition(packetType)

        if (
            this.strictKeyExchange &&
            this.strictInitialExchange &&
            !isStrictKeyExchangePacket(packetType)
        ) {
            throw new KeyExchangeError("Received a non-KEX packet during strict key exchange")
        }
        if (!(packetType in PacketTypeToName)) {
            this.debug("Unsupported SSH packet type:", packetType)
            this.sendPacket(new Unimplemented({ sequence_number: decoded.sequenceNumber }))
            if (this.packetDecoder.bufferedLength > 0) {
                this.scheduleMessageProcessing(Buffer.alloc(0))
            }
            return
        }
        const packetName = PacketTypeToName[packetType]
        if (!(packetName in packets)) {
            this.debug("Unimplemented SSH packet:", packetName)
            this.sendPacket(new Unimplemented({ sequence_number: decoded.sequenceNumber }))
            if (this.packetDecoder.bufferedLength > 0) {
                this.scheduleMessageProcessing(Buffer.alloc(0))
            }
            return
        }
        this.validateHigherLayerPhase(packetType)
        const packet =
            packetType === PacketNameToType.SSH_MSG_KEXDH_REPLY &&
            this.kexAlgorithm instanceof RSA2048SHA256
                ? KexRSASecret
                : packetType === PacketNameToType.SSH_MSG_KEXDH_INIT &&
                    this.kexAlgorithm instanceof DiffieHellmanGroupExchange
                  ? KexDHGexRequestOld
                  : packets[packetName as keyof typeof packets]

        const p = packet.parse(payload)
        if (packetType === PacketNameToType.SSH_MSG_KEXINIT && this.strictInitialExchange) {
            const clientAlgorithms = (p as KexInit).data.kex_algorithms
            const negotiated = negotiatesStrictKeyExchange(
                clientAlgorithms,
                this.serverKexInit!.data.kex_algorithms,
            )
            this.strictKeyExchange ||= negotiated
            if (negotiated && decoded.sequenceNumber !== 0) {
                throw new KeyExchangeError("Strict key exchange requires KEXINIT to be packet zero")
            }
        }
        if (this.strictKeyExchange && this.strictInitialExchange) {
            if (this.strictInitialPackets.has(packetType)) {
                throw new KeyExchangeError("Received a duplicate packet during strict key exchange")
            }
            this.strictInitialPackets.add(packetType)
        }
        this.emit("packet", p)
        this.routeGlobalRequestReply(p)
        this.debug("Parsing packet:", this.packetForDebug(p))

        switch (packet.type) {
            case PacketNameToType.SSH_MSG_DISCONNECT: {
                const disconnect = p as Disconnect
                this.peerDisconnect = peerDisconnectInfo(disconnect.data)
                this.emit("disconnect", this.peerDisconnect)
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
                this.emit("protocolDebug", protocolDebugMessage(debug.data))
                this.debug(`Received debug packet:`, [debug.data.message])
                break
            }

            case PacketNameToType.SSH_MSG_SERVICE_REQUEST:
                if (!this.awaitingServiceRequest) {
                    throw new DisconnectError(
                        DisconnectReason.SSH_DISCONNECT_PROTOCOL_ERROR,
                        "SSH client sent an unexpected service request",
                    )
                }
                break

            case PacketNameToType.SSH_MSG_SERVICE_ACCEPT:
                throw new DisconnectError(
                    DisconnectReason.SSH_DISCONNECT_PROTOCOL_ERROR,
                    "SSH client sent a service acceptance",
                )

            case PacketNameToType.SSH_MSG_EXT_INFO: {
                this.negotiatedClientExtensions = copySSHExtensions((p as ExtInfo).data.extensions)
                this.emit("clientExtensions", this.clientExtensions)
                break
            }

            case PacketNameToType.SSH_MSG_PING: {
                const ping = p as Ping
                this.sendPacket(new Pong({ data: ping.data.data }))
                break
            }

            case PacketNameToType.SSH_MSG_PONG:
                break

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

            case PacketNameToType.SSH_MSG_KEXDH_REPLY:
                if (!(this.kexAlgorithm instanceof RSA2048SHA256)) {
                    throw new Error("Received an RSA secret for another key exchange")
                }
                this.emit("clientKexRSASecret", p as KexRSASecret)
                this.packetProcessingPaused = true
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
                if (this.strictKeyExchange) this.packetDecoder.resetSequenceNumber()
                if (!this.initialClientNewKeysReceived) {
                    this.initialClientNewKeysReceived = true
                    this.clientExtInfoAfterNewKeys = true
                }
                this.emit("clientNewKeys")
                break

            case PacketNameToType.SSH_MSG_CHANNEL_OPEN:
                this.reserveRemoteChannelId((p as ChannelOpen).data.sender_channel_id)
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
                this.reserveRemoteChannelId(confirmation.data.sender_channel_id)
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
            case PacketNameToType.SSH_MSG_CHANNEL_SUCCESS: {
                const success = p as ChannelSuccess
                this.queueChannelAction(success.data.recipient_channel_id, (channel) => {
                    channel.receiveRequestSuccess()
                })
                break
            }
            case PacketNameToType.SSH_MSG_CHANNEL_FAILURE: {
                const failure = p as ChannelFailure
                this.queueChannelAction(failure.data.recipient_channel_id, (channel) => {
                    channel.receiveRequestFailure()
                })
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
                    if (channel.isFullyClosed) {
                        this.channels.delete(channel.localId)
                        if (channel.remoteId !== undefined) {
                            this.remoteChannelIds.delete(channel.remoteId)
                        }
                    }
                })
                break
            }
        }

        if (this.packetDecoder.bufferedLength > 0) {
            this.scheduleMessageProcessing(Buffer.alloc(0))
        }
    }

    private validateClientExtInfoPosition(packetType: PacketType): void {
        if (packetType === PacketNameToType.SSH_MSG_EXT_INFO) {
            if (!this.clientExtInfoAfterNewKeys) {
                throw new Error("Client EXT_INFO arrived outside its RFC 8308 opportunity")
            }
            this.clientExtInfoAfterNewKeys = false
            return
        }
        this.clientExtInfoAfterNewKeys = false
    }

    private validateHigherLayerPhase(packetType: PacketType): void {
        if (packetType >= 50 && packetType < 80) {
            if (!this.authenticationInProgress) {
                throw new DisconnectError(
                    DisconnectReason.SSH_DISCONNECT_PROTOCOL_ERROR,
                    "SSH client sent an authentication message outside authentication",
                )
            }
            if (
                packetType !== PacketNameToType.SSH_MSG_USERAUTH_REQUEST &&
                packetType !== PacketNameToType.SSH_MSG_USERAUTH_INFO_RESPONSE
            ) {
                throw new DisconnectError(
                    DisconnectReason.SSH_DISCONNECT_PROTOCOL_ERROR,
                    "SSH client sent a server-only authentication message",
                )
            }
        }
        if (packetType >= 80 && packetType < 128 && !this.hasAuthenticated) {
            throw new DisconnectError(
                DisconnectReason.SSH_DISCONNECT_PROTOCOL_ERROR,
                "SSH client sent a connection message before authentication completed",
            )
        }
    }

    private connectionClosedError(fallback: string): Error {
        return this.peerDisconnect
            ? new PeerDisconnectError(this.peerDisconnect)
            : new Error(fallback)
    }

    private reserveRemoteChannelId(remoteId: number): void {
        if (this.remoteChannelIds.has(remoteId)) {
            throw new DisconnectError(
                DisconnectReason.SSH_DISCONNECT_PROTOCOL_ERROR,
                `SSH peer reused active channel identifier ${remoteId}`,
            )
        }
        this.remoteChannelIds.add(remoteId)
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
                this.handleMessageError(error)
            })
    }
}
