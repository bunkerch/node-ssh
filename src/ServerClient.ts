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
    ServerHookerGSSAPIAuthenticationContext,
    ServerHookerGSSAPIAuthenticationController,
    ServerHookerGlobalRequestContext,
    ServerHookerGlobalRequestController,
    ServerHookerElevationContext,
    ServerHookerElevationController,
    ServerHookerStreamLocalForwardContext,
    ServerHookerTCPIPForwardContext,
    type ServerTransport,
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
    compression_algorithms,
    host_key_algorithms,
    public_key_signature_algorithms,
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
    ProtocolError,
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
import ExtInfo, {
    AUTHENTICATION_EXT_INFO_EXTENSION,
    copySSHExtensions,
    type SSHExtension,
} from "./packets/ExtInfo.js"
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
import { decodeSSHUTF8 } from "./utils/SSHText.js"
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
import GSSAPIWithMICAuthMethod from "./auth/gssapi-with-mic.js"
import GSSAPIKeyExchangeAuthMethod from "./auth/gssapi-keyex.js"
import {
    buildGSSAPIKeyExchangeUserAuthMIC,
    buildGSSAPIUserAuthMIC,
    closeGSSAPIContext,
    GSSAPIError,
    normalizeGSSAPIContextStep,
    normalizeGSSAPIKeyExchangeContextStep,
    normalizeGSSAPIToken,
    type GSSAPIContextStep,
    type GSSAPIKeyExchangeServerContext,
    type GSSAPIServerContext,
} from "./GSSAPI.js"
import {
    UserAuthGSSAPIError,
    UserAuthGSSAPIErrorToken,
    UserAuthGSSAPIExchangeComplete,
    UserAuthGSSAPIMIC,
    UserAuthGSSAPIResponse,
    UserAuthGSSAPIToken,
} from "./packets/UserAuthGSSAPI.js"
import {
    findNoFlowControlValue,
    negotiateNoFlowControl,
    noFlowControlExtension,
    noFlowControlValue,
    type NoFlowControlValue,
} from "./NoFlowControl.js"
import PacketEventQueue from "./utils/PacketEventQueue.js"
import {
    AGENT_FORWARDING_EXTENSION,
    AGENT_FORWARDING_EXTENSION_VERSION,
    authorizeAgentForwarding,
    type AgentForwardingProtocol,
} from "./AgentForwarding.js"
import GSSAPIKeyExchange from "./algorithms/kex/gssapi-key-exchange.js"
import { ELEVATION_EXTENSION, findElevationRequest, type ElevationRequest } from "./Elevation.js"
import { serializeBinaryBoolean } from "./utils/BinaryBoolean.js"
import {
    delayCompressionExtension,
    findDelayCompressionOffers,
    negotiateDelayCompression,
    type DelayCompressionOffers,
    type NegotiatedDelayCompression,
} from "./DelayCompression.js"
import {
    KexGSSAPIComplete,
    KexGSSAPIContinue,
    KexGSSAPIError,
    KexGSSAPIHostKey,
    KexGSSAPIInit,
} from "./packets/KexGSSAPI.js"

interface RemoteForwardListener {
    server: net.Server
}

export class ServerGlobalRequestError extends Error {
    name = "ServerGlobalRequestError"
}

interface PendingGlobalRequest {
    name: string
    resolve: (response: Buffer) => void
    reject: (error: Error) => void
}

const MAX_MESSAGES_BEFORE_NEWCOMPRESS = 32

interface GSSAPIAuthenticationResult {
    allowLogin: boolean
    continuation?: ServerHookerGSSAPIAuthenticationController
    pendingRequest?: UserAuthRequest
    abandoned?: boolean
}

export interface ServerClientEvents {
    error: [error: Error]
    /** The peer transport reached EOF; terminal close cleanup follows. */
    end: []
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
    private socket: ServerTransport
    connectionId: string
    peerDisconnect?: Readonly<PeerDisconnectInfo>
    server: Server

    queue = new ActionQueue<string>()

    constructor(socket: ServerTransport, server: Server) {
        super()
        this.socket = socket
        this.server = server
        this.connectionId = randomBase36(9)
        this.delayCompressionRekeyBlocked = server.options.delayCompression !== false

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

        this.socket.on("end", () => {
            this.emit("end")
            this.socket.destroy()
        })

        this.socket.on("close", () => {
            this.clearHandshakeTimeout()
            this.clearKeepalive()
            this.clearRekeyTimer()
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
            this.agentForwardingProtocol = undefined
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
            void this.closeInitialGSSAPIKeyExchangeContext().catch((error) =>
                this.debug("Could not close the initial GSS-API key-exchange context:", error),
            )
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
    private clientAuthenticationExtInfoSupported = false
    private clientElevationRequest?: ElevationRequest
    private clientDelayCompressionOffers?: Readonly<DelayCompressionOffers>
    private advertisedDelayCompressionOffers?: Readonly<DelayCompressionOffers>
    private pendingDelayCompression?: Readonly<NegotiatedDelayCompression>
    private awaitingClientNewCompress = false
    private messagesBeforeNewCompress = 0
    private delayCompressionRekeyBlocked = false
    private advertisedNoFlowControlValue?: NoFlowControlValue
    private noFlowControlEnabled = false
    private authenticationRequestReceived = false
    private authenticationExtInfoSent = false
    private keyExchangeInProgress = false
    private peerKexInitReceived = false
    private inboundNewKeysReady = false
    private readonly expectedInboundKeyExchangePackets = new Set<PacketType>()
    private discardNextGuessedKeyExchangePacket = false
    private readonly packetsQueuedDuringKeyExchange: Packet[] = []
    private readonly remoteChannelIds = new Set<number>()
    private initialGSSAPIKeyExchangeContext?: GSSAPIKeyExchangeServerContext
    private initialGSSAPIKeyExchangeStep?: Readonly<GSSAPIContextStep>
    private initialGSSAPIKeyExchangeMechanismOID?: Buffer

    private async closeInitialGSSAPIKeyExchangeContext(): Promise<void> {
        const context = this.initialGSSAPIKeyExchangeContext
        this.initialGSSAPIKeyExchangeContext = undefined
        this.initialGSSAPIKeyExchangeStep = undefined
        this.initialGSSAPIKeyExchangeMechanismOID = undefined
        if (context) await closeGSSAPIContext(context)
    }

    clientProtocolVersion?: ProtocolVersionExchange
    clientKexDHInit?: KexDHInit
    // TODO: Assess if these should be private properties
    clientKexInit?: KexInit
    #clientKexInitPayload?: Buffer
    serverKexInit?: KexInit
    #serverKexInitPayload?: Buffer

    get serverKexInitPayload(): Buffer | undefined {
        return this.#serverKexInitPayload && Buffer.from(this.#serverKexInitPayload)
    }

    get clientKexInitPayload(): Buffer | undefined {
        return this.#clientKexInitPayload && Buffer.from(this.#clientKexInitPayload)
    }
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
    #sessionID?: Buffer

    get sessionID(): Buffer | undefined {
        return this.#sessionID && Buffer.from(this.#sessionID)
    }
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
    private agentForwardingProtocol?: AgentForwardingProtocol
    private noMoreSessionsRequested = false
    private authenticationExpired = false
    private authenticationInProgress = false
    private activeAuthenticationMethod?: string
    private readonly pendingGlobalRequests: PendingGlobalRequest[] = []
    private keepaliveTimer?: ReturnType<typeof setTimeout>
    private rekeyTimer?: ReturnType<typeof setTimeout>
    private automaticRekeyScheduled = false
    private unansweredKeepalives = 0
    private handshakeTimer?: ReturnType<typeof setTimeout>

    get noMoreSessions(): boolean {
        return this.noMoreSessionsRequested
    }

    get clientExtensions(): readonly Readonly<SSHExtension>[] {
        return copySSHExtensions(this.negotiatedClientExtensions)
    }

    /** Whether the client permits one EXT_INFO update after authentication starts. */
    get clientSupportsAuthenticationExtensionInfo(): boolean {
        return this.clientAuthenticationExtInfoSupported
    }

    /** The client's advertised RFC 8308 operating-system elevation preference. */
    get clientElevationPreference(): ElevationRequest | undefined {
        return this.clientElevationRequest
    }

    /** Whether RFC 8308 no-flow-control is active for this connection. */
    get noFlowControl(): boolean {
        return this.noFlowControlEnabled
    }

    private updateNoFlowControl(): void {
        this.noFlowControlEnabled = negotiateNoFlowControl(
            this.advertisedNoFlowControlValue,
            this.negotiatedClientExtensions,
        )
    }

    private updateDelayCompression(): void {
        try {
            this.pendingDelayCompression = negotiateDelayCompression(
                this.clientDelayCompressionOffers,
                this.advertisedDelayCompressionOffers,
            )
        } catch (error) {
            if (!(error instanceof KeyExchangeError)) throw error
            throw new DisconnectError(
                DisconnectReason.SSH_DISCONNECT_KEY_EXCHANGE_FAILED,
                error.message,
            )
        }
    }

    private assertChannelCapacity(): void {
        if (
            this.noFlowControlEnabled &&
            (this.channels.size !== 0 || this.remoteChannelIds.size !== 0)
        ) {
            throw new Error("RFC 8308 no-flow-control permits only one simultaneous SSH channel")
        }
    }

    [authorizeAgentForwarding](protocol: AgentForwardingProtocol): void {
        this.agentForwardingEnabled = true
        if (protocol === "rfc9987" || !this.agentForwardingProtocol) {
            this.agentForwardingProtocol = protocol
        }
    }

    state = SocketState.Closed
    get isConnected(): boolean {
        return this.state === SocketState.Connected
    }

    async openssh_forwardAgent(): Promise<ForwardedAgentChannel> {
        return this.openAgentChannel("legacy")
    }

    /** Open an agent channel using the form authorized by the client request. */
    async forwardAgent(): Promise<ForwardedAgentChannel> {
        return this.openAgentChannel(this.agentForwardingProtocol ?? "legacy")
    }

    private async openAgentChannel(
        protocol: AgentForwardingProtocol,
    ): Promise<ForwardedAgentChannel> {
        if (!this.isConnected) throw new Error("SSH connection is not open")
        if (!this.agentForwardingEnabled) {
            throw new Error("The SSH client has not authorized agent forwarding")
        }
        this.assertChannelCapacity()
        const channel = new ForwardedAgentChannel(this, protocol)
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
    ): Promise<ForwardedTCPIPChannel> {
        return this.openForwardedTCPIPChannel(boundAddress, boundPort, remoteAddress, remotePort)
    }

    openssh_forwardOutStreamLocal(socketPath: string): Promise<ForwardedStreamLocalChannel> {
        return this.openForwardedStreamLocalChannel(socketPath)
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

        this.assertChannelCapacity()
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

    /** Gracefully close the connection with an application disconnect. */
    end(): this {
        return this.disconnect(
            new DisconnectError(DisconnectReason.SSH_DISCONNECT_BY_APPLICATION, ""),
        )
    }

    disconnect(error?: DisconnectError): this {
        this.clearRekeyTimer()
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
        return this
    }

    terminate(): this {
        this.clearRekeyTimer()
        this.socket.destroy()
        this.state = SocketState.Disconnected
        return this
    }

    setNoDelay(noDelay = true): this {
        this.socket.setNoDelay?.(noDelay)
        return this
    }

    rekey(): Promise<void> {
        if (this.sessionID === undefined || this.socket.destroyed) {
            return Promise.reject(
                new Error("Cannot rekey before the initial SSH key exchange is complete"),
            )
        }
        if (this.keyExchangeInProgress) {
            return Promise.reject(new Error("SSH key exchange is already in progress"))
        }
        if (this.delayCompressionRekeyBlocked) {
            return Promise.reject(
                new Error("Cannot rekey before RFC 8308 delay-compression is resolved"),
            )
        }
        return this.performKeyExchange().catch((error: unknown) => {
            this.terminate()
            throw error
        })
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

    sendAuthenticationExtensions(extensions: readonly SSHExtension[]): this {
        if (!this.clientAuthenticationExtInfoSupported) {
            throw new Error("SSH client did not advertise authentication extension information")
        }
        if (this.hasAuthenticated) {
            throw new Error("Cannot send authentication extension information after authentication")
        }
        if (!this.authenticationRequestReceived || !this.authenticationInProgress) {
            throw new Error(
                "Authentication extension information requires an active authentication request",
            )
        }
        if (this.authenticationExtInfoSent) {
            throw new Error("SSH server already sent authentication extension information")
        }
        const packet = new ExtInfo({ extensions })
        const noFlowControl = findNoFlowControlValue(extensions)
        const delayCompression = findDelayCompressionOffers(extensions)
        const negotiatedDelayCompression = negotiateDelayCompression(
            this.clientDelayCompressionOffers,
            delayCompression,
        )
        this.sendPacket(packet)
        this.advertisedNoFlowControlValue = noFlowControl
        this.updateNoFlowControl()
        this.advertisedDelayCompressionOffers = delayCompression
        this.pendingDelayCompression = negotiatedDelayCompression
        if (delayCompression) this.delayCompressionRekeyBlocked = true
        this.authenticationExtInfoSent = true
        return this
    }

    globalRequest(name: string, args: Buffer = Buffer.alloc(0)): Promise<Buffer> {
        try {
            this.validateGlobalRequest(name, args)
            if (!this.isConnected || !this.hasAuthenticated) {
                throw new Error("Cannot send an SSH global request before authentication")
            }
            return new Promise<Buffer>((resolve, reject) => {
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
            return Promise.reject(error as Error)
        }
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
        if (!request) {
            throw new ProtocolError("Received an unexpected SSH global request response")
        }
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
                    if (name === "null") return true
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

    private async performGSSAPIKeyExchange(
        algorithm: GSSAPIKeyExchange,
        clientKexInit: Buffer,
        hostKey: Buffer,
        retainContext: boolean,
    ): Promise<{
        exchangeHash: Buffer
        context?: GSSAPIKeyExchangeServerContext
        step?: Readonly<GSSAPIContextStep>
    }> {
        const context = await algorithm.createServerContext({
            service: "host",
            remoteAddress: this.socket.remoteAddress,
            remotePort: this.socket.remotePort,
        })
        assertServerGSSAPIKeyExchangeContext(context)
        const packets = new PacketEventQueue(
            this,
            () => new KeyExchangeError("Connection closed during GSS-API key exchange"),
        )
        let contextRetained = false
        try {
            this.expectInboundKeyExchange(KexGSSAPIInit.type)
            this.resumePacketProcessing()
            const init = await packets.next()
            if (!(init instanceof KexGSSAPIInit)) {
                throw new KeyExchangeError("Expected a GSS-API key-exchange init message")
            }
            if (hostKey.length > 0) this.sendPacket(new KexGSSAPIHostKey(hostKey))
            let step = normalizeGSSAPIKeyExchangeContextStep(await context.step(init.token))
            while (!step.complete) {
                this.sendPacket(new KexGSSAPIContinue(requireGSSAPIKeyExchangeToken(step.token)))
                this.expectInboundKeyExchange(KexGSSAPIContinue.type)
                this.resumePacketProcessing()
                const packet = await packets.next()
                if (!(packet instanceof KexGSSAPIContinue)) {
                    throw new KeyExchangeError(
                        "Expected a GSS-API key-exchange continuation message",
                    )
                }
                step = normalizeGSSAPIKeyExchangeContextStep(await context.step(packet.token))
            }
            if (!step.integrity || !step.mutualAuthentication) {
                throw new KeyExchangeError(
                    "GSS-API key exchange requires integrity and mutual authentication",
                )
            }
            algorithm.generateKeyPair("server")
            algorithm.computeSharedSecret(init.publicKey)
            const exchangeHash = algorithm.computeHServer(this, clientKexInit, hostKey)
            const mic = normalizeGSSAPIToken(
                await context.getMIC(exchangeHash),
                "GSS-API key-exchange MIC",
            )
            this.sendPacket(
                new KexGSSAPIComplete(
                    algorithm.getPublicKey(),
                    mic,
                    step.token,
                    algorithm.exchangeValueEncoding,
                ),
            )
            contextRetained =
                retainContext &&
                step.peerIdentity !== undefined &&
                typeof context.verifyMIC === "function"
            return {
                exchangeHash,
                context: contextRetained ? context : undefined,
                step: contextRetained ? step : undefined,
            }
        } catch (error) {
            if (error instanceof GSSAPIError && this.socket.writable) {
                this.sendPacket(
                    new KexGSSAPIError({
                        majorStatus: error.majorStatus,
                        minorStatus: error.minorStatus,
                        message: error.message,
                        languageTag: error.languageTag,
                    }),
                )
                if (error.token) this.sendPacket(new KexGSSAPIContinue(error.token))
            }
            if (error instanceof KeyExchangeError) throw error
            throw new KeyExchangeError(
                error instanceof Error ? error.message : "GSS-API key exchange failed",
            )
        } finally {
            packets.close()
            if (!contextRetained) await closeGSSAPIContext(context)
        }
    }

    private async performKeyExchange(peerInitiated = false): Promise<void> {
        if (this.keyExchangeInProgress) {
            throw new Error("SSH key exchange is already in progress")
        }
        const isRekey = this.sessionID !== undefined
        this.strictInitialExchange = !isRekey
        if (!isRekey) this.strictInitialPackets.clear()
        this.keyExchangeInProgress = true
        this.clearRekeyTimer()
        this.peerKexInitReceived = peerInitiated
        this.inboundNewKeysReady = false
        this.expectedInboundKeyExchangePackets.clear()
        this.discardNextGuessedKeyExchangePacket = false
        if (!peerInitiated) {
            this.expectedInboundKeyExchangePackets.add(PacketNameToType.SSH_MSG_KEXINIT)
        }
        this.hasReceivedNewKeys = false
        this.hasSentNewKeys = false

        try {
            this.serverKexInit = this.createKexInit()
            this.sendPacket(this.serverKexInit)
            if (!peerInitiated) await this.waitEvent("clientKexInit")
            const clientKexInitBuffer = this.clientKexInitPayload
            assert(clientKexInitBuffer, "Missing exact client KEXINIT payload")
            const clientKexInit = KexInit.parse(clientKexInitBuffer)
            this.clientKexInit = clientKexInit
            this.strictKeyExchange ||= negotiatesStrictKeyExchange(
                clientKexInit.data.kex_algorithms,
                this.serverKexInit.data.kex_algorithms,
            )
            chooseAlgorithms(this)
            this.discardNextGuessedKeyExchangePacket =
                this.shouldDiscardGuessedPacket(clientKexInit)

            const kexAlgorithm = this.kexAlgorithm
            assert(kexAlgorithm, "No key exchange algorithm was negotiated")
            const hostKey =
                this.hostKeyAlgorithm!.alg_name === "null"
                    ? undefined
                    : this.server.options.hostKeys.find(
                          (key) => key.data.alg === this.hostKeyAlgorithm!.key_format,
                      )
            const publicKey = hostKey?.data.publicKey.serialize() ?? Buffer.alloc(0)
            let h: Buffer | undefined
            if (kexAlgorithm instanceof GSSAPIKeyExchange) {
                const result = await this.performGSSAPIKeyExchange(
                    kexAlgorithm,
                    clientKexInitBuffer,
                    publicKey,
                    !isRekey,
                )
                h = result.exchangeHash
                this.initialGSSAPIKeyExchangeContext = result.context
                this.initialGSSAPIKeyExchangeStep = result.step
                this.initialGSSAPIKeyExchangeMechanismOID = result.context
                    ? Buffer.from(kexAlgorithm.mechanismOID)
                    : undefined
            } else if (kexAlgorithm instanceof DiffieHellmanGroupExchange) {
                this.expectInboundKeyExchange(
                    PacketNameToType.SSH_MSG_KEXDH_INIT,
                    PacketNameToType.SSH_MSG_KEX_DH_GEX_REQUEST,
                )
                const [request] = await this.waitEvent("clientKexDHGexRequest")
                if (request instanceof KexDHGexRequestOld) {
                    kexAlgorithm.setOldRequest(request.data.preferred)
                } else {
                    kexAlgorithm.setRequest(request.data)
                }
                const group = kexAlgorithm.selectServerGroup()
                kexAlgorithm.generateKeyPair()
                this.sendPacket(new KexDHGexGroup(group))
                this.expectInboundKeyExchange(PacketNameToType.SSH_MSG_KEX_DH_GEX_INIT)
                const [init] = await this.waitEvent("clientKexDHGexInit")
                kexAlgorithm.computeSharedSecret(init.data.e)
            } else if (kexAlgorithm instanceof RSA2048SHA256) {
                this.expectInboundKeyExchange(PacketNameToType.SSH_MSG_KEXDH_REPLY)
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
                this.expectInboundKeyExchange(PacketNameToType.SSH_MSG_KEXDH_INIT)
                const [clientKexDHInit] = await this.waitEvent("clientKexDHInit")
                this.clientKexDHInit = clientKexDHInit
                kexAlgorithm.generateKeyPair("server")
                kexAlgorithm.computeSharedSecret(clientKexDHInit.data.e)
            }

            if (!(kexAlgorithm instanceof GSSAPIKeyExchange)) {
                assert(hostKey, "No host key found for the negotiated algorithm")
                h = kexAlgorithm.computeHServer(this, clientKexInitBuffer, publicKey)
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
            }
            assert(h, "Key exchange hash was not computed")

            this.H = h
            this.#sessionID ??= Buffer.from(h)
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
            this.inboundNewKeysReady = true
            this.expectInboundKeyExchange(PacketNameToType.SSH_MSG_NEWKEYS)
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
                const noFlowControl = noFlowControlExtension(this.server.options.noFlowControl)
                this.advertisedNoFlowControlValue = noFlowControlValue(
                    this.server.options.noFlowControl,
                )
                const delayCompression =
                    this.server.options.delayCompression === false
                        ? undefined
                        : delayCompressionExtension(this.server.options.delayCompression)
                this.advertisedDelayCompressionOffers =
                    this.server.options.delayCompression === false
                        ? undefined
                        : this.server.options.delayCompression
                this.sendPacket(
                    new ExtInfo({
                        extensions: [
                            {
                                name: "server-sig-algs",
                                value: Buffer.from(
                                    public_key_signature_algorithms.join(","),
                                    "ascii",
                                ),
                            },
                            { name: "ping@openssh.com", value: Buffer.from("0", "ascii") },
                            {
                                name: AGENT_FORWARDING_EXTENSION,
                                value: AGENT_FORWARDING_EXTENSION_VERSION,
                            },
                            ...(this.server.hooker.hasHooks("publicKeyAuthentication")
                                ? [
                                      {
                                          name: "publickey-hostbound@openssh.com",
                                          value: Buffer.from("0", "ascii"),
                                      },
                                  ]
                                : []),
                            ...(noFlowControl ? [noFlowControl] : []),
                            ...(delayCompression ? [delayCompression] : []),
                        ],
                    }),
                )
                if (delayCompression) this.delayCompressionRekeyBlocked = true
            }
            while (this.packetsQueuedDuringKeyExchange.length > 0) {
                this.writePacket(this.packetsQueuedDuringKeyExchange.shift()!)
            }
            this.keyExchangeInProgress = false
            this.strictInitialExchange = false
            this.resetRekeyTimer()
            this.checkRekeyByteLimit()
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
            this.expectedInboundKeyExchangePackets.clear()
        }
    }

    async connect(): Promise<void> {
        this.startHandshakeTimeout()
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
        this.clearHandshakeTimeout()

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
        this.resetKeepalive()
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

        if (this.server.options.sendAllHostKeys && this.server.options.hostKeys.length > 0) {
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

        this.on("channelOpenRequest", (packet) => {
            this.startEventOperation(this.handleChannelOpenRequest(packet), "channel-open request")
        })
        this.on("channelRequest", (packet) => {
            this.startEventOperation(this.handleChannelRequest(packet), "channel request")
        })
    }

    private startEventOperation(operation: Promise<void>, description: string): void {
        void operation.catch((error: unknown) => {
            const failure = error instanceof Error ? error : new Error(String(error))
            this.debug(`Unhandled failure while processing SSH ${description}:`, failure)
            // Leave the rejected-promise chain before entering EventEmitter's synchronous error
            // path. If an error observer itself throws, Node reports that as an ordinary uncaught
            // listener exception instead of turning it into an unhandled promise rejection.
            queueMicrotask(() => this.handleMessageError(failure))
        })
    }

    private async handleChannelOpenRequest(packet: ChannelOpen): Promise<void> {
        this.debug(`ChannelOpenRequest`, packet)

        const lock = await this.queue.obtainLock("channelOpenRequest")
        let accepted = false
        try {
            if (!this.isConnected) return
            if (
                this.noFlowControlEnabled &&
                (this.channels.size !== 0 || this.remoteChannelIds.size > 1)
            ) {
                throw new ChannelOpenError(
                    ChannelOpenFailureReasonCodes.SSH_OPEN_RESOURCE_SHORTAGE,
                    packet.data.sender_channel_id,
                    "RFC 8308 no-flow-control permits only one simultaneous SSH channel",
                )
            }
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

            const policyCompleted = await this.server.hooker.triggerHookChecked(
                "channelOpenRequest",
                channel,
                controller,
                this,
            )
            if (!this.isConnected) return

            if (!policyCompleted || !controller.allowOpen) {
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
            if (!this.isConnected) return

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
    }

    private async handleChannelRequest(packet: ChannelRequest): Promise<void> {
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

        // Make sure PTY setup is handled before exec, shell, and later requests.
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
            // The base method sends channel failure for an otherwise unhandled request.
            await Channel.prototype.handleChannelRequest.call(channel, packet)
        } finally {
            lock.release()
        }
    }

    private async handleGlobalRequest(packet: GlobalRequest): Promise<void> {
        this.debug(`Received global request packet:`, packet)
        if (!this.isConnected) return

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
        const policyCompleted = await this.server.hooker.triggerHookChecked(
            "globalRequest",
            context,
            controller,
            this,
        )
        if (!this.isConnected) return
        if (!packet.data.want_reply) return
        if (!policyCompleted || !controller.success) {
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
            const policyCompleted = await this.server.hooker.triggerHookChecked(
                "tcpipForward",
                context,
                controller,
                this,
            )
            if (!this.isConnected) return
            if (!policyCompleted || !controller.allow) {
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
            if (packet.data.want_reply && this.isConnected) {
                this.sendPacket(new RequestFailure({}))
            }
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
        return Object.freeze({
            bindAddress: decodeSSHUTF8(bindAddress, "TCP forwarding bind address"),
            bindPort,
        })
    }

    private async handleStreamLocalForward(packet: GlobalRequest): Promise<void> {
        try {
            const context = this.parseStreamLocalForwardArgs(packet.data.args)
            const controller = { allow: false }
            const policyCompleted = await this.server.hooker.triggerHookChecked(
                "streamLocalForward",
                context,
                controller,
                this,
            )
            if (!this.isConnected) return
            if (
                !policyCompleted ||
                !controller.allow ||
                this.remoteStreamLocalListeners.has(context.socketPath)
            ) {
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
            if (packet.data.want_reply && this.isConnected) {
                this.sendPacket(new RequestFailure({}))
            }
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
        return Object.freeze({
            socketPath: decodeSSHUTF8(socketPath, "stream-local forwarding socket path"),
        })
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
        this.assertChannelCapacity()
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
        socket.on("error", () => channel.terminate())
        socket.on("close", () => channel.close())

        try {
            this.assertChannelCapacity()
            this.channels.set(channel.localId, channel)
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
        if (
            this.server.options.gssapi.some((mechanism) => mechanism.createContext !== undefined) &&
            this.server.hooker.hasHooks("gssapiAuthentication")
        ) {
            authenticationMethods.push(SSHAuthenticationMethods.GSSAPIWithMIC)
        }
        if (
            this.initialGSSAPIKeyExchangeContext &&
            this.initialGSSAPIKeyExchangeStep?.peerIdentity !== undefined &&
            this.server.hooker.hasHooks("gssapiAuthentication")
        ) {
            authenticationMethods.unshift(SSHAuthenticationMethods.GSSAPIKeyExchange)
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

                        const policyCompleted = await this.server.hooker.triggerHookChecked(
                            "noneAuthentication",
                            Object.freeze(context),
                            controller,
                            this,
                        )
                        this.assertAuthenticationActive()

                        if (policyCompleted && controller.allowLogin) {
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
                        const policyCompleted = await this.server.hooker.triggerHookChecked(
                            "publicKeyAuthentication",
                            Object.freeze(context),
                            controller,
                            this,
                        )
                        this.assertAuthenticationActive()
                        if (!policyCompleted) {
                            sendAuthenticationFailure({}, SSHAuthenticationMethods.PublicKey)
                            break
                        }
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
                        const policyCompleted = await this.server.hooker.triggerHookChecked(
                            "hostbasedAuthentication",
                            Object.freeze(context),
                            controller,
                            this,
                        )
                        this.assertAuthenticationActive()
                        if (!policyCompleted) {
                            sendAuthenticationFailure({}, SSHAuthenticationMethods.Hostbased)
                            break
                        }
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

                        const policyCompleted = await this.server.hooker.triggerHookChecked(
                            "passwordAuthentication",
                            Object.freeze(context),
                            controller,
                            this,
                        )
                        this.assertAuthenticationActive()

                        if (!policyCompleted) {
                            sendAuthenticationFailure({}, SSHAuthenticationMethods.Password)
                            break
                        }

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
                            const policyCompleted = await this.server.hooker.triggerHookChecked(
                                "keyboardInteractiveAuthentication",
                                Object.freeze(context),
                                controller,
                                this,
                            )
                            this.assertAuthenticationActive()

                            if (!policyCompleted) {
                                sendAuthenticationFailure(
                                    {},
                                    SSHAuthenticationMethods.KeyboardInteractive,
                                )
                                break keyboardInteractive
                            }

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
                    case SSHAuthenticationMethods.GSSAPIWithMIC: {
                        const result = await this.performGSSAPIAuthentication(authRequest)
                        this.assertAuthenticationActive()
                        if (result.pendingRequest) pendingAuthRequest = result.pendingRequest
                        if (result.abandoned) break
                        if (result.allowLogin) {
                            allowLogin = true
                            break authentication
                        }
                        sendAuthenticationFailure(
                            result.continuation,
                            SSHAuthenticationMethods.GSSAPIWithMIC,
                        )
                        break
                    }
                    case SSHAuthenticationMethods.GSSAPIKeyExchange: {
                        const controller =
                            await this.performGSSAPIKeyExchangeAuthentication(authRequest)
                        this.assertAuthenticationActive()
                        if (controller.allowLogin) {
                            allowLogin = true
                            break authentication
                        }
                        sendAuthenticationFailure(
                            controller,
                            SSHAuthenticationMethods.GSSAPIKeyExchange,
                        )
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
        await this.closeInitialGSSAPIKeyExchangeContext()
        this.credentials = authRequest

        if (allowLogin) {
            let elevationResult: boolean | undefined
            if (this.server.hooker.hasHooks("elevation")) {
                const context: ServerHookerElevationContext = Object.freeze({
                    preference: this.clientElevationRequest ?? "default",
                    username: authRequest.data.username,
                })
                const controller: ServerHookerElevationController = {}
                const policyCompleted = await this.server.hooker.triggerHookChecked(
                    "elevation",
                    context,
                    controller,
                    this,
                )
                this.assertAuthenticationActive()
                if (policyCompleted) {
                    if (
                        controller.elevated !== undefined &&
                        typeof controller.elevated !== "boolean"
                    ) {
                        throw new TypeError("SSH elevation policy result must be a boolean")
                    }
                    elevationResult = controller.elevated
                }
            }
            this.sendPacket(new UserAuthSuccess({}))
            this.hasAuthenticated = true
            this.activateAuthenticatedServerCompression()
            this.prepareAuthenticatedClientCompression()
            if (this.clientElevationRequest !== undefined && elevationResult !== undefined) {
                this.sendPacket(
                    new GlobalRequest({
                        request_name: ELEVATION_EXTENSION,
                        want_reply: false,
                        args: serializeBinaryBoolean(elevationResult),
                    }),
                )
            }
        } else {
            throw new DisconnectError(
                DisconnectReason.SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE,
                "No auth methods were successful.",
            )
        }
    }

    private async performGSSAPIAuthentication(
        authRequest: UserAuthRequest,
    ): Promise<GSSAPIAuthenticationResult> {
        const method = authRequest.data.method
        assert(method instanceof GSSAPIWithMICAuthMethod)
        const mechanism = method.data.mechanismOIDs
            .map((oid) =>
                this.server.options.gssapi.find(
                    (candidate) =>
                        candidate.createContext !== undefined && candidate.oid.equals(oid),
                ),
            )
            .find((candidate) => candidate !== undefined)
        if (!mechanism?.createContext) return { allowLogin: false }

        const packets = new PacketEventQueue(
            this,
            () => new Error("SSH connection closed during GSS-API authentication"),
        )
        let context: GSSAPIServerContext | undefined
        this.sendPacket(new UserAuthGSSAPIResponse(mechanism.oid))

        try {
            context = await mechanism.createContext(
                Object.freeze({
                    username: authRequest.data.username,
                    service: authRequest.data.service_name,
                    remoteAddress: this.socket.remoteAddress,
                    remotePort: this.socket.remotePort,
                }),
            )
            assertServerGSSAPIContext(context)
            while (true) {
                const packet = await waitForQueuedHigherLayerPacket(packets)
                if (packet instanceof UserAuthRequest) {
                    return { allowLogin: false, abandoned: true, pendingRequest: packet }
                }
                if (packet instanceof UserAuthGSSAPIErrorToken) {
                    try {
                        await context.step(packet.token)
                    } catch (error) {
                        this.debug("GSS-API mechanism rejected the client error token:", error)
                    }
                    const next = await waitForQueuedHigherLayerPacket(packets)
                    if (!(next instanceof UserAuthRequest)) {
                        throw new ProtocolError(
                            "GSS-API client error token was not followed by a new authentication request",
                        )
                    }
                    return { allowLogin: false, abandoned: true, pendingRequest: next }
                }
                if (
                    packet instanceof UserAuthGSSAPIMIC ||
                    packet instanceof UserAuthGSSAPIExchangeComplete
                ) {
                    return { allowLogin: false }
                }
                if (!(packet instanceof UserAuthGSSAPIToken)) {
                    throw new ProtocolError(
                        "Expected a GSS-API context token before context completion",
                    )
                }

                const step = normalizeGSSAPIContextStep(await context.step(packet.token))
                if (step.token) this.sendPacket(new UserAuthGSSAPIToken(step.token))
                if (!step.complete) continue
                const integrity = step.integrity!

                const acknowledgement = await waitForQueuedHigherLayerPacket(packets)
                if (acknowledgement instanceof UserAuthRequest) {
                    return {
                        allowLogin: false,
                        abandoned: true,
                        pendingRequest: acknowledgement,
                    }
                }
                if (acknowledgement instanceof UserAuthGSSAPIErrorToken) {
                    try {
                        await context.step(acknowledgement.token)
                    } catch (error) {
                        this.debug("GSS-API mechanism rejected the client error token:", error)
                    }
                    const next = await waitForQueuedHigherLayerPacket(packets)
                    if (!(next instanceof UserAuthRequest)) {
                        throw new ProtocolError(
                            "GSS-API client error token was not followed by a new authentication request",
                        )
                    }
                    return { allowLogin: false, abandoned: true, pendingRequest: next }
                }
                if (integrity) {
                    if (!(acknowledgement instanceof UserAuthGSSAPIMIC)) {
                        return { allowLogin: false }
                    }
                    assert(this.sessionID, "SSH session identifier is unavailable")
                    const micInput = buildGSSAPIUserAuthMIC(
                        this.sessionID,
                        authRequest.data.username,
                        authRequest.data.service_name,
                    )
                    if (!(await context.verifyMIC(micInput, acknowledgement.mic))) {
                        return { allowLogin: false }
                    }
                } else if (!(acknowledgement instanceof UserAuthGSSAPIExchangeComplete)) {
                    return { allowLogin: false }
                }

                const policyContext: ServerHookerGSSAPIAuthenticationContext = Object.freeze({
                    username: authRequest.data.username,
                    service: authRequest.data.service_name,
                    mechanismOID: Buffer.from(mechanism.oid),
                    integrity,
                    peerIdentity: step.peerIdentity,
                    delegatedCredentials: step.delegatedCredentials,
                })
                const controller: ServerHookerGSSAPIAuthenticationController = {
                    allowLogin: false,
                }
                const policyCompleted = await this.server.hooker.triggerHookChecked(
                    "gssapiAuthentication",
                    policyContext,
                    controller,
                    this,
                )
                return policyCompleted
                    ? { allowLogin: controller.allowLogin, continuation: controller }
                    : { allowLogin: false }
            }
        } catch (error) {
            if (error instanceof ProtocolError) throw error
            if (error instanceof GSSAPIError) {
                this.sendPacket(
                    new UserAuthGSSAPIError({
                        majorStatus: error.majorStatus,
                        minorStatus: error.minorStatus,
                        message: error.message,
                        languageTag: error.languageTag,
                    }),
                )
                if (error.token) this.sendPacket(new UserAuthGSSAPIErrorToken(error.token))
            } else {
                this.debug("GSS-API authentication mechanism failed:", error)
            }
            return { allowLogin: false }
        } finally {
            packets.close()
            if (context) {
                try {
                    await closeGSSAPIContext(context)
                } catch (error) {
                    this.debug("Could not close the GSS-API server context:", error)
                }
            }
        }
    }

    private async performGSSAPIKeyExchangeAuthentication(
        authRequest: UserAuthRequest,
    ): Promise<ServerHookerGSSAPIAuthenticationController> {
        const method = authRequest.data.method
        assert(method instanceof GSSAPIKeyExchangeAuthMethod)
        const context = this.initialGSSAPIKeyExchangeContext
        const step = this.initialGSSAPIKeyExchangeStep
        const mechanismOID = this.initialGSSAPIKeyExchangeMechanismOID
        const controller: ServerHookerGSSAPIAuthenticationController = { allowLogin: false }
        if (!context?.verifyMIC || !step || !mechanismOID || !this.sessionID) return controller

        this.initialGSSAPIKeyExchangeContext = undefined
        this.initialGSSAPIKeyExchangeStep = undefined
        this.initialGSSAPIKeyExchangeMechanismOID = undefined
        try {
            const micInput = buildGSSAPIKeyExchangeUserAuthMIC(
                this.sessionID,
                authRequest.data.username,
                authRequest.data.service_name,
            )
            if (!(await context.verifyMIC(micInput, method.mic))) return controller
            const policyContext: ServerHookerGSSAPIAuthenticationContext = Object.freeze({
                username: authRequest.data.username,
                service: authRequest.data.service_name,
                mechanismOID: Buffer.from(mechanismOID),
                integrity: true,
                peerIdentity: step.peerIdentity,
                delegatedCredentials: step.delegatedCredentials,
            })
            const policyCompleted = await this.server.hooker.triggerHookChecked(
                "gssapiAuthentication",
                policyContext,
                controller,
                this,
            )
            return policyCompleted ? controller : { allowLogin: false }
        } finally {
            await closeGSSAPIContext(context)
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
        const payload = packet.serialize()
        if (packet === this.serverKexInit) this.#serverKexInitPayload = Buffer.from(payload)
        const encoded = this.packetEncoder.encode(payload)
        this.socket!.write(encoded.data)
        this.checkRekeyByteLimit()
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

    private activateAuthenticatedServerCompression(): void {
        if (this.pendingDelayCompression) {
            this.serverCompressionAlgorithm = compression_algorithms.get(
                this.pendingDelayCompression.serverToClient,
            )
            assert(this.serverCompressionAlgorithm)
            this.installOutboundCompression()
        } else if (this.serverCompressionAlgorithm?.delayed) {
            this.installOutboundCompression()
        }
        this.delayCompressionRekeyBlocked = false
    }

    private prepareAuthenticatedClientCompression(): void {
        if (this.pendingDelayCompression) {
            this.awaitingClientNewCompress = true
            this.messagesBeforeNewCompress = 0
        } else if (this.clientCompressionAlgorithm?.delayed) {
            this.installInboundCompression()
        }
    }

    private activateClientCompression(): void {
        if (!this.awaitingClientNewCompress || !this.pendingDelayCompression) {
            throw new ProtocolError("SSH client sent an unexpected NEWCOMPRESS message")
        }
        this.clientCompressionAlgorithm = compression_algorithms.get(
            this.pendingDelayCompression.clientToServer,
        )
        assert(this.clientCompressionAlgorithm)
        this.installInboundCompression()
        this.awaitingClientNewCompress = false
        this.messagesBeforeNewCompress = 0
        this.pendingDelayCompression = undefined
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
        this.checkRekeyByteLimit()

        const { payload } = decoded
        this.emit("message", decoded.data)

        const packetType = payload[0] as PacketType
        this.debug("Receiving packet:", packetType)

        if (this.discardNextGuessedKeyExchangePacket) {
            this.discardNextGuessedKeyExchangePacket = false
            this.debug("Discarding incorrectly guessed key-exchange packet")
            if (this.packetDecoder.bufferedLength > 0) {
                this.scheduleMessageProcessing(Buffer.alloc(0))
            }
            return
        }
        this.validateKeyExchangePhase(packetType)
        this.validateClientExtInfoPosition(packetType)

        if (
            this.strictKeyExchange &&
            this.strictInitialExchange &&
            !isStrictKeyExchangePacket(packetType)
        ) {
            throw new KeyExchangeError("Received a non-KEX packet during strict key exchange")
        }
        if (this.awaitingClientNewCompress && packetType !== PacketNameToType.SSH_MSG_NEWCOMPRESS) {
            this.messagesBeforeNewCompress++
            if (this.messagesBeforeNewCompress > MAX_MESSAGES_BEFORE_NEWCOMPRESS) {
                throw new ProtocolError(
                    `SSH client did not send NEWCOMPRESS within ${MAX_MESSAGES_BEFORE_NEWCOMPRESS} messages`,
                )
            }
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
        this.validateKeyExchangeMessageBoundary(packetType)
        this.validateHigherLayerPhase(packetType)
        let p: Packet
        if (
            this.kexAlgorithm instanceof GSSAPIKeyExchange &&
            (packetType === KexGSSAPIInit.type || packetType === KexGSSAPIContinue.type)
        ) {
            p =
                packetType === KexGSSAPIInit.type
                    ? KexGSSAPIInit.parse(payload, this.kexAlgorithm.exchangeValueEncoding)
                    : KexGSSAPIContinue.parse(payload)
        } else {
            const packet =
                packetType === PacketNameToType.SSH_MSG_KEXDH_REPLY &&
                this.kexAlgorithm instanceof RSA2048SHA256
                    ? KexRSASecret
                    : packetType === PacketNameToType.SSH_MSG_KEXDH_INIT &&
                        this.kexAlgorithm instanceof DiffieHellmanGroupExchange
                      ? KexDHGexRequestOld
                      : packetType === PacketNameToType.SSH_MSG_USERAUTH_INFO_RESPONSE &&
                          this.activeAuthenticationMethod === SSHAuthenticationMethods.GSSAPIWithMIC
                        ? UserAuthGSSAPIToken
                        : packets[packetName as keyof typeof packets]
            p = packet.parse(payload)
        }
        if (p instanceof KexGSSAPIInit || p instanceof KexGSSAPIContinue) {
            this.packetProcessingPaused = true
        }
        if (p instanceof UserAuthRequest) {
            this.activeAuthenticationMethod = p.data.method.method_name
            this.authenticationRequestReceived = true
        }
        if (p instanceof KexInit) this.#clientKexInitPayload = Buffer.from(payload)
        if (p instanceof KexInit) this.peerKexInitReceived = true
        if (packetType === PacketNameToType.SSH_MSG_KEXINIT && this.strictInitialExchange) {
            const clientAlgorithms = (p as KexInit).data.kex_algorithms
            const negotiated = negotiatesStrictKeyExchange(
                clientAlgorithms,
                this.serverKexInit!.data.kex_algorithms,
            )
            this.strictKeyExchange ||= negotiated
            if (
                negotiated &&
                (decoded.sequenceNumber !== 0 ||
                    this.packetDecoder.hasSequenceNumberWrapped ||
                    this.packetEncoder.hasSequenceNumberWrapped)
            ) {
                throw new KeyExchangeError(
                    "Strict key exchange requires unwrapped sequence numbers and KEXINIT at packet zero",
                )
            }
        }
        if (this.strictKeyExchange && this.strictInitialExchange) {
            const repeatableGSSContinuation =
                this.kexAlgorithm instanceof GSSAPIKeyExchange &&
                packetType === KexGSSAPIContinue.type
            if (!repeatableGSSContinuation && this.strictInitialPackets.has(packetType)) {
                throw new KeyExchangeError("Received a duplicate packet during strict key exchange")
            }
            this.strictInitialPackets.add(packetType)
        }
        this.emit("packet", p)
        this.routeGlobalRequestReply(p)
        this.debug("Parsing packet:", this.packetForDebug(p))

        switch (packetType) {
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
                this.clientAuthenticationExtInfoSupported = this.negotiatedClientExtensions.some(
                    ({ name }) => name === AUTHENTICATION_EXT_INFO_EXTENSION,
                )
                this.clientElevationRequest = findElevationRequest(this.negotiatedClientExtensions)
                this.clientDelayCompressionOffers = findDelayCompressionOffers(
                    this.negotiatedClientExtensions,
                )
                this.updateDelayCompression()
                this.updateNoFlowControl()
                this.emit("clientExtensions", this.clientExtensions)
                break
            }

            case PacketNameToType.SSH_MSG_NEWCOMPRESS:
                this.activateClientCompression()
                break

            case PacketNameToType.SSH_MSG_PING: {
                const ping = p as Ping
                this.sendPacket(new Pong({ data: ping.data.data }))
                break
            }

            case PacketNameToType.SSH_MSG_PONG:
                break

            case PacketNameToType.SSH_MSG_KEXINIT:
                if (this.sessionID !== undefined && !this.keyExchangeInProgress) {
                    void this.performKeyExchange(true).catch((error: Error) => {
                        this.emit("error", error)
                        this.terminate()
                    })
                }
                this.emit("clientKexInit", p as KexInit, this.clientKexInitPayload!)
                break

            case PacketNameToType.SSH_MSG_KEXDH_INIT:
                if (p instanceof KexGSSAPIInit) {
                    break
                } else if (p instanceof KexDHGexRequestOld) {
                    this.emit("clientKexDHGexRequest", p)
                } else {
                    this.emit("clientKexDHInit", p as KexDHInit)
                    this.packetProcessingPaused = true
                }
                break

            case PacketNameToType.SSH_MSG_KEXDH_REPLY:
                if (p instanceof KexGSSAPIContinue) break
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
                this.inboundNewKeysReady = false
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

    private validateKeyExchangePhase(packetType: PacketType): void {
        const exchangeOnly =
            packetType === PacketNameToType.SSH_MSG_NEWKEYS ||
            packetType === PacketNameToType.SSH_MSG_KEXDH_INIT ||
            packetType === PacketNameToType.SSH_MSG_KEXDH_REPLY ||
            packetType === PacketNameToType.SSH_MSG_KEX_DH_GEX_INIT ||
            packetType === PacketNameToType.SSH_MSG_KEX_DH_GEX_REPLY ||
            packetType === PacketNameToType.SSH_MSG_KEX_DH_GEX_REQUEST
        if (packetType === PacketNameToType.SSH_MSG_KEXINIT) {
            if (!this.keyExchangeInProgress) return
            if (!this.expectedInboundKeyExchangePackets.delete(packetType)) {
                throw new DisconnectError(
                    DisconnectReason.SSH_DISCONNECT_PROTOCOL_ERROR,
                    "SSH client sent an unexpected KEXINIT during key exchange",
                )
            }
            return
        }
        if (exchangeOnly && !this.keyExchangeInProgress) {
            throw new DisconnectError(
                DisconnectReason.SSH_DISCONNECT_PROTOCOL_ERROR,
                "SSH client sent a key-exchange message outside key exchange",
            )
        }
        if (packetType === PacketNameToType.SSH_MSG_NEWKEYS && !this.inboundNewKeysReady) {
            throw new DisconnectError(
                DisconnectReason.SSH_DISCONNECT_PROTOCOL_ERROR,
                "SSH client sent NEWKEYS before fresh inbound keys were ready",
            )
        }
        if (exchangeOnly && !this.expectedInboundKeyExchangePackets.delete(packetType)) {
            throw new DisconnectError(
                DisconnectReason.SSH_DISCONNECT_PROTOCOL_ERROR,
                "SSH client sent an out-of-order key-exchange message",
            )
        }
    }

    private validateKeyExchangeMessageBoundary(packetType: PacketType): void {
        if (!this.peerKexInitReceived || this.hasReceivedNewKeys) return
        const genericTransport = packetType >= 1 && packetType <= 19
        const serviceMessage =
            packetType === PacketNameToType.SSH_MSG_SERVICE_REQUEST ||
            packetType === PacketNameToType.SSH_MSG_SERVICE_ACCEPT
        const keyExchangeMessage = packetType >= 20 && packetType <= 49
        if ((genericTransport && !serviceMessage) || keyExchangeMessage) return
        throw new DisconnectError(
            DisconnectReason.SSH_DISCONNECT_PROTOCOL_ERROR,
            "SSH client sent a non-key-exchange message after KEXINIT",
        )
    }

    private expectInboundKeyExchange(...packetTypes: PacketType[]): void {
        this.expectedInboundKeyExchangePackets.clear()
        for (const packetType of packetTypes) {
            this.expectedInboundKeyExchangePackets.add(packetType)
        }
    }

    private shouldDiscardGuessedPacket(peerKexInit: KexInit): boolean {
        if (!peerKexInit.data.first_kex_packet_follows) return false
        const negotiatedKex = (this.kexAlgorithm!.constructor as typeof KexAlgorithm).alg_name
        return (
            peerKexInit.data.kex_algorithms[0] !== negotiatedKex ||
            peerKexInit.data.server_host_key_algorithms[0] !== this.hostKeyAlgorithm!.alg_name
        )
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
                packetType !== PacketNameToType.SSH_MSG_USERAUTH_INFO_RESPONSE &&
                !(
                    this.activeAuthenticationMethod === SSHAuthenticationMethods.GSSAPIWithMIC &&
                    (packetType === PacketNameToType.SSH_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE ||
                        packetType === PacketNameToType.SSH_MSG_USERAUTH_GSSAPI_ERRTOK ||
                        packetType === PacketNameToType.SSH_MSG_USERAUTH_GSSAPI_MIC)
                )
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

    private resetKeepalive(): void {
        this.clearKeepalive()
        this.unansweredKeepalives = 0
        this.scheduleKeepalive()
    }

    private clearHandshakeTimeout(): void {
        if (this.handshakeTimer !== undefined) clearTimeout(this.handshakeTimer)
        this.handshakeTimer = undefined
    }

    private startHandshakeTimeout(): void {
        if (this.server.options.handshakeTimeout === 0) return
        this.handshakeTimer = setTimeout(() => {
            this.socket.destroy(new Error("Timed out while waiting for SSH handshake"))
        }, this.server.options.handshakeTimeout)
        this.handshakeTimer.unref()
    }

    private scheduleKeepalive(): void {
        if (this.server.options.keepaliveInterval === 0 || !this.isConnected) return
        this.keepaliveTimer = setTimeout(
            () => this.sendKeepalive(),
            this.server.options.keepaliveInterval,
        )
        this.keepaliveTimer.unref()
    }

    private clearKeepalive(): void {
        if (this.keepaliveTimer !== undefined) clearTimeout(this.keepaliveTimer)
        this.keepaliveTimer = undefined
    }

    private resetRekeyTimer(): void {
        this.clearRekeyTimer()
        if (
            this.server.options.rekeyInterval === 0 ||
            this.sessionID === undefined ||
            this.socket.destroyed
        ) {
            return
        }
        this.rekeyTimer = setTimeout(
            () => this.scheduleAutomaticRekey("time limit"),
            this.server.options.rekeyInterval,
        )
        this.rekeyTimer.unref()
    }

    private clearRekeyTimer(): void {
        if (this.rekeyTimer !== undefined) clearTimeout(this.rekeyTimer)
        this.rekeyTimer = undefined
    }

    private checkRekeyByteLimit(): void {
        const limit = this.server.options.rekeyBytes
        if (
            limit > 0 &&
            (this.packetEncoder.bytesProtected >= limit ||
                this.packetDecoder.bytesProtected >= limit)
        ) {
            this.scheduleAutomaticRekey("byte limit")
        }
    }

    private scheduleAutomaticRekey(reason: string): void {
        this.clearRekeyTimer()
        if (
            this.automaticRekeyScheduled ||
            this.keyExchangeInProgress ||
            this.sessionID === undefined ||
            this.socket.destroyed
        ) {
            return
        }
        this.automaticRekeyScheduled = true
        queueMicrotask(() => {
            this.automaticRekeyScheduled = false
            if (this.keyExchangeInProgress || this.socket.destroyed) return
            this.debug(`Starting automatic SSH rekey after ${reason}`)
            void this.rekey().catch((error: unknown) => {
                this.debug("Automatic SSH rekey failed:", error)
            })
        })
    }

    private sendKeepalive(): void {
        this.keepaliveTimer = undefined
        if (!this.isConnected) return
        this.unansweredKeepalives++
        if (this.unansweredKeepalives > this.server.options.keepaliveCountMax) {
            this.emit("error", new Error("SSH keepalive timeout"))
            this.terminate()
            return
        }

        void this.globalRequest("keepalive@openssh.com").then(
            () => this.resetKeepalive(),
            (error: unknown) => {
                if (error instanceof ServerGlobalRequestError) this.resetKeepalive()
            },
        )
        this.scheduleKeepalive()
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
        if (
            packet instanceof UserAuthGSSAPIToken ||
            packet instanceof UserAuthGSSAPIErrorToken ||
            packet instanceof UserAuthGSSAPIMIC
        ) {
            return {
                type: packet.constructor.name,
                token: "<redacted>",
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

function assertServerGSSAPIContext(context: unknown): asserts context is GSSAPIServerContext {
    if (
        typeof context !== "object" ||
        context === null ||
        typeof (context as { step?: unknown }).step !== "function" ||
        typeof (context as { verifyMIC?: unknown }).verifyMIC !== "function"
    ) {
        throw new TypeError("Invalid SSH server GSS-API context")
    }
}

function assertServerGSSAPIKeyExchangeContext(
    context: unknown,
): asserts context is GSSAPIKeyExchangeServerContext {
    if (
        typeof context !== "object" ||
        context === null ||
        typeof (context as { step?: unknown }).step !== "function" ||
        typeof (context as { getMIC?: unknown }).getMIC !== "function" ||
        ("verifyMIC" in context &&
            context.verifyMIC !== undefined &&
            typeof context.verifyMIC !== "function") ||
        ("close" in context && context.close !== undefined && typeof context.close !== "function")
    ) {
        throw new TypeError("Invalid SSH server GSS-API key-exchange context")
    }
}

function requireGSSAPIKeyExchangeToken(token: Buffer | undefined): Buffer {
    if (!token) {
        throw new KeyExchangeError("GSS-API context step did not produce a required token")
    }
    return normalizeGSSAPIToken(token)
}

async function waitForQueuedHigherLayerPacket(packets: PacketEventQueue): Promise<Packet> {
    while (true) {
        const packet = await packets.next()
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
