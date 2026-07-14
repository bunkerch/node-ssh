import crypto from "crypto"
import EventEmitter from "node:events"
import net from "node:net"
import type { Duplex } from "node:stream"
import {
    SocketState,
    SSHAuthenticationMethods,
    PacketNameToType,
    SSHServiceNames,
    PacketType,
    PacketTypeToName,
} from "./constants.js"
import ProtocolVersionExchange from "./ProtocolVersionExchange.js"
import assert from "node:assert"
import Packet, { packets, Packets } from "./packet.js"
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
    encryption_algorithms,
    host_key_algorithms,
    kex_algorithms,
    mac_algorithms,
    type HostKeyAlgorithm,
    type CompressionAlgorithm,
    default_algorithm_names,
} from "./algorithms.js"
import KexDHInit from "./packets/KexDHInit.js"
import KexDHReply from "./packets/KexDHReply.js"
import KexDHGexGroup from "./packets/KexDHGexGroup.js"
import KexDHGexInit from "./packets/KexDHGexInit.js"
import KexDHGexReply from "./packets/KexDHGexReply.js"
import KexDHGexRequest from "./packets/KexDHGexRequest.js"
import {
    defaultGroupExchangeRequest,
    DiffieHellmanGroupExchange,
} from "./algorithms/kex/diffie-hellman-group-exchange.js"
import EncodedSignature from "./utils/Signature.js"
import ExtInfo, { copySSHExtensions, type SSHExtension } from "./packets/ExtInfo.js"
import Ping from "./packets/Ping.js"
import Pong from "./packets/Pong.js"
import PublicKey, { SSHCertificatePublicKey } from "./utils/PublicKey.js"
import { Hooker } from "./utils/Hooker.js"
import NewKeys from "./packets/NewKeys.js"
import { KeyExchangeError } from "./algorithms/kex/key-exchange.js"
import RSA2048SHA256 from "./algorithms/kex/rsa2048-sha256.js"
import KexRSAPublicKey from "./packets/KexRSAPublicKey.js"
import KexRSASecret from "./packets/KexRSASecret.js"
import KexRSADone from "./packets/KexRSADone.js"
import UserAuthRequest from "./packets/UserAuthRequest.js"
import Disconnect, {
    DisconnectError,
    DisconnectReason,
    PeerDisconnectError,
    ProtocolError,
    peerDisconnectInfo,
    type PeerDisconnectInfo,
} from "./packets/Disconnect.js"
import ServiceRequest from "./packets/ServiceRequest.js"
import ServiceAccept from "./packets/ServiceAccept.js"
import Agent from "./publickey/Agent.js"
import NoneAgent from "./publickey/NoneAgent.js"
import GlobalRequest from "./packets/GlobalRequest.js"
import RequestFailure from "./packets/RequestFailure.js"
import RequestSuccess from "./packets/RequestSuccess.js"
import Debug, { protocolDebugMessage, type ProtocolDebugMessage } from "./packets/Debug.js"
import Ignore from "./packets/Ignore.js"
import Unimplemented from "./packets/Unimplemented.js"
import { readNextBuffer, readNextUint32, serializeBuffer, serializeUint32 } from "./utils/Buffer.js"
import IdentificationParser from "./IdentificationParser.js"
import { BinaryPacketDecoder, BinaryPacketEncoder } from "./BinaryPacket.js"
import {
    isStrictKeyExchangePacket,
    negotiatesStrictKeyExchange,
    STRICT_KEX_CLIENT_MARKERS,
} from "./StrictKeyExchange.js"
import ClientChannel from "./channels/ClientChannel.js"
import ClientSessionChannel from "./channels/ClientSessionChannel.js"
import type { ClientPtyOptions, ClientX11Options } from "./channels/ClientSessionChannel.js"
import ClientTCPIPChannel from "./channels/ClientTCPIPChannel.js"
import ClientForwardedTCPIPChannel from "./channels/ClientForwardedTCPIPChannel.js"
import ClientDirectStreamLocalChannel from "./channels/ClientDirectStreamLocalChannel.js"
import ClientForwardedStreamLocalChannel, {
    StreamLocalConnectionDetails,
} from "./channels/ClientForwardedStreamLocalChannel.js"
import ClientAgentChannel from "./channels/ClientAgentChannel.js"
import ClientTunnelChannel from "./channels/ClientTunnelChannel.js"
import { AUTOMATIC_TUNNEL_UNIT, type TunnelMode } from "./channels/Tunnel.js"
import ClientX11Channel, { X11ConnectionDetails } from "./channels/ClientX11Channel.js"
import type { TCPIPConnectionDetails } from "./channels/ClientTCPIPChannel.js"
import ChannelOpen from "./packets/ChannelOpen.js"
import ChannelOpenConfirmation from "./packets/ChannelOpenConfirmation.js"
import ChannelOpenFailure, { ChannelOpenFailureReasonCodes } from "./packets/ChannelOpenFailure.js"
import ChannelWindowAdjust from "./packets/ChannelWindowAdjust.js"
import ChannelData from "./packets/ChannelData.js"
import ChannelExtendedData from "./packets/ChannelExtendedData.js"
import ChannelEOF from "./packets/ChannelEOF.js"
import ChannelClose from "./packets/ChannelClose.js"
import ChannelRequest from "./packets/ChannelRequest.js"
import ChannelSuccess from "./packets/ChannelSuccess.js"
import ChannelFailure from "./packets/ChannelFailure.js"
import UserAuthBanner from "./packets/UserAuthBanner.js"
import UserAuthFailure from "./packets/UserAuthFailure.js"
import UserAuthPKOK from "./packets/UserAuthPKOK.js"
import UserAuthPasswordChangeRequest from "./packets/UserAuthPasswordChangeRequest.js"
import UserAuthInfoRequest, { UserAuthPrompt } from "./packets/UserAuthInfoRequest.js"
import UserAuthInfoResponse from "./packets/UserAuthInfoResponse.js"
import SFTPClient from "./sftp/SFTPClient.js"
import {
    resolveClientAlgorithmOptions,
    type ClientAlgorithmOptions,
    type NegotiatedAlgorithms,
    type ResolvedAlgorithmOptions,
} from "./AlgorithmOptions.js"
import PrivateKey from "./utils/PrivateKey.js"
import { parseHostKeysProofResponse } from "./utils/HostKeysProof.js"
import { ActionQueue } from "./utils/ActionQueue.js"
import PrivateKeyAgent from "./publickey/PrivateKeyAgent.js"
import SSHAgent from "./publickey/SSHAgent.js"
import { parseKey } from "./KeyParsing.js"

export interface ClientHostbasedOptions {
    key: PrivateKey
    localHostname: string
    localUsername: string
    /** Signature algorithm; defaults to the strongest algorithm supported by the key. */
    algorithm?: string
}

export interface ClientOptions {
    hostname?: string
    port?: number
    /** Local address to bind for a new TCP connection. Ignored when `sock` is supplied. */
    localAddress?: string
    /** Local port to bind for a new TCP connection. Ignored when `sock` is supplied. */
    localPort?: number
    /** Resolve `hostname` to IPv4 only. Has no effect when `forceIPv6` is also true. */
    forceIPv4?: boolean
    /** Resolve `hostname` to IPv6 only. Has no effect when `forceIPv4` is also true. */
    forceIPv6?: boolean
    /** Node.js hash name used to hex-encode the key passed to `hostVerifier`. */
    hostHash?: string
    /** Verify the raw serialized host key, or its `hostHash` digest, before NEWKEYS. */
    hostVerifier?: ClientHostVerifier
    /** Custom SSH software identifier and optional comments, without the `SSH-2.0-` prefix. */
    ident?: string | Buffer
    /** Reject OpenSSH-specific APIs for peers without a compatible OpenSSH identifier. */
    strictVendor?: boolean
    algorithms?: ClientAlgorithmOptions
    username?: string
    password?: string
    /** Signing agent object, or a UNIX-domain agent socket path. */
    agent?: Agent | string
    /** Request agent forwarding by default for exec and shell sessions. */
    agentForward?: boolean
    /** Private key object or encoded private-key container used for public-key authentication. */
    privateKey?: PrivateKey | string | Buffer
    /** Certificate public key paired with `privateKey` for certificate authentication. */
    certificate?: PublicKey | string | Buffer
    /** Passphrase for an encoded `privateKey`. */
    passphrase?: string | Buffer
    /** RFC 4252 host-based authentication identity. */
    hostbased?: ClientHostbasedOptions
    protocolVersionExchange?: ProtocolVersionExchange
    serverClient?: boolean
    authenticationMethodsOrder?: SSHAuthenticationMethods[]
    keepaliveInterval?: number
    keepaliveCountMax?: number
    /** Maximum milliseconds for TCP connection, SSH handshake, and authentication. Zero disables. */
    readyTimeout?: number
    /** Already-connected duplex transport, such as an SSH direct-tcpip channel. */
    sock?: Duplex
    /** Receive the same already-redacted diagnostic arguments as the `debug` event. */
    debug?: (...message: unknown[]) => void
}

export interface ClientOptionsRequired
    extends Required<
        Omit<
            ClientOptions,
            | "sock"
            | "localAddress"
            | "localPort"
            | "hostHash"
            | "hostVerifier"
            | "hostbased"
            | "ident"
            | "algorithms"
            | "privateKey"
            | "certificate"
            | "passphrase"
            | "agent"
            | "debug"
        >
    > {
    sock?: Duplex
    localAddress?: string
    localPort?: number
    hostHash?: string
    hostVerifier?: ClientHostVerifier
    hostbased?: ClientHostbasedOptions
    ident?: string | Buffer
    algorithms?: ClientAlgorithmOptions
    privateKey?: PrivateKey | string | Buffer
    certificate?: PublicKey | string | Buffer
    passphrase?: string | Buffer
    agent: Agent
    debug?: (...message: unknown[]) => void
}

export type ClientHostVerifier = (
    key: Buffer | string,
    callback: (verified: boolean) => void,
) => boolean | void

export interface ClientEvents {
    debug: [...message: unknown[]]
    error: [error: Error]
    close: []
    /** Authenticated or unauthenticated terminal disconnect received from the peer. */
    disconnect: [info: Readonly<PeerDisconnectInfo>]
    /** Human-readable transport diagnostic sent by the peer. */
    protocolDebug: [info: Readonly<ProtocolDebugMessage>]
    connect: []
    message: [message: Buffer]
    packet: [packet: Packet]
    /** Host keys whose ownership was cryptographically proved for this connection. */
    hostKeys: [publicKeys: readonly PublicKey[]]
    tcpWrapperLog: [message: string]
    serverProtocolVersion: [protocolVersion: ProtocolVersionExchange]
    serverKexInit: [serverKexInit: KexInit, payload: Buffer]
    serverKexDHReply: [serverKexDHReply: KexDHReply]
    serverKexDHGexGroup: [group: KexDHGexGroup]
    serverKexDHGexReply: [reply: KexDHGexReply]
    serverKexRSAPublicKey: [publicKey: KexRSAPublicKey]
    serverKexRSADone: [done: KexRSADone]
    clientNewKeys: []
    serverNewKeys: []
    handshake: [negotiated: Readonly<NegotiatedAlgorithms>]
    rekey: []
    /** Complete server pre-identification greeting, including its line endings. */
    greeting: [greeting: string]
    banner: [message: string, languageTag: string]
    /** Complete replacement set from the latest valid server EXT_INFO message. */
    serverExtensions: [extensions: readonly Readonly<SSHExtension>[]]
    "tcp connection": [
        details: Readonly<TCPIPConnectionDetails>,
        accept: () => ClientForwardedTCPIPChannel | undefined,
        reject: () => void,
    ]
    "unix connection": [
        details: Readonly<StreamLocalConnectionDetails>,
        accept: () => ClientForwardedStreamLocalChannel | undefined,
        reject: () => void,
    ]
    x11: [
        details: Readonly<X11ConnectionDetails>,
        accept: () => ClientX11Channel | undefined,
        reject: () => void,
    ]
}

export interface ClientHookerHostKeyController {
    allowHostKey: boolean
}
export type ClientHookerPasswordAuthContext = Readonly<{
    username: string
}>
export interface ClientHookerPasswordAuthController {
    password: string | undefined
}
export type ClientHookerPasswordChangeContext = Readonly<{
    username: string
    prompt: string
    languageTag: string
}>
export interface ClientHookerPasswordChangeController {
    newPassword: string | undefined
}
export type ClientHookerKeyboardInteractiveContext = Readonly<{
    username: string
    name: string
    instruction: string
    languageTag: string
    prompts: readonly Readonly<UserAuthPrompt>[]
    round: number
}>
export interface ClientHookerKeyboardInteractiveController {
    responses: string[] | undefined
}
export type ClientHookerGlobalRequestContext = Readonly<{
    name: string
    args: Buffer
    wantReply: boolean
}>
export interface ClientHookerGlobalRequestController {
    success: boolean
    response?: Buffer
}
export type ClientHookerAuthenticationMethodContext = Readonly<{
    /** Configured methods that have already failed during the current authentication stage. */
    attemptedMethods: readonly SSHAuthenticationMethods[]
    /** Method the configured order would select when the hook does not override it. */
    defaultMethod: SSHAuthenticationMethods
    /** The latest server continuation list, or undefined before the first failure. */
    methodsRemaining: readonly SSHAuthenticationMethods[] | undefined
    /** Whether the server accepted a factor before entering the current stage. */
    partialSuccess: boolean
}>
export interface ClientHookerAuthenticationMethodController {
    /** Select the next method, or set undefined to stop authentication. */
    method: SSHAuthenticationMethods | undefined
}
// eslint-disable-next-line @typescript-eslint/consistent-type-definitions
export type ClientHooker = {
    // `serverPublicKey` is the second argument because
    // in some cases, you don't actually need it
    // i.e. when blindly trusting the server public key.
    hostKey: [hostKeyController: ClientHookerHostKeyController, serverPublicKey: PublicKey]
    passwordAuth: [
        passwordAuthContext: ClientHookerPasswordAuthContext,
        passwordAuthController: ClientHookerPasswordAuthController,
    ]
    passwordChange: [
        passwordChangeContext: ClientHookerPasswordChangeContext,
        passwordChangeController: ClientHookerPasswordChangeController,
    ]
    keyboardInteractive: [
        keyboardInteractiveContext: ClientHookerKeyboardInteractiveContext,
        keyboardInteractiveController: ClientHookerKeyboardInteractiveController,
    ]
    authenticationMethod: [
        authenticationMethodContext: ClientHookerAuthenticationMethodContext,
        authenticationMethodController: ClientHookerAuthenticationMethodController,
    ]
    globalRequest: [
        globalRequestContext: ClientHookerGlobalRequestContext,
        globalRequestController: ClientHookerGlobalRequestController,
    ]
}

export type ClientChannelCallback<T extends ClientChannel = ClientChannel> = (
    error: Error | undefined,
    channel?: T,
) => void
export type ClientSessionCallback = ClientChannelCallback<ClientSessionChannel>
export type ClientSFTPCallback = (error: Error | undefined, sftp?: SFTPClient) => void
export type ClientForwardCallback = ClientChannelCallback<ClientTCPIPChannel>
export type ClientForwardInCallback = (error: Error | undefined, port?: number) => void
export type ClientStreamLocalCallback = ClientChannelCallback<ClientDirectStreamLocalChannel>
export type ClientPingCallback = (error: Error | undefined, data?: Buffer) => void
export type ClientGlobalRequestCallback = (error: Error | undefined, response?: Buffer) => void
export type ClientEnvironment = Readonly<Record<string, string>>
export interface ClientSessionOptions {
    agentForward?: boolean
    allowHalfOpen?: boolean
    env?: ClientEnvironment
    pty?: boolean | ClientPtyOptions
    x11?: boolean | number | ClientX11Options
}

export class GlobalRequestError extends Error {
    name = "GlobalRequestError"
}

interface PendingGlobalRequest {
    name: string
    resolve: (args: Buffer) => void
    reject: (error: Error) => void
}

interface PendingPing {
    data: Buffer
    resolve: (data: Buffer) => void
    reject: (error: Error) => void
}

interface RemoteForwarding {
    bindAddress: string
    bindPort: number
}

export default class Client extends EventEmitter<ClientEvents> {
    options: ClientOptionsRequired
    peerDisconnect?: Readonly<PeerDisconnectInfo>
    private readonly explicitAuthenticationMethodsOrder: boolean

    constructor(options: ClientOptions) {
        super()

        this.explicitAuthenticationMethodsOrder = options.authenticationMethodsOrder !== undefined
        this.options = { ...options } as ClientOptionsRequired
        this.options.hostname ??= "localhost"
        this.options.port ??= 22
        this.options.forceIPv4 ??= false
        this.options.forceIPv6 ??= false
        this.options.strictVendor ??= true
        this.options.username ??= "root"
        this.options.password ??= ""
        if (this.options.debug !== undefined && typeof this.options.debug !== "function") {
            throw new TypeError("SSH debug option must be a function")
        }
        this.options.agentForward ??= false
        if (typeof this.options.agent === "string") {
            this.options.agent = new SSHAgent(this.options.agent)
        }
        if (this.options.agent !== undefined && this.options.privateKey !== undefined) {
            throw new TypeError("SSH agent and privateKey options are mutually exclusive")
        }
        if (this.options.certificate !== undefined && this.options.privateKey === undefined) {
            throw new TypeError("SSH certificate option requires privateKey")
        }
        if (this.options.privateKey !== undefined) {
            if (
                this.options.privateKey instanceof PrivateKey &&
                this.options.passphrase !== undefined
            ) {
                throw new TypeError("SSH passphrase is only valid for an encoded privateKey")
            }
            const key =
                this.options.privateKey instanceof PrivateKey
                    ? this.options.privateKey
                    : parseKey(this.options.privateKey, this.options.passphrase)
            if (!(key instanceof PrivateKey)) {
                throw new TypeError("SSH privateKey option must contain a private key")
            }
            let authenticationKey = key
            if (this.options.certificate !== undefined) {
                const certificate =
                    this.options.certificate instanceof PublicKey
                        ? this.options.certificate
                        : parseKey(this.options.certificate)
                if (!(certificate instanceof PublicKey)) {
                    throw new TypeError("SSH certificate option must contain a public key")
                }
                authenticationKey = key.withCertificate(certificate)
            }
            this.options.agent = new PrivateKeyAgent(authenticationKey)
            this.options.privateKey = undefined
            this.options.certificate = undefined
            this.options.passphrase = undefined
        } else if (this.options.passphrase !== undefined) {
            throw new TypeError("SSH passphrase option requires privateKey")
        }
        this.options.agent ??= new NoneAgent()
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
        this.options.authenticationMethodsOrder ??= [
            SSHAuthenticationMethods.None,
            SSHAuthenticationMethods.PublicKey,
            SSHAuthenticationMethods.Password,
            SSHAuthenticationMethods.Hostbased,
        ]
        this.options.keepaliveInterval ??= 0
        this.options.keepaliveCountMax ??= 3
        this.options.readyTimeout ??= 20_000
        if (
            !Number.isFinite(this.options.keepaliveInterval) ||
            this.options.keepaliveInterval < 0
        ) {
            throw new RangeError("SSH keepalive interval must be a non-negative number")
        }
        if (
            !Number.isInteger(this.options.keepaliveCountMax) ||
            this.options.keepaliveCountMax < 0
        ) {
            throw new RangeError("SSH keepalive count maximum must be a non-negative integer")
        }
        if (!Number.isFinite(this.options.readyTimeout) || this.options.readyTimeout < 0) {
            throw new RangeError("SSH ready timeout must be a non-negative number")
        }
        if (
            this.options.localPort !== undefined &&
            (!Number.isInteger(this.options.localPort) ||
                this.options.localPort < 0 ||
                this.options.localPort > 65_535)
        ) {
            throw new RangeError("SSH local port must be an integer between 0 and 65535")
        }
        if (this.options.hostHash !== undefined) {
            try {
                crypto.createHash(this.options.hostHash)
            } catch {
                throw new RangeError(
                    `Unsupported SSH host hash algorithm: ${this.options.hostHash}`,
                )
            }
        }
        this.algorithmOffer = resolveClientAlgorithmOptions(
            this.options.algorithms,
            {
                kex: [...kex_algorithms.keys()],
                serverHostKey: [...host_key_algorithms.keys()],
                cipher: [...encryption_algorithms.keys()],
                hmac: [...mac_algorithms.keys()],
                compress: [...compression_algorithms.keys()],
            },
            default_algorithm_names,
        )

        setImmediate(() => {
            this.debug("Client created with options:", {
                ...this.options,
                password: this.options.password ? "<redacted>" : "",
                privateKey: undefined,
                certificate: undefined,
                passphrase: undefined,
                agent: this.options.agent.constructor.name,
                debug: this.options.debug ? "<configured>" : undefined,
            })
        })

        if (this.options.password) {
            this.hooker.hook("passwordAuth", async (controller, context, answer) => {
                // should not happen, but we've been given a
                // pair of username and password, we want them
                // to be used together.
                if (context.username != this.options.username) return
                answer.password = this.options.password
            })

            setImmediate(() => {
                this.debug("Password authentication handled by client options")
            })
        }
    }

    hooker = new Hooker<ClientHooker>()

    private socket?: Duplex
    private identificationParser = new IdentificationParser({ allowPreamble: true })
    private readonly greetingChunks: Buffer[] = []
    readonly algorithmOffer: ResolvedAlgorithmOptions
    private packetDecoder = new BinaryPacketDecoder()
    private packetEncoder = new BinaryPacketEncoder()
    private packetProcessingPaused = false
    private strictKeyExchange = false
    private strictInitialExchange = false
    private readonly strictInitialPackets = new Set<PacketType>()

    serverProtocolVersion?: ProtocolVersionExchange
    serverKexDHReply?: KexDHReply
    // TODO: Assess if these should be private properties
    clientKexInit?: KexInit
    serverKexInit?: KexInit
    kexAlgorithm?: KexAlgorithm
    hostKeyAlgorithm?: HostKeyAlgorithm
    serverSignatureAlgorithms?: readonly string[]
    private negotiatedServerHostKey?: Buffer
    private hostboundAuthenticationSupported = false
    private negotiatedServerExtensions: readonly Readonly<SSHExtension>[] = Object.freeze([])
    private initialServerNewKeysReceived = false
    private serverExtInfoAfterNewKeys = false
    private serverExtInfoMustPrecedeSuccess = false
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
    activeAuthenticationMethod?: SSHAuthenticationMethods
    authenticationMethodsRemaining?: ReadonlySet<SSHAuthenticationMethods>
    partialAuthenticationSuccess = false
    private authenticationFailureSequence = 0
    private awaitingServiceAccept = false
    private authenticationInProgress = false

    localChannelIndex = 0
    channels = new Map<number, ClientChannel>()
    private readonly remoteChannelIds = new Set<number>()
    private readonly pendingGlobalRequests: PendingGlobalRequest[] = []
    private readonly pendingPings: PendingPing[] = []
    private transportPingSupported = false
    private readonly remoteForwardings = new Map<string, RemoteForwarding>()
    private readonly remoteStreamLocalForwardings = new Set<string>()
    private readonly x11Forwardings = new Map<number, { single: boolean }>()
    agentForwardingEnabled = false
    private keepaliveTimer?: ReturnType<typeof setTimeout>
    private unansweredKeepalives = 0
    private readyTimer?: ReturnType<typeof setTimeout>
    private keyExchangeInProgress = false
    private readonly packetsQueuedDuringKeyExchange: Packet[] = []
    private readonly actionQueue = new ActionQueue()

    get serverHostKey(): Buffer | undefined {
        return this.negotiatedServerHostKey ? Buffer.from(this.negotiatedServerHostKey) : undefined
    }

    get hostboundPublicKeyAuthentication(): boolean {
        return this.hostboundAuthenticationSupported
    }

    get serverExtensions(): readonly Readonly<SSHExtension>[] {
        return copySSHExtensions(this.negotiatedServerExtensions)
    }

    registerX11Forwarding(sessionId: number, single: boolean): void {
        this.x11Forwardings.set(sessionId, { single })
    }

    unregisterX11Forwarding(sessionId: number): void {
        this.x11Forwardings.delete(sessionId)
    }

    state = SocketState.Closed
    get isConnected(): boolean {
        return this.state === SocketState.Connected
    }
    get canConnect(): boolean {
        return this.state === SocketState.Closed
    }

    private resetConnectionState(): void {
        this.peerDisconnect = undefined
        this.identificationParser = new IdentificationParser({ allowPreamble: true })
        this.greetingChunks.length = 0
        this.packetDecoder = new BinaryPacketDecoder()
        this.packetEncoder = new BinaryPacketEncoder()
        this.packetProcessingPaused = false
        this.strictKeyExchange = false
        this.strictInitialExchange = false
        this.strictInitialPackets.clear()

        this.serverProtocolVersion = undefined
        this.serverKexDHReply = undefined
        this.clientKexInit = undefined
        this.serverKexInit = undefined
        this.kexAlgorithm = undefined
        this.hostKeyAlgorithm = undefined
        this.serverSignatureAlgorithms = undefined
        this.negotiatedServerHostKey = undefined
        this.hostboundAuthenticationSupported = false
        this.negotiatedServerExtensions = Object.freeze([])
        this.initialServerNewKeysReceived = false
        this.serverExtInfoAfterNewKeys = false
        this.serverExtInfoMustPrecedeSuccess = false
        this.clientEncryptionAlgorithm = undefined
        this.serverEncryptionAlgorithm = undefined
        this.clientEncryption = undefined
        this.serverEncryption = undefined
        this.clientMacAlgorithm = undefined
        this.serverMacAlgorithm = undefined
        this.clientMac = undefined
        this.serverMac = undefined
        this.clientCompressionAlgorithm = undefined
        this.serverCompressionAlgorithm = undefined

        this.H = undefined
        this.sessionID = undefined
        this.ivClientToServer = undefined
        this.ivServerToClient = undefined
        this.encryptionKeyClientToServer = undefined
        this.encryptionKeyServerToClient = undefined
        this.integrityKeyClientToServer = undefined
        this.integrityKeyServerToClient = undefined
        this.hasReceivedNewKeys = false
        this.hasSentNewKeys = false
        this.hasAuthenticated = false
        this.activeAuthenticationMethod = undefined
        this.authenticationMethodsRemaining = undefined
        this.partialAuthenticationSuccess = false
        this.authenticationFailureSequence = 0
        this.awaitingServiceAccept = false
        this.authenticationInProgress = false

        this.localChannelIndex = 0
        this.channels.clear()
        this.remoteChannelIds.clear()
        this.pendingGlobalRequests.length = 0
        this.pendingPings.length = 0
        this.transportPingSupported = false
        this.remoteForwardings.clear()
        this.remoteStreamLocalForwardings.clear()
        this.x11Forwardings.clear()
        this.agentForwardingEnabled = false
        this.unansweredKeepalives = 0
        this.keyExchangeInProgress = false
        this.packetsQueuedDuringKeyExchange.length = 0
        this.actionQueue.actionQueues.clear()
    }

    debug(...message: unknown[]): void {
        this.options.debug?.(...message)
        this.emit("debug", ...message)
    }

    setNoDelay(noDelay = true): this {
        if (this.socket && "setNoDelay" in this.socket) {
            ;(this.socket as net.Socket).setNoDelay(noDelay)
        }
        return this
    }

    assertOpenSSHVendor(): void {
        if (!this.options.strictVendor) return
        const software = this.serverProtocolVersion?.protocol_software ?? ""
        if (/^OpenSSH_(?:[5-9]|[1-9]\d)/u.test(software)) return
        throw new Error("strictVendor enabled and server is not OpenSSH or compatible version")
    }

    rekey(): Promise<void>
    rekey(callback: (error?: Error) => void): this
    rekey(callback?: (error?: Error) => void): Promise<void> | this {
        if (!this.isConnected) {
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
            this.destroy()
            throw error
        })
        if (!callback) return operation
        operation.then(
            () => callback(),
            (error: Error) => callback(error),
        )
        return this
    }

    ping(data?: Buffer): Promise<Buffer>
    ping(callback: ClientPingCallback): this
    ping(data: Buffer, callback: ClientPingCallback): this
    ping(
        dataOrCallback: Buffer | ClientPingCallback = Buffer.alloc(0),
        callback?: ClientPingCallback,
    ): Promise<Buffer> | this {
        const data = typeof dataOrCallback === "function" ? Buffer.alloc(0) : dataOrCallback
        callback = typeof dataOrCallback === "function" ? dataOrCallback : callback
        let operation: Promise<Buffer>
        if (!this.isConnected) {
            operation = Promise.reject(new Error("Cannot ping before the SSH connection is ready"))
        } else if (!this.transportPingSupported) {
            operation = Promise.reject(
                new Error("SSH server did not advertise transport ping support"),
            )
        } else if (!Buffer.isBuffer(data)) {
            operation = Promise.reject(new TypeError("SSH transport ping data must be a buffer"))
        } else {
            const sent = Buffer.from(data)
            operation = new Promise<Buffer>((resolve, reject) => {
                this.pendingPings.push({ data: sent, resolve, reject })
                try {
                    this.sendPacket(new Ping({ data: sent }))
                } catch (error) {
                    this.pendingPings.pop()
                    reject(error as Error)
                }
            })
        }
        if (!callback) return operation
        operation.then(
            (reply) => callback(undefined, reply),
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
    globalRequest(name: string, callback: ClientGlobalRequestCallback): this
    globalRequest(name: string, args: Buffer, callback: ClientGlobalRequestCallback): this
    globalRequest(
        name: string,
        argsOrCallback: Buffer | ClientGlobalRequestCallback = Buffer.alloc(0),
        callback?: ClientGlobalRequestCallback,
    ): Promise<Buffer> | this {
        const args = typeof argsOrCallback === "function" ? Buffer.alloc(0) : argsOrCallback
        callback = typeof argsOrCallback === "function" ? argsOrCallback : callback
        let operation: Promise<Buffer>
        try {
            this.validateGlobalRequest(name, args)
            operation = this.sendGlobalRequest(name, Buffer.from(args))
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

    openSession(): Promise<ClientSessionChannel>
    openSession(callback: ClientSessionCallback): this
    openSession(callback?: ClientSessionCallback): Promise<ClientSessionChannel> | this {
        return this.withOptionalChannelCallback(this.openSessionChannel(), callback)
    }

    exec(command: string, options?: ClientSessionOptions): Promise<ClientSessionChannel>
    exec(command: string, callback: ClientSessionCallback): this
    exec(command: string, options: ClientSessionOptions, callback: ClientSessionCallback): this
    exec(
        command: string,
        optionsOrCallback: ClientSessionOptions | ClientSessionCallback = {},
        callback?: ClientSessionCallback,
    ): Promise<ClientSessionChannel> | this {
        const options = typeof optionsOrCallback === "function" ? {} : optionsOrCallback
        const resolvedCallback =
            typeof optionsOrCallback === "function" ? optionsOrCallback : callback
        const operation = this.openSessionChannel().then(async (channel) => {
            try {
                await this.configureSession(channel, options, false)
                await channel.exec(command)
                return channel
            } catch (error) {
                channel.close()
                throw error
            }
        })
        return this.withOptionalChannelCallback(operation, resolvedCallback)
    }

    shell(options?: ClientSessionOptions): Promise<ClientSessionChannel>
    shell(callback: ClientSessionCallback): this
    shell(options: ClientSessionOptions, callback: ClientSessionCallback): this
    shell(
        optionsOrCallback: ClientSessionOptions | ClientSessionCallback = {},
        callback?: ClientSessionCallback,
    ): Promise<ClientSessionChannel> | this {
        const options = typeof optionsOrCallback === "function" ? {} : optionsOrCallback
        const resolvedCallback =
            typeof optionsOrCallback === "function" ? optionsOrCallback : callback
        const operation = this.openSessionChannel().then(async (channel) => {
            try {
                await this.configureSession(channel, options, true)
                await channel.shell()
                return channel
            } catch (error) {
                channel.close()
                throw error
            }
        })
        return this.withOptionalChannelCallback(operation, resolvedCallback)
    }

    subsystem(name: string): Promise<ClientSessionChannel>
    subsystem(name: string, callback: ClientSessionCallback): this
    subsystem(
        name: string,
        callback?: ClientSessionCallback,
    ): Promise<ClientSessionChannel> | this {
        const operation = this.openSessionChannel().then(async (channel) => {
            try {
                await channel.subsystem(name)
                return channel
            } catch (error) {
                channel.close()
                throw error
            }
        })
        return this.withOptionalChannelCallback(operation, callback)
    }

    subsys(name: string): Promise<ClientSessionChannel>
    subsys(name: string, callback: ClientSessionCallback): this
    subsys(name: string, callback?: ClientSessionCallback): Promise<ClientSessionChannel> | this {
        return callback ? this.subsystem(name, callback) : this.subsystem(name)
    }

    openssh_noMoreSessions(): Promise<void>
    openssh_noMoreSessions(callback: (error?: Error) => void): this
    openssh_noMoreSessions(callback?: (error?: Error) => void): Promise<void> | this {
        const operation = this.requestNoMoreSessions()
        if (!callback) return operation
        operation.then(
            () => callback(),
            (error: Error) => callback(error),
        )
        return this
    }

    opensshNoMoreSessions(): Promise<void> {
        return this.requestNoMoreSessions()
    }

    sftp(environment?: ClientEnvironment): Promise<SFTPClient>
    sftp(callback: ClientSFTPCallback): this
    sftp(environment: ClientEnvironment, callback: ClientSFTPCallback): this
    sftp(
        environmentOrCallback: ClientEnvironment | ClientSFTPCallback = {},
        callback?: ClientSFTPCallback,
    ): Promise<SFTPClient> | this {
        const environment = typeof environmentOrCallback === "function" ? {} : environmentOrCallback
        const resolvedCallback =
            typeof environmentOrCallback === "function" ? environmentOrCallback : callback
        const operation = this.openSessionChannel().then(async (channel) => {
            try {
                for (const [name, value] of Object.entries(environment)) {
                    await channel.setEnv(name, value, false)
                }
                await channel.subsystem("sftp")
                const software = this.serverProtocolVersion?.protocol_software ?? ""
                return await SFTPClient.connect(channel, /^(?:OpenSSH_|dropbear)/iu.test(software))
            } catch (error) {
                channel.close()
                throw error
            }
        })
        if (!resolvedCallback) return operation
        void operation.then(
            (sftp) => resolvedCallback(undefined, sftp),
            (error: unknown) =>
                resolvedCallback(error instanceof Error ? error : new Error(String(error))),
        )
        return this
    }

    forwardOut(
        sourceHost: string,
        sourcePort: number,
        destinationHost: string,
        destinationPort: number,
    ): Promise<ClientTCPIPChannel>
    forwardOut(
        sourceHost: string,
        sourcePort: number,
        destinationHost: string,
        destinationPort: number,
        callback: ClientForwardCallback,
    ): this
    forwardOut(
        sourceHost: string,
        sourcePort: number,
        destinationHost: string,
        destinationPort: number,
        callback?: ClientForwardCallback,
    ): Promise<ClientTCPIPChannel> | this {
        const operation = this.openClientChannel(
            new ClientTCPIPChannel(this, {
                sourceHost,
                sourcePort,
                destinationHost,
                destinationPort,
            }),
        )
        return this.withOptionalChannelCallback(operation, callback)
    }

    forwardIn(bindAddress: string, bindPort: number): Promise<number>
    forwardIn(bindAddress: string, bindPort: number, callback: ClientForwardInCallback): this
    forwardIn(
        bindAddress: string,
        bindPort: number,
        callback?: ClientForwardInCallback,
    ): Promise<number> | this {
        const operation = this.requestRemoteForward(bindAddress, bindPort)
        if (!callback) return operation
        operation.then(
            (port) => callback(undefined, port),
            (error: Error) => callback(error),
        )
        return this
    }

    unforwardIn(bindAddress: string, bindPort: number): Promise<void>
    unforwardIn(bindAddress: string, bindPort: number, callback: (error?: Error) => void): this
    unforwardIn(
        bindAddress: string,
        bindPort: number,
        callback?: (error?: Error) => void,
    ): Promise<void> | this {
        const operation = this.cancelRemoteForward(bindAddress, bindPort)
        if (!callback) return operation
        operation.then(
            () => callback(),
            (error: Error) => callback(error),
        )
        return this
    }

    openssh_forwardOutStreamLocal(socketPath: string): Promise<ClientDirectStreamLocalChannel>
    openssh_forwardOutStreamLocal(socketPath: string, callback: ClientStreamLocalCallback): this
    openssh_forwardOutStreamLocal(
        socketPath: string,
        callback?: ClientStreamLocalCallback,
    ): Promise<ClientDirectStreamLocalChannel> | this {
        try {
            this.assertOpenSSHVendor()
        } catch (error) {
            return this.withOptionalChannelCallback(
                Promise.reject<ClientDirectStreamLocalChannel>(error),
                callback,
            )
        }
        this.validateSocketPath(socketPath)
        const operation = this.openClientChannel(
            new ClientDirectStreamLocalChannel(this, socketPath),
        )
        return this.withOptionalChannelCallback(operation, callback)
    }

    openssh_openTunnel(mode: TunnelMode, unit?: number): Promise<ClientTunnelChannel>
    openssh_openTunnel(
        mode: TunnelMode,
        unit: number,
        callback: ClientChannelCallback<ClientTunnelChannel>,
    ): this
    openssh_openTunnel(mode: TunnelMode, callback: ClientChannelCallback<ClientTunnelChannel>): this
    openssh_openTunnel(
        mode: TunnelMode,
        unitOrCallback: number | ClientChannelCallback<ClientTunnelChannel> = AUTOMATIC_TUNNEL_UNIT,
        callback?: ClientChannelCallback<ClientTunnelChannel>,
    ): Promise<ClientTunnelChannel> | this {
        const unit = typeof unitOrCallback === "number" ? unitOrCallback : AUTOMATIC_TUNNEL_UNIT
        const resolvedCallback = typeof unitOrCallback === "function" ? unitOrCallback : callback
        let operation: Promise<ClientTunnelChannel>
        try {
            this.assertOpenSSHVendor()
            operation = this.openClientChannel(new ClientTunnelChannel(this, mode, unit))
        } catch (error) {
            operation = Promise.reject(error)
        }
        return this.withOptionalChannelCallback(operation, resolvedCallback)
    }

    openssh_forwardInStreamLocal(socketPath: string): Promise<void>
    openssh_forwardInStreamLocal(socketPath: string, callback: (error?: Error) => void): this
    openssh_forwardInStreamLocal(
        socketPath: string,
        callback?: (error?: Error) => void,
    ): Promise<void> | this {
        const operation = this.requestRemoteStreamLocalForward(socketPath)
        if (!callback) return operation
        operation.then(
            () => callback(),
            (error: Error) => callback(error),
        )
        return this
    }

    openssh_unforwardInStreamLocal(socketPath: string): Promise<void>
    openssh_unforwardInStreamLocal(socketPath: string, callback: (error?: Error) => void): this
    openssh_unforwardInStreamLocal(
        socketPath: string,
        callback?: (error?: Error) => void,
    ): Promise<void> | this {
        const operation = this.cancelRemoteStreamLocalForward(socketPath)
        if (!callback) return operation
        operation.then(
            () => callback(),
            (error: Error) => callback(error),
        )
        return this
    }

    private async openSessionChannel(): Promise<ClientSessionChannel> {
        return this.openClientChannel(new ClientSessionChannel(this))
    }

    private async configureSession(
        channel: ClientSessionChannel,
        options: ClientSessionOptions,
        defaultPty: boolean,
    ): Promise<void> {
        channel.allowHalfOpen = options.allowHalfOpen !== false
        if (options.agentForward ?? this.options.agentForward) {
            await channel.openssh_forwardAgent()
        }
        for (const [name, value] of Object.entries(options.env ?? {})) {
            await channel.setEnv(name, value, false)
        }
        const pty = options.pty ?? defaultPty
        if (pty) await channel.requestPty(pty === true ? {} : pty)
        if (options.x11) {
            const x11 =
                options.x11 === true
                    ? {}
                    : typeof options.x11 === "number"
                      ? { screen: options.x11 }
                      : options.x11
            await channel.requestX11(x11)
        }
    }

    private async openClientChannel<T extends ClientChannel>(channel: T): Promise<T> {
        if (!this.isConnected || !this.hasAuthenticated) {
            throw new Error("Cannot open an SSH channel before authentication completes")
        }

        this.channels.set(channel.localId, channel)
        try {
            this.sendPacket(channel.getOpenPacket())
            await channel.waitUntilOpen()
            return channel
        } catch (error) {
            this.channels.delete(channel.localId)
            channel.destroy()
            throw error
        }
    }

    private withOptionalChannelCallback<T extends ClientChannel>(
        operation: Promise<T>,
        callback?: ClientChannelCallback<T>,
    ): Promise<T> | this {
        if (!callback) return operation
        operation.then(
            (channel) => callback(undefined, channel),
            (error: Error) => callback(error),
        )
        return this
    }

    private async handleServerHostKeys(packet: GlobalRequest): Promise<void> {
        const publicKeys: PublicKey[] = []
        const seen = new Set<string>()
        let raw = packet.data.args
        while (raw.length !== 0) {
            let encoded: Buffer
            ;[encoded, raw] = readNextBuffer(raw)
            try {
                const publicKey = PublicKey.parse(encoded)
                const identity = publicKey.serialize().toString("base64")
                if (seen.has(identity)) continue
                seen.add(identity)
                publicKeys.push(publicKey)
            } catch (error) {
                this.debug("Ignoring an unsupported advertised SSH host key:", error)
            }
        }
        if (publicKeys.length === 0) return
        if (!this.isConnected) await this.waitEvent("connect")
        assert(this.sessionID, "SSH host-key proof requires an established session")
        const response = await this.sendGlobalRequest(
            "hostkeys-prove-00@openssh.com",
            Buffer.concat(publicKeys.map((publicKey) => serializeBuffer(publicKey.serialize()))),
        )
        const verified = parseHostKeysProofResponse(this.sessionID, publicKeys, response)
        this.debug(`Verified ${verified.length} of ${publicKeys.length} advertised SSH host keys`)
        if (verified.length !== 0) this.emit("hostKeys", verified)
    }

    private async handleServerGlobalRequest(packet: GlobalRequest): Promise<void> {
        this.debug(`Received global request packet:`, packet)

        if (packet.data.request_name === "hostkeys-00@openssh.com") {
            if (packet.data.want_reply) {
                this.sendPacket(new RequestSuccess({ args: Buffer.alloc(0) }))
            }
            void this.handleServerHostKeys(packet).catch((error: unknown) => {
                this.debug("Could not verify advertised SSH host keys:", error)
            })
            return
        }

        this.debug(`Unknown global request name: ${packet.data.request_name}`)
        const context: ClientHookerGlobalRequestContext = Object.freeze({
            name: packet.data.request_name,
            args: Buffer.from(packet.data.args),
            wantReply: packet.data.want_reply,
        })
        const controller: ClientHookerGlobalRequestController = { success: false }
        await this.hooker.triggerHook("globalRequest", context, controller)
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

    private async requestRemoteForward(bindAddress: string, bindPort: number): Promise<number> {
        this.validatePort(bindPort, "remote forwarding port")
        const args = Buffer.concat([
            serializeBuffer(Buffer.from(bindAddress, "utf8")),
            serializeUint32(bindPort),
        ])
        const response = await this.sendGlobalRequest("tcpip-forward", args)
        let actualPort = bindPort
        if (bindPort === 0) {
            let remaining: Buffer
            ;[actualPort, remaining] = readNextUint32(response)
            if (remaining.length !== 0 || actualPort === 0 || actualPort > 65_535) {
                throw new Error("Invalid allocated port in tcpip-forward success response")
            }
        } else if (response.length !== 0) {
            throw new Error("Unexpected data in tcpip-forward success response")
        }

        const key = this.remoteForwardingKey(bindAddress, actualPort)
        if (this.remoteForwardings.has(key)) {
            throw new Error(`Remote forwarding already exists for ${bindAddress}:${actualPort}`)
        }
        this.remoteForwardings.set(key, { bindAddress, bindPort: actualPort })
        return actualPort
    }

    private async requestNoMoreSessions(): Promise<void> {
        this.assertOpenSSHVendor()
        const response = await this.sendGlobalRequest(
            "no-more-sessions@openssh.com",
            Buffer.alloc(0),
        )
        if (response.length !== 0) {
            throw new Error("Unexpected data in no-more-sessions success response")
        }
    }

    private async cancelRemoteForward(bindAddress: string, bindPort: number): Promise<void> {
        this.validatePort(bindPort, "remote forwarding port")
        const key = this.remoteForwardingKey(bindAddress, bindPort)
        if (!this.remoteForwardings.has(key)) {
            throw new Error(`No remote forwarding exists for ${bindAddress}:${bindPort}`)
        }
        await this.sendGlobalRequest(
            "cancel-tcpip-forward",
            Buffer.concat([
                serializeBuffer(Buffer.from(bindAddress, "utf8")),
                serializeUint32(bindPort),
            ]),
        )
        this.remoteForwardings.delete(key)
    }

    private async requestRemoteStreamLocalForward(socketPath: string): Promise<void> {
        this.assertOpenSSHVendor()
        this.validateSocketPath(socketPath)
        if (this.remoteStreamLocalForwardings.has(socketPath)) {
            throw new Error(`Remote stream-local forwarding already exists for ${socketPath}`)
        }
        await this.sendGlobalRequest(
            "streamlocal-forward@openssh.com",
            serializeBuffer(Buffer.from(socketPath, "utf8")),
        )
        this.remoteStreamLocalForwardings.add(socketPath)
    }

    private async cancelRemoteStreamLocalForward(socketPath: string): Promise<void> {
        this.assertOpenSSHVendor()
        this.validateSocketPath(socketPath)
        if (!this.remoteStreamLocalForwardings.has(socketPath)) {
            throw new Error(`No remote stream-local forwarding exists for ${socketPath}`)
        }
        await this.sendGlobalRequest(
            "cancel-streamlocal-forward@openssh.com",
            serializeBuffer(Buffer.from(socketPath, "utf8")),
        )
        this.remoteStreamLocalForwardings.delete(socketPath)
    }

    private sendGlobalRequest(name: string, args: Buffer): Promise<Buffer> {
        if (!this.isConnected || !this.hasAuthenticated) {
            return Promise.reject(
                new Error("Cannot send an SSH global request before authentication"),
            )
        }
        const response = new Promise<Buffer>((resolve, reject) => {
            this.pendingGlobalRequests.push({ name, resolve, reject })
        })
        try {
            this.sendPacket(new GlobalRequest({ request_name: name, want_reply: true, args }))
        } catch (error) {
            this.pendingGlobalRequests.pop()
            return Promise.reject(error)
        }
        return response
    }

    private validateGlobalRequest(name: string, args: Buffer): void {
        if (!/^[\x21-\x7e]+$/u.test(name)) {
            throw new TypeError("SSH global request name must be non-empty printable ASCII")
        }
        if (!Buffer.isBuffer(args)) {
            throw new TypeError("SSH global request arguments must be a buffer")
        }
    }

    private validatePort(port: number, name: string): void {
        if (!Number.isInteger(port) || port < 0 || port > 65_535) {
            throw new RangeError(`SSH ${name} must be between 0 and 65535`)
        }
    }

    private validateSocketPath(socketPath: string): void {
        if (socketPath.length === 0 || socketPath.includes("\0")) {
            throw new TypeError("SSH stream-local socket path must be non-empty and contain no NUL")
        }
    }

    private remoteForwardingKey(address: string, port: number): string {
        return `${address}\0${port}`
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
        if (error instanceof DisconnectError && this.socket?.writable) {
            this.sendPacket(
                new Disconnect({
                    reason_code: error.reason_code,
                    description: error.message,
                    language_tag: "",
                }),
            )
            this.socket.end()
            return
        }
        this.socket?.destroy(error)
    }

    private resumePacketProcessing(): void {
        this.packetProcessingPaused = false
        if (this.packetDecoder.bufferedLength > 0) {
            this.scheduleMessageProcessing(Buffer.alloc(0))
        }
    }

    private installOutboundCompression(): void {
        assert(this.clientCompressionAlgorithm, "Client compression algorithm not selected")
        this.packetEncoder.setCompression(
            createPacketCompressor(this.clientCompressionAlgorithm, this.hasAuthenticated),
        )
    }

    private installInboundCompression(): void {
        assert(this.serverCompressionAlgorithm, "Server compression algorithm not selected")
        this.packetDecoder.setCompression(
            createPacketDecompressor(this.serverCompressionAlgorithm, this.hasAuthenticated),
        )
    }

    private enableDelayedCompression(): void {
        if (this.clientCompressionAlgorithm?.delayed) this.installOutboundCompression()
        if (this.serverCompressionAlgorithm?.delayed) this.installInboundCompression()
    }

    private createKexInit(): KexInit {
        return new KexInit({
            cookie: crypto.getRandomValues(Buffer.alloc(16)),
            kex_algorithms: [
                ...this.algorithmOffer.kex,
                ...(this.sessionID === undefined
                    ? ["ext-info-c", ...STRICT_KEX_CLIENT_MARKERS]
                    : []),
            ],
            server_host_key_algorithms: [...this.algorithmOffer.serverHostKey],
            encryption_algorithms_client_to_server: [...this.algorithmOffer.cipher],
            encryption_algorithms_server_to_client: [...this.algorithmOffer.cipher],
            mac_algorithms_client_to_server: [...this.algorithmOffer.hmac],
            mac_algorithms_server_to_client: [...this.algorithmOffer.hmac],
            compression_algorithms_client_to_server: [...this.algorithmOffer.compress],
            compression_algorithms_server_to_client: [...this.algorithmOffer.compress],
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
        this.clearKeepalive()
        this.hasReceivedNewKeys = false
        this.hasSentNewKeys = false

        try {
            this.clientKexInit = this.createKexInit()
            this.sendPacket(this.clientKexInit)
            const [serverKexInit, serverKexInitBuffer] =
                received ?? (await this.waitEvent("serverKexInit"))
            this.serverKexInit = serverKexInit
            this.strictKeyExchange ||= negotiatesStrictKeyExchange(
                this.clientKexInit.data.kex_algorithms,
                serverKexInit.data.kex_algorithms,
            )
            chooseAlgorithms(this)

            const kexAlgorithm = this.kexAlgorithm
            assert(kexAlgorithm, "No key exchange algorithm was negotiated")
            let hostKeyBlob: Buffer
            let signatureBlob: Buffer
            if (kexAlgorithm instanceof DiffieHellmanGroupExchange) {
                kexAlgorithm.setRequest(defaultGroupExchangeRequest)
                this.sendPacket(new KexDHGexRequest(defaultGroupExchangeRequest))
                const [group] = await this.waitEvent("serverKexDHGexGroup")
                kexAlgorithm.acceptServerGroup(group.data.p, group.data.g)
                kexAlgorithm.generateKeyPair()
                this.sendPacket(new KexDHGexInit({ e: kexAlgorithm.getPublicKey() }))
                const reply = (await this.waitEvent("serverKexDHGexReply"))[0]
                kexAlgorithm.setServerHostKey(reply.data.K_S)
                kexAlgorithm.computeSharedSecret(reply.data.f)
                hostKeyBlob = reply.data.K_S
                signatureBlob = reply.data.H_sig
            } else if (kexAlgorithm instanceof RSA2048SHA256) {
                const [publicKey] = await this.waitEvent("serverKexRSAPublicKey")
                kexAlgorithm.setServerKeys(publicKey.data.hostKey, publicKey.data.transientKey)
                this.sendPacket(
                    new KexRSASecret({ encryptedSecret: kexAlgorithm.generateSecret() }),
                )
                const [done] = await this.waitEvent("serverKexRSADone")
                hostKeyBlob = publicKey.data.hostKey
                signatureBlob = done.data.signature
            } else {
                kexAlgorithm.generateKeyPair()
                this.sendPacket(
                    new KexDHInit({
                        e: kexAlgorithm.getPublicKey(),
                        encoding: kexAlgorithm.exchangeValueEncoding,
                    }),
                )
                const reply = (await this.waitEvent("serverKexDHReply"))[0]
                this.serverKexDHReply = reply
                kexAlgorithm.computeSharedSecret(reply.data.f)
                hostKeyBlob = reply.data.K_S
                signatureBlob = reply.data.H_sig
            }
            const hostKey = PublicKey.parse(hostKeyBlob)
            assert(
                hostKey.data.alg === this.hostKeyAlgorithm!.key_format,
                "Server did not use the negotiated host key algorithm",
            )
            const signature = EncodedSignature.parse(signatureBlob)
            assert(
                signature.data.alg === this.hostKeyAlgorithm!.signature_algorithm,
                "Server did not use the negotiated signature algorithm",
            )
            const h = kexAlgorithm.computeHClient(this, serverKexInitBuffer)
            assert(hostKey.verifySignature(h, signature), "Invalid host key signature from server")

            const certificateAlgorithm = hostKey.data.algorithm
            if (certificateAlgorithm instanceof SSHCertificatePublicKey) {
                const now = BigInt(Math.floor(Date.now() / 1000))
                assert(certificateAlgorithm.data.role === "host", "Invalid host certificate role")
                assert(
                    now >= certificateAlgorithm.data.validAfter &&
                        now < certificateAlgorithm.data.validBefore,
                    "Host certificate is outside its validity interval",
                )
                assert(
                    certificateAlgorithm.verifyCertificateSignature(),
                    "Invalid host certificate authority signature",
                )
            }

            await this.verifyConfiguredHostKey(hostKeyBlob)
            this.negotiatedServerHostKey = Buffer.from(hostKeyBlob)

            if (this.hooker.hasHooks("hostKey")) {
                const controller: ClientHookerHostKeyController = { allowHostKey: false }
                await this.hooker.triggerHook("hostKey", controller, hostKey)
                if (!controller.allowHostKey) throw new Error("Host key not allowed by hook")
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

            this.sendPacket(new NewKeys({}))
            if (this.strictKeyExchange) this.packetEncoder.resetSequenceNumber()
            this.hasSentNewKeys = true
            this.packetEncoder.setProtection(
                createOutboundPacketProtection(
                    this.clientEncryptionAlgorithm!,
                    this.clientEncryption,
                    this.clientMacAlgorithm,
                    this.clientMac,
                ),
            )
            this.installOutboundCompression()
            if (!isRekey && serverKexInit.data.kex_algorithms.includes("ext-info-s")) {
                this.sendPacket(new ExtInfo({ extensions: [] }))
            }
            while (this.packetsQueuedDuringKeyExchange.length > 0) {
                this.writePacket(this.packetsQueuedDuringKeyExchange.shift()!)
            }
            this.emit("clientNewKeys")
            if (!this.hasReceivedNewKeys) await this.waitEvent("serverNewKeys")
            while (this.packetsQueuedDuringKeyExchange.length > 0) {
                this.writePacket(this.packetsQueuedDuringKeyExchange.shift()!)
            }
            this.keyExchangeInProgress = false
            this.strictInitialExchange = false
            this.emit("handshake", describeNegotiatedAlgorithms(this))
            if (isRekey) this.emit("rekey")
        } catch (error) {
            if (error instanceof KeyExchangeError && this.socket?.writable) {
                this.sendPacket(
                    new Disconnect({
                        reason_code: DisconnectReason.SSH_DISCONNECT_KEY_EXCHANGE_FAILED,
                        description: error.message,
                        language_tag: "",
                    }),
                )
                this.socket.end()
            } else if (!isRekey) {
                this.socket?.destroy()
            }
            throw error
        } finally {
            this.keyExchangeInProgress = false
            this.strictInitialExchange = false
            this.resetKeepalive()
        }
    }

    async connect(): Promise<void> {
        if (!this.canConnect) {
            throw new Error("Cannot initiate connection; client is not in a state to connect")
        }
        this.resetConnectionState()
        this.state = SocketState.Connecting
        const suppliedSocket = this.options.sock
        if (suppliedSocket?.destroyed) {
            this.state = SocketState.Closed
            throw new Error("The supplied SSH transport is already destroyed")
        }
        this.socket =
            suppliedSocket ??
            net.createConnection({
                host: this.options.hostname,
                port: this.options.port,
                localAddress: this.options.localAddress,
                localPort: this.options.localPort,
                family:
                    this.options.forceIPv4 === this.options.forceIPv6
                        ? undefined
                        : this.options.forceIPv4
                          ? 4
                          : 6,
            })
        if (this.options.readyTimeout > 0) {
            this.readyTimer = setTimeout(() => {
                this.socket?.destroy(new Error("Timed out while waiting for handshake"))
            }, this.options.readyTimeout)
        }

        let connected = suppliedSocket !== undefined
        await new Promise<void>((resolve, reject) => {
            const connectListener = () => {
                connected = true
                resolve()
            }
            if (suppliedSocket === undefined) this.socket!.once("connect", connectListener)
            const errorListener = (error: Error) => {
                this.clearReadyTimeout()
                this.state = SocketState.Closed
                this.debug("Socket error:", error)
                this.socket = undefined

                if (connected) {
                    this.emit("error", error)
                } else {
                    reject(error)
                }
            }
            this.socket!.on("error", errorListener)
            const closeListener = () => {
                this.clearReadyTimeout()
                this.clearKeepalive()
                this.state = SocketState.Closed
                this.debug("Socket closed")
                this.socket = undefined
                const closeError = this.connectionClosedError("SSH connection closed")
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
                while (this.pendingPings.length > 0) {
                    this.pendingPings
                        .shift()!
                        .reject(
                            this.connectionClosedError(
                                "SSH connection closed during transport ping",
                            ),
                        )
                }
                this.remoteForwardings.clear()
                this.remoteStreamLocalForwardings.clear()
                this.x11Forwardings.clear()
                this.agentForwardingEnabled = false
                this.emit("close")
                if (!connected) reject(closeError)
            }
            this.socket!.on("close", closeListener)
            if (suppliedSocket !== undefined) resolve()
        })

        this.socket!.on("data", (data) => {
            try {
                this.onMessage(data)
            } catch (error) {
                this.handleMessageError(error as Error)
            }
        })

        this.debug(`Socket connected, sending protocol version exchange packet...`)
        this.socket!.write(this.options.protocolVersionExchange.toString())

        const [serverProtocolVersion] = await this.waitEvent("serverProtocolVersion")
        this.debug("Server protocol version:", serverProtocolVersion)

        await this.performKeyExchange()

        this.debug("Starting authentication...")

        this.awaitingServiceAccept = true
        let serviceAnswer: ServiceAccept
        try {
            this.sendPacket(
                new ServiceRequest({
                    service_name: SSHServiceNames.UserAuth,
                }),
            )

            serviceAnswer = await this.waitForPackets(
                {
                    SSH_MSG_SERVICE_ACCEPT: {
                        predicate: (packet) => {
                            if (packet.data.service_name !== SSHServiceNames.UserAuth) {
                                throw new DisconnectError(
                                    DisconnectReason.SSH_DISCONNECT_PROTOCOL_ERROR,
                                    `SSH server accepted unexpected service ${packet.data.service_name}`,
                                )
                            }
                            return true
                        },
                    },
                },
                10_000,
            )
        } finally {
            this.awaitingServiceAccept = false
        }
        assert(serviceAnswer.data.service_name == SSHServiceNames.UserAuth)

        const methodList = [...this.options.authenticationMethodsOrder]
        if (
            !this.explicitAuthenticationMethodsOrder &&
            this.hooker.hasHooks("keyboardInteractive") &&
            !methodList.includes(SSHAuthenticationMethods.KeyboardInteractive)
        ) {
            const passwordIndex = methodList.indexOf(SSHAuthenticationMethods.Password)
            methodList.splice(
                passwordIndex < 0 ? methodList.length : passwordIndex,
                0,
                SSHAuthenticationMethods.KeyboardInteractive,
            )
        }
        const attemptedMethods = new Set<SSHAuthenticationMethods>()
        this.authenticationInProgress = true
        try {
            authentication: while (true) {
                const defaultMethod = methodList.find(
                    (candidate) =>
                        !attemptedMethods.has(candidate) &&
                        (!this.authenticationMethodsRemaining ||
                            this.authenticationMethodsRemaining.has(candidate)),
                )
                if (!defaultMethod) throw new Error("All authentication methods failed.")

                const selection: ClientHookerAuthenticationMethodController = {
                    method: defaultMethod,
                }
                if (this.hooker.hasHooks("authenticationMethod")) {
                    const methodsRemaining = this.authenticationMethodsRemaining
                        ? Object.freeze([...this.authenticationMethodsRemaining])
                        : undefined
                    const context: ClientHookerAuthenticationMethodContext = Object.freeze({
                        attemptedMethods: Object.freeze([...attemptedMethods]),
                        defaultMethod,
                        methodsRemaining,
                        partialSuccess: this.partialAuthenticationSuccess,
                    })
                    await this.hooker.triggerHook("authenticationMethod", context, selection)
                }

                const method = selection.method
                if (method === undefined) throw new Error("Authentication was stopped by policy.")
                if (!methodList.includes(method)) {
                    throw new TypeError(
                        `Selected SSH authentication method is not configured: ${method}`,
                    )
                }
                if (attemptedMethods.has(method)) {
                    throw new TypeError(
                        `Selected SSH authentication method already failed in this stage: ${method}`,
                    )
                }
                if (
                    this.authenticationMethodsRemaining &&
                    !this.authenticationMethodsRemaining.has(method)
                ) {
                    throw new TypeError(
                        `Selected SSH authentication method was not advertised by the server: ${method}`,
                    )
                }
                const m = UserAuthRequest.auth_methods.get(method)
                if (!m) {
                    attemptedMethods.add(method)
                    continue
                }
                this.debug(`Trying auth method`, m.method_name)

                this.activeAuthenticationMethod = m.method_name
                const failureSequence = this.authenticationFailureSequence
                let success: boolean
                try {
                    success = await m.handleAuthentication(this)
                } finally {
                    this.activeAuthenticationMethod = undefined
                }
                if (success) {
                    this.debug(`Authentication successful with method`, m.method_name)
                    this.debug("Authenticated as", this.options.username)

                    break authentication
                }

                if (
                    this.authenticationFailureSequence > failureSequence &&
                    this.partialAuthenticationSuccess
                ) {
                    attemptedMethods.clear()
                    this.debug(`Authentication method completed partially; continuing with`, [
                        ...(this.authenticationMethodsRemaining ?? []),
                    ])
                } else {
                    attemptedMethods.add(method)
                }
            }
        } finally {
            this.authenticationInProgress = false
        }
        this.hasAuthenticated = true

        // we are connected and logged in
        // we can now open channels
        this.state = SocketState.Connected
        this.clearReadyTimeout()
        this.resetKeepalive()
        this.emit("connect")
    }

    end(): this {
        this.clearReadyTimeout()
        this.clearKeepalive()
        if (this.socket && !this.socket.destroyed && this.socket.writable) {
            if (this.serverProtocolVersion) {
                this.sendPacket(
                    new Disconnect({
                        reason_code: DisconnectReason.SSH_DISCONNECT_BY_APPLICATION,
                        description: "",
                        language_tag: "",
                    }),
                )
            }
            this.state = SocketState.Disconnected
            this.socket.end()
        }
        return this
    }

    destroy(): this {
        this.clearReadyTimeout()
        this.clearKeepalive()
        if (this.socket && !this.socket.destroyed) {
            this.state = SocketState.Disconnected
            this.socket.destroy()
        }
        return this
    }

    waitEvent<event extends keyof ClientEvents>(event: event): Promise<ClientEvents[event]> {
        return new Promise((resolve, reject) => {
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
            const handler = (...values: ClientEvents[event]) => {
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
    waitForPacket<Name extends keyof typeof packets>(name: Name): Promise<(typeof packets)[Name]> {
        return new Promise((resolve, reject) => {
            const classType = packets[name]
            const onError = (error: Error) => {
                cleanup()
                reject(error)
            }
            const onClose = () => {
                cleanup()
                reject(
                    this.connectionClosedError(`SSH connection closed while waiting for ${name}`),
                )
            }
            const handler = (p: Packet) => {
                if (p instanceof classType) {
                    // @ts-expect-error good luck typing that
                    resolve(p)
                    cleanup()
                }
            }
            const cleanup = () => {
                this.off("packet", handler)
                this.off("error", onError)
                this.off("close", onClose)
            }
            this.on("packet", handler)
            this.once("error", onError)
            this.once("close", onClose)
        })
    }

    // holy fucking shit what the fuck are those types ?
    waitForPackets<
        Predicates extends {
            [Name in keyof Packets]?: {
                predicate: (packet: Packets[Name]) => boolean
            }
        },
    >(
        Predicates: Predicates,
        timeout: number,
    ): Promise<Packets[Extract<keyof Predicates, keyof Packets>]> {
        return new Promise((resolve, reject) => {
            const cleanup = () => {
                this.off("packet", onPacket)
                this.off("error", onError)
                this.off("close", onClose)
                clearTimeout(timer)
            }
            const onPacket = (packet: Packet) => {
                const packetType = (packet.constructor as typeof Packet).type
                const packetName = PacketTypeToName[packetType]
                // we're not interested by this packet
                if (!(packetName in Predicates)) return
                if (!(packetName in packets)) return

                const predicateEntry = Predicates[packetName as keyof Predicates]
                if (!predicateEntry) return

                const { predicate } = predicateEntry as unknown as {
                    predicate: (packet: Packet) => boolean
                }
                if (!predicate(packet)) return

                // @ts-expect-error good luck typing that
                resolve(packet)
                cleanup()
            }
            const onError = (error: Error) => {
                cleanup()
                reject(error)
            }
            const onClose = () => {
                cleanup()
                reject(
                    this.connectionClosedError("SSH connection closed while waiting for message"),
                )
            }
            const timer = setTimeout(() => {
                cleanup()
                reject(new Error("Timed out waiting for message"))
            }, timeout)
            this.on("packet", onPacket)
            this.once("error", onError)
            this.once("close", onClose)
        })
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

    onMessage(message: Buffer): void {
        if (!this.serverProtocolVersion) {
            const result = this.identificationParser.push(message)
            for (const lineBuf of result.preamble) {
                this.greetingChunks.push(Buffer.from(lineBuf))
                this.emit("message", lineBuf)
                const line = lineBuf.toString("utf8").replace(/\r?\n$/u, "")
                this.emit("tcpWrapperLog", line)
                this.debug("TCP Wrapper log:", line)
            }

            if (!result.version || !result.identification) return

            if (this.greetingChunks.length > 0) {
                this.emit("greeting", Buffer.concat(this.greetingChunks).toString("utf8"))
            }

            this.emit("message", result.identification)
            this.serverProtocolVersion = result.version
            this.emit("serverProtocolVersion", result.version)

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

        this.validateKeyExchangePhase(packetType)
        this.validateServerExtInfoPosition(packetType)

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
        let packet: typeof Packet
        if (
            packetType === PacketNameToType.SSH_MSG_KEXDH_INIT &&
            this.kexAlgorithm instanceof RSA2048SHA256
        ) {
            packet = KexRSAPublicKey
        } else if (
            packetType === PacketNameToType.SSH_MSG_KEX_DH_GEX_INIT &&
            this.kexAlgorithm instanceof RSA2048SHA256
        ) {
            packet = KexRSADone
        } else if (
            packetType === PacketNameToType.SSH_MSG_KEXDH_REPLY &&
            this.kexAlgorithm instanceof DiffieHellmanGroupExchange
        ) {
            packet = KexDHGexGroup
        } else if (packetType === PacketNameToType.SSH_MSG_USERAUTH_PK_OK) {
            switch (this.activeAuthenticationMethod) {
                case SSHAuthenticationMethods.Password:
                    packet = UserAuthPasswordChangeRequest
                    break
                case SSHAuthenticationMethods.KeyboardInteractive:
                    packet = UserAuthInfoRequest
                    break
                default:
                    packet = UserAuthPKOK
            }
        } else {
            packet = packets[packetName as keyof typeof packets]
        }

        const p = packet.parse(payload)
        this.debug("Parsing packet:", this.packetForDebug(p))

        if (packetType === PacketNameToType.SSH_MSG_KEXINIT && this.strictInitialExchange) {
            const serverAlgorithms = (p as KexInit).data.kex_algorithms
            const negotiated = negotiatesStrictKeyExchange(
                this.clientKexInit!.data.kex_algorithms,
                serverAlgorithms,
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

        if (p instanceof UserAuthFailure) {
            this.authenticationMethodsRemaining = new Set(p.data.auth_methods)
            this.partialAuthenticationSuccess = p.data.partial_success
            this.authenticationFailureSequence++
        }

        this.emit("packet", p)

        if (p instanceof GlobalRequest) {
            void this.actionQueue
                .queueAction("globalRequest", () => this.handleServerGlobalRequest(p))
                .catch((error: Error) => this.socket?.destroy(error))
        }
        this.routeGlobalRequestReply(p)
        this.routeChannelPacket(p)

        switch (packet.type) {
            case PacketNameToType.SSH_MSG_DISCONNECT: {
                const disconnect = p as Disconnect
                this.peerDisconnect = peerDisconnectInfo(disconnect.data)
                this.emit("disconnect", this.peerDisconnect)
                this.debug(
                    "Server disconnected:",
                    DisconnectReason[disconnect.data.reason_code],
                    disconnect.data.description,
                    disconnect.data.language_tag,
                )
                this.destroy()
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
                throw new DisconnectError(
                    DisconnectReason.SSH_DISCONNECT_PROTOCOL_ERROR,
                    "SSH server sent a service request",
                )

            case PacketNameToType.SSH_MSG_SERVICE_ACCEPT:
                if (!this.awaitingServiceAccept) {
                    throw new DisconnectError(
                        DisconnectReason.SSH_DISCONNECT_PROTOCOL_ERROR,
                        "SSH server sent an unexpected service acceptance",
                    )
                }
                break

            case PacketNameToType.SSH_MSG_USERAUTH_BANNER: {
                const banner = p as UserAuthBanner
                this.emit("banner", banner.data.message, banner.data.languageTag)
                break
            }

            case PacketNameToType.SSH_MSG_USERAUTH_SUCCESS:
                this.hasAuthenticated = true
                this.enableDelayedCompression()
                break

            case PacketNameToType.SSH_MSG_EXT_INFO: {
                this.applyServerExtensions((p as ExtInfo).data.extensions)
                break
            }

            case PacketNameToType.SSH_MSG_PING: {
                const ping = p as Ping
                this.sendPacket(new Pong({ data: ping.data.data }))
                break
            }

            case PacketNameToType.SSH_MSG_PONG: {
                const pong = p as Pong
                const pending = this.pendingPings.shift()
                if (!pending) break
                if (!pong.data.data.equals(pending.data)) {
                    const error = new Error("SSH transport pong did not echo the ping data")
                    pending.reject(error)
                    throw error
                }
                pending.resolve(Buffer.from(pong.data.data))
                break
            }

            case PacketNameToType.SSH_MSG_KEXINIT:
                if (this.state === SocketState.Connected && !this.keyExchangeInProgress) {
                    void this.performKeyExchange([p as KexInit, payload]).catch((error: Error) => {
                        this.socket?.destroy(error)
                    })
                }
                this.emit("serverKexInit", p as KexInit, payload)
                break

            case PacketNameToType.SSH_MSG_KEXDH_INIT:
                if (!(this.kexAlgorithm instanceof RSA2048SHA256)) {
                    throw new Error("Received an RSA public key for another key exchange")
                }
                this.emit("serverKexRSAPublicKey", p as KexRSAPublicKey)
                break

            case PacketNameToType.SSH_MSG_NEWKEYS:
                this.hasReceivedNewKeys = true
                this.packetDecoder.setProtection(
                    createInboundPacketProtection(
                        this.serverEncryptionAlgorithm!,
                        this.serverEncryption!,
                        this.serverMacAlgorithm,
                        this.serverMac,
                    ),
                )
                this.installInboundCompression()
                if (this.strictKeyExchange) this.packetDecoder.resetSequenceNumber()
                if (!this.initialServerNewKeysReceived) {
                    this.initialServerNewKeysReceived = true
                    this.serverExtInfoAfterNewKeys = true
                }
                this.emit("serverNewKeys")
                break

            case PacketNameToType.SSH_MSG_KEXDH_REPLY:
                if (p instanceof KexDHGexGroup) {
                    this.emit("serverKexDHGexGroup", p)
                } else {
                    this.packetProcessingPaused = true
                    this.emit("serverKexDHReply", p as KexDHReply)
                }
                break

            case PacketNameToType.SSH_MSG_KEX_DH_GEX_REPLY:
                if (!(this.kexAlgorithm instanceof DiffieHellmanGroupExchange)) {
                    throw new Error("Received a group-exchange reply for another key exchange")
                }
                this.packetProcessingPaused = true
                this.emit("serverKexDHGexReply", p as KexDHGexReply)
                break

            case PacketNameToType.SSH_MSG_KEX_DH_GEX_INIT:
                if (!(this.kexAlgorithm instanceof RSA2048SHA256)) {
                    throw new Error("Received RSA key-exchange completion for another key exchange")
                }
                this.packetProcessingPaused = true
                this.emit("serverKexRSADone", p as KexRSADone)
                break
        }

        if (this.packetDecoder.bufferedLength > 0) {
            this.scheduleMessageProcessing(Buffer.alloc(0))
        }
    }

    private validateServerExtInfoPosition(packetType: PacketType): void {
        if (this.serverExtInfoMustPrecedeSuccess) {
            this.serverExtInfoMustPrecedeSuccess = false
            if (packetType !== PacketNameToType.SSH_MSG_USERAUTH_SUCCESS) {
                throw new Error("Server EXT_INFO was not immediately followed by USERAUTH_SUCCESS")
            }
        }
        if (packetType === PacketNameToType.SSH_MSG_EXT_INFO) {
            if (this.serverExtInfoAfterNewKeys) {
                this.serverExtInfoAfterNewKeys = false
                return
            }
            if (this.initialServerNewKeysReceived && !this.hasAuthenticated) {
                this.serverExtInfoMustPrecedeSuccess = true
                return
            }
            throw new Error("Server EXT_INFO arrived outside an RFC 8308 opportunity")
        }
        this.serverExtInfoAfterNewKeys = false
    }

    private validateKeyExchangePhase(packetType: PacketType): void {
        const exchangeOnly =
            packetType === PacketNameToType.SSH_MSG_NEWKEYS ||
            packetType === PacketNameToType.SSH_MSG_KEXDH_INIT ||
            packetType === PacketNameToType.SSH_MSG_KEXDH_REPLY ||
            packetType === PacketNameToType.SSH_MSG_KEX_DH_GEX_INIT ||
            packetType === PacketNameToType.SSH_MSG_KEX_DH_GEX_REPLY ||
            packetType === PacketNameToType.SSH_MSG_KEX_DH_GEX_REQUEST
        if (exchangeOnly && !this.keyExchangeInProgress) {
            throw new DisconnectError(
                DisconnectReason.SSH_DISCONNECT_PROTOCOL_ERROR,
                "SSH server sent a key-exchange message outside key exchange",
            )
        }
    }

    private validateHigherLayerPhase(packetType: PacketType): void {
        if (packetType >= 50 && packetType < 80) {
            if (!this.authenticationInProgress) {
                throw new DisconnectError(
                    DisconnectReason.SSH_DISCONNECT_PROTOCOL_ERROR,
                    "SSH server sent an authentication message outside authentication",
                )
            }
            if (
                packetType !== PacketNameToType.SSH_MSG_USERAUTH_FAILURE &&
                packetType !== PacketNameToType.SSH_MSG_USERAUTH_SUCCESS &&
                packetType !== PacketNameToType.SSH_MSG_USERAUTH_BANNER &&
                packetType !== PacketNameToType.SSH_MSG_USERAUTH_PK_OK
            ) {
                throw new DisconnectError(
                    DisconnectReason.SSH_DISCONNECT_PROTOCOL_ERROR,
                    "SSH server sent a client-only authentication message",
                )
            }
        }
        if (packetType >= 80 && packetType < 128 && !this.hasAuthenticated) {
            throw new DisconnectError(
                DisconnectReason.SSH_DISCONNECT_PROTOCOL_ERROR,
                "SSH server sent a connection message before authentication completed",
            )
        }
    }

    private applyServerExtensions(extensions: readonly SSHExtension[]): void {
        this.negotiatedServerExtensions = copySSHExtensions(extensions)
        this.serverSignatureAlgorithms = undefined
        this.transportPingSupported = false
        this.hostboundAuthenticationSupported = false

        const signatureAlgorithms = extensions.find(({ name }) => name === "server-sig-algs")
        if (signatureAlgorithms) {
            this.serverSignatureAlgorithms = Object.freeze(
                signatureAlgorithms.value
                    .toString("ascii")
                    .split(",")
                    .filter((name) => name.length > 0),
            )
        }
        const ping = extensions.find(({ name }) => name === "ping@openssh.com")
        this.transportPingSupported = ping?.value.equals(Buffer.from("0", "ascii")) === true
        const hostbound = extensions.find(({ name }) => name === "publickey-hostbound@openssh.com")
        this.hostboundAuthenticationSupported =
            hostbound?.value.equals(Buffer.from("0", "ascii")) === true
        this.emit("serverExtensions", this.serverExtensions)
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

    private routeChannelPacket(packet: Packet): void {
        if (packet instanceof ChannelOpen) {
            this.handleIncomingChannelOpen(packet)
            return
        }

        if (packet instanceof ChannelOpenConfirmation) {
            this.reserveRemoteChannelId(packet.data.sender_channel_id)
            this.getChannel(packet.data.recipient_channel_id).confirmOpen(packet)
            return
        }
        if (packet instanceof ChannelOpenFailure) {
            const channel = this.getChannel(packet.data.recipient_channel_id)
            channel.failOpen(packet)
            this.channels.delete(channel.localId)
            return
        }

        const recipient = this.channelRecipient(packet)
        if (recipient === undefined) return
        const channel = this.getChannel(recipient)

        if (packet instanceof ChannelWindowAdjust) {
            channel.receiveWindowAdjust(packet.data.bytes_to_add)
        } else if (packet instanceof ChannelData) {
            channel.receiveData(packet.data.data)
        } else if (packet instanceof ChannelExtendedData) {
            channel.receiveExtendedData(packet.data.data_type_code, packet.data.data)
        } else if (packet instanceof ChannelEOF) {
            channel.receiveEOF()
        } else if (packet instanceof ChannelClose) {
            channel.receiveClose()
            if (channel.isFullyClosed) {
                this.channels.delete(channel.localId)
                if (channel.remoteId !== undefined) this.remoteChannelIds.delete(channel.remoteId)
            }
        } else if (packet instanceof ChannelRequest) {
            void this.actionQueue
                .queueAction(`channelRequest:${recipient}`, () => channel.receiveRequest(packet))
                .catch((error: Error) => this.handleMessageError(error))
        } else if (packet instanceof ChannelSuccess) {
            channel.receiveRequestSuccess()
        } else if (packet instanceof ChannelFailure) {
            channel.receiveRequestFailure()
        }
    }

    private routeGlobalRequestReply(packet: Packet): void {
        if (!(packet instanceof RequestSuccess) && !(packet instanceof RequestFailure)) return
        const request = this.pendingGlobalRequests.shift()
        if (!request) throw new Error("Received an unexpected SSH global request response")
        if (packet instanceof RequestSuccess) {
            request.resolve(packet.data.args)
        } else {
            request.reject(new GlobalRequestError(`SSH global request ${request.name} failed`))
        }
    }

    private resetKeepalive(): void {
        this.clearKeepalive()
        this.unansweredKeepalives = 0
        this.scheduleKeepalive()
    }

    private scheduleKeepalive(): void {
        if (this.options.keepaliveInterval === 0 || !this.isConnected) return
        this.keepaliveTimer = setTimeout(() => this.sendKeepalive(), this.options.keepaliveInterval)
        this.keepaliveTimer.unref()
    }

    private clearKeepalive(): void {
        if (this.keepaliveTimer !== undefined) clearTimeout(this.keepaliveTimer)
        this.keepaliveTimer = undefined
    }

    private clearReadyTimeout(): void {
        if (this.readyTimer !== undefined) clearTimeout(this.readyTimer)
        this.readyTimer = undefined
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

    private async verifyConfiguredHostKey(serializedHostKey: Buffer): Promise<void> {
        const verifier = this.options.hostVerifier
        if (!verifier) return

        const presentedKey: Buffer | string = this.options.hostHash
            ? crypto.createHash(this.options.hostHash).update(serializedHostKey).digest("hex")
            : Buffer.from(serializedHostKey)
        const allowed = await new Promise<boolean>((resolve, reject) => {
            let completed = false
            const cleanup = () => {
                this.off("error", fail)
                this.off("close", closed)
            }
            const complete = (verified: boolean) => {
                if (completed) return
                completed = true
                cleanup()
                resolve(verified === true)
            }
            const fail = (error: Error) => {
                if (completed) return
                completed = true
                cleanup()
                reject(error)
            }
            const closed = () => fail(new Error("SSH connection closed during host verification"))
            this.once("error", fail)
            this.once("close", closed)
            try {
                const result = verifier(presentedKey, complete)
                if (result !== undefined) complete(result)
            } catch (error) {
                fail(error as Error)
            }
        })
        if (!allowed) throw new Error("Host key not allowed by verifier")
    }

    private sendKeepalive(): void {
        this.keepaliveTimer = undefined
        if (!this.isConnected) return
        this.unansweredKeepalives++
        if (this.unansweredKeepalives > this.options.keepaliveCountMax) {
            this.emit("error", new Error("SSH keepalive timeout"))
            this.destroy()
            return
        }

        void this.sendGlobalRequest("keepalive@openssh.com", Buffer.alloc(0)).then(
            () => this.resetKeepalive(),
            (error: unknown) => {
                if (error instanceof GlobalRequestError) this.resetKeepalive()
            },
        )
        this.scheduleKeepalive()
    }

    private handleIncomingChannelOpen(packet: ChannelOpen): void {
        this.reserveRemoteChannelId(packet.data.sender_channel_id)
        if (packet.data.channel_type === ClientX11Channel.channelType) {
            this.handleIncomingX11ChannelOpen(packet)
            return
        }
        if (packet.data.channel_type === ClientAgentChannel.channelType) {
            void this.handleIncomingAgentChannelOpen(packet)
            return
        }
        if (packet.data.channel_type === ClientForwardedStreamLocalChannel.channelType) {
            this.handleIncomingStreamLocalChannelOpen(packet)
            return
        }
        if (packet.data.channel_type !== "forwarded-tcpip") {
            const reason =
                packet.data.channel_type === "session"
                    ? ChannelOpenFailureReasonCodes.SSH_OPEN_ADMINISTRATIVELY_PROHIBITED
                    : ChannelOpenFailureReasonCodes.SSH_OPEN_UNKNOWN_CHANNEL_TYPE
            this.rejectIncomingChannel(packet, reason, "Server-initiated channel is not supported")
            return
        }

        const details = Object.freeze(ClientForwardedTCPIPChannel.parseDetails(packet.data.args))
        if (!this.isRemoteForwardAuthorized(details)) {
            this.rejectIncomingChannel(
                packet,
                ChannelOpenFailureReasonCodes.SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
                "No matching remote forwarding was requested",
            )
            return
        }
        if (this.listenerCount("tcp connection") === 0) {
            this.rejectIncomingChannel(
                packet,
                ChannelOpenFailureReasonCodes.SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
                "No remote forwarding handler is registered",
            )
            return
        }

        let decided = false
        const accept = (): ClientForwardedTCPIPChannel | undefined => {
            if (decided) return undefined
            decided = true
            const channel = new ClientForwardedTCPIPChannel(this, packet)
            this.channels.set(channel.localId, channel)
            this.sendPacket(channel.getOpenConfirmationPacket())
            return channel
        }
        const reject = (): void => {
            if (decided) return
            decided = true
            this.rejectIncomingChannel(
                packet,
                ChannelOpenFailureReasonCodes.SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
                "Remote forwarding connection was rejected",
            )
        }
        this.emit("tcp connection", details, accept, reject)
        if (!decided) reject()
    }

    private handleIncomingX11ChannelOpen(packet: ChannelOpen): void {
        const authorizations = [...this.x11Forwardings.entries()]
        const authorization =
            authorizations.find(([, candidate]) => !candidate.single) ?? authorizations[0]
        if (!authorization) {
            this.rejectIncomingChannel(
                packet,
                ChannelOpenFailureReasonCodes.SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
                "X11 forwarding was not requested",
            )
            return
        }
        if (authorization[1].single) this.x11Forwardings.delete(authorization[0])

        let details: Readonly<X11ConnectionDetails>
        try {
            details = Object.freeze(ClientX11Channel.parseDetails(packet.data.args))
        } catch (error) {
            this.debug("Invalid incoming X11 channel", error)
            this.rejectIncomingChannel(
                packet,
                ChannelOpenFailureReasonCodes.SSH_OPEN_CONNECT_FAILED,
                "Invalid X11 channel metadata",
            )
            return
        }
        if (this.listenerCount("x11") === 0) {
            this.rejectIncomingChannel(
                packet,
                ChannelOpenFailureReasonCodes.SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
                "No X11 forwarding handler is registered",
            )
            return
        }

        let decided = false
        const accept = (): ClientX11Channel | undefined => {
            if (decided) return undefined
            decided = true
            const channel = new ClientX11Channel(this, packet)
            this.channels.set(channel.localId, channel)
            this.sendPacket(channel.getOpenConfirmationPacket())
            return channel
        }
        const reject = (): void => {
            if (decided) return
            decided = true
            this.rejectIncomingChannel(
                packet,
                ChannelOpenFailureReasonCodes.SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
                "X11 forwarding connection was rejected",
            )
        }
        this.emit("x11", details, accept, reject)
        if (!decided) reject()
    }

    private async handleIncomingAgentChannelOpen(packet: ChannelOpen): Promise<void> {
        if (packet.data.args.length !== 0) {
            this.rejectIncomingChannel(
                packet,
                ChannelOpenFailureReasonCodes.SSH_OPEN_CONNECT_FAILED,
                "Authentication agent channel has trailing data",
            )
            return
        }
        const getStream = this.options.agent.getStream
        if (!this.agentForwardingEnabled || !getStream) {
            this.rejectIncomingChannel(
                packet,
                ChannelOpenFailureReasonCodes.SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
                "Agent forwarding was not requested",
            )
            return
        }

        let stream: Awaited<ReturnType<NonNullable<Agent["getStream"]>>>
        try {
            stream = await getStream.call(this.options.agent)
        } catch (error) {
            this.debug("Could not connect an incoming channel to the SSH agent", error)
            this.rejectIncomingChannel(
                packet,
                ChannelOpenFailureReasonCodes.SSH_OPEN_CONNECT_FAILED,
                "Could not connect to the authentication agent",
            )
            return
        }

        try {
            const channel = new ClientAgentChannel(this, packet)
            this.channels.set(channel.localId, channel)
            stream.on("error", () => channel.destroy())
            stream.on("close", () => channel.close())
            channel.on("error", () => stream.destroy())
            channel.on("close", () => stream.destroy())
            stream.pipe(channel).pipe(stream)
            this.sendPacket(channel.getOpenConfirmationPacket())
        } catch (error) {
            stream.destroy()
            this.debug("Could not accept an incoming SSH agent channel", error)
            this.rejectIncomingChannel(
                packet,
                ChannelOpenFailureReasonCodes.SSH_OPEN_CONNECT_FAILED,
                "Invalid authentication agent channel",
            )
        }
    }

    private handleIncomingStreamLocalChannelOpen(packet: ChannelOpen): void {
        const details = Object.freeze(
            ClientForwardedStreamLocalChannel.parseDetails(packet.data.args),
        )
        if (!this.remoteStreamLocalForwardings.has(details.socketPath)) {
            this.rejectIncomingChannel(
                packet,
                ChannelOpenFailureReasonCodes.SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
                "No matching remote stream-local forwarding was requested",
            )
            return
        }
        if (this.listenerCount("unix connection") === 0) {
            this.rejectIncomingChannel(
                packet,
                ChannelOpenFailureReasonCodes.SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
                "No stream-local forwarding handler is registered",
            )
            return
        }

        let decided = false
        const accept = (): ClientForwardedStreamLocalChannel | undefined => {
            if (decided) return undefined
            decided = true
            const channel = new ClientForwardedStreamLocalChannel(this, packet)
            this.channels.set(channel.localId, channel)
            this.sendPacket(channel.getOpenConfirmationPacket())
            return channel
        }
        const reject = (): void => {
            if (decided) return
            decided = true
            this.rejectIncomingChannel(
                packet,
                ChannelOpenFailureReasonCodes.SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
                "Remote stream-local forwarding connection was rejected",
            )
        }
        this.emit("unix connection", details, accept, reject)
        if (!decided) reject()
    }

    private rejectIncomingChannel(
        packet: ChannelOpen,
        reasonCode: ChannelOpenFailureReasonCodes,
        description: string,
    ): void {
        this.remoteChannelIds.delete(packet.data.sender_channel_id)
        this.sendPacket(
            new ChannelOpenFailure({
                recipient_channel_id: packet.data.sender_channel_id,
                reason_code: reasonCode,
                description,
                language_tag: "",
            }),
        )
    }

    private isRemoteForwardAuthorized(details: Readonly<TCPIPConnectionDetails>): boolean {
        for (const forwarding of this.remoteForwardings.values()) {
            if (forwarding.bindPort !== details.destinationPort) continue
            if (forwarding.bindAddress === details.destinationHost) return true
            if (forwarding.bindAddress === "") return true
            if (forwarding.bindAddress === "0.0.0.0" && net.isIP(details.destinationHost) === 4) {
                return true
            }
            if (forwarding.bindAddress === "::" && net.isIP(details.destinationHost) === 6) {
                return true
            }
            if (
                forwarding.bindAddress === "localhost" &&
                (details.destinationHost === "127.0.0.1" || details.destinationHost === "::1")
            ) {
                return true
            }
        }
        return false
    }

    private channelRecipient(packet: Packet): number | undefined {
        if (
            packet instanceof ChannelWindowAdjust ||
            packet instanceof ChannelData ||
            packet instanceof ChannelExtendedData ||
            packet instanceof ChannelEOF ||
            packet instanceof ChannelClose ||
            packet instanceof ChannelRequest ||
            packet instanceof ChannelSuccess ||
            packet instanceof ChannelFailure
        ) {
            return packet.data.recipient_channel_id
        }
        return undefined
    }

    private getChannel(localId: number): ClientChannel {
        const channel = this.channels.get(localId)
        if (!channel) {
            throw new ProtocolError(`Received a packet for unknown SSH channel ${localId}`)
        }
        return channel
    }
}
