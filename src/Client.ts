import crypto from "crypto"
import EventEmitter from "node:events"
import net from "node:net"
import { Duplex, isReadable } from "node:stream"
import {
    SocketState,
    SSHAuthenticationMethods,
    PacketNameToType,
    SSHServiceNames,
    PacketType,
    PacketTypeToName,
} from "./constants.js"
import ProtocolVersionExchange, { copyProtocolVersionExchange } from "./ProtocolVersionExchange.js"
import assert from "node:assert"
import Packet, { packets, protocolPacketMetadata, type ProtocolPacketMetadata } from "./packet.js"
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
    instantiateTransportAlgorithms,
    describeNegotiatedAlgorithms,
    compression_algorithms,
    encryption_algorithms,
    host_key_algorithms,
    kex_algorithms,
    mac_algorithm_names,
    type HostKeyAlgorithm,
    type KeyExchangeHashContext,
    type KexAlgorithmFactory,
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
import ExtInfo, {
    AUTHENTICATION_EXT_INFO_EXTENSION,
    copySSHExtensions,
    type SSHExtension,
} from "./packets/ExtInfo.js"
import Ping from "./packets/Ping.js"
import Pong from "./packets/Pong.js"
import PublicKey, { SSHCertificatePublicKey } from "./utils/PublicKey.js"
import { Hooker } from "./utils/Hooker.js"
import NewKeys from "./packets/NewKeys.js"
import NewCompress from "./packets/NewCompress.js"
import { KeyExchangeError } from "./algorithms/kex/key-exchange.js"
import { registerKeyExchanges } from "./KeyExchangeRegistry.js"
import { registerClientConfiguration } from "./ConnectionConfiguration.js"
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
import Agent, { AgentType } from "./publickey/Agent.js"
import NoneAgent from "./publickey/NoneAgent.js"
import GlobalRequest from "./packets/GlobalRequest.js"
import RequestFailure from "./packets/RequestFailure.js"
import RequestSuccess from "./packets/RequestSuccess.js"
import Debug, { protocolDebugMessage, type ProtocolDebugMessage } from "./packets/Debug.js"
import Ignore from "./packets/Ignore.js"
import Unimplemented from "./packets/Unimplemented.js"
import {
    readNextBinaryBoolean,
    readNextBuffer,
    readNextUint32,
    serializeBuffer,
    serializeUint32,
} from "./utils/Buffer.js"
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
import ChannelOpenFailure, {
    ChannelOpenError,
    ChannelOpenFailureReasonCodes,
} from "./packets/ChannelOpenFailure.js"
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
import {
    UserAuthGSSAPIErrorToken,
    UserAuthGSSAPIMIC,
    UserAuthGSSAPIResponse,
    UserAuthGSSAPIToken,
} from "./packets/UserAuthGSSAPI.js"
import SFTPClient, { type SFTPClientOptions } from "./sftp/SFTPClient.js"
import PublicKeySubsystemClient, {
    type PublicKeySubsystemClientOptions,
} from "./publickey/PublicKeySubsystemClient.js"
import {
    resolveClientAlgorithmOptions,
    type ClientAlgorithmOptions,
    type NegotiatedAlgorithms,
    type ResolvedAlgorithmOptions,
} from "./AlgorithmOptions.js"
import PrivateKey from "./utils/PrivateKey.js"
import {
    HOST_KEYS_EXTENSION,
    HOST_KEYS_EXTENSION_VERSION,
    HOST_KEYS_PROOF_DOMAIN,
    HOST_KEYS_PROOF_REQUEST,
    HOST_KEYS_REQUEST,
    LEGACY_HOST_KEYS_PROOF_REQUEST,
    LEGACY_HOST_KEYS_REQUEST,
    MAX_HOST_KEYS_PER_REQUEST,
    parseHostKeysProofResponse,
    type HostKeysProofDomain,
    type RSASHA2SignatureAlgorithm,
} from "./utils/HostKeysProof.js"
import { ActionQueue } from "./utils/ActionQueue.js"
import PrivateKeyAgent from "./publickey/PrivateKeyAgent.js"
import { createSocketAgent } from "./publickey/SocketAgent.js"
import { parseKey } from "./KeyParsing.js"
import { encodeSSHUTF8 } from "./utils/SSHText.js"
import {
    closeGSSAPIContext,
    buildGSSAPIKeyExchangeUserAuthMIC,
    GSSAPIError,
    normalizeGSSAPIClientMechanisms,
    normalizeGSSAPIKeyExchangeContextStep,
    normalizeGSSAPIToken,
    type GSSAPIClientMechanism,
    type GSSAPIKeyExchangeClientContext,
} from "./GSSAPI.js"
import type { UserAuthGSSAPIErrorData } from "./packets/UserAuthGSSAPI.js"
import {
    AGENT_FORWARDING_EXTENSION,
    AGENT_FORWARDING_EXTENSION_VERSION,
    RFC9987_AGENT_CHANNEL,
} from "./AgentForwarding.js"
import {
    DEFAULT_REKEY_BYTES,
    DEFAULT_REKEY_INTERVAL,
    validateRekeyBytes,
    validateRekeyInterval,
} from "./RekeyLimits.js"
import GSSAPIKeyExchange, {
    createGSSAPIKeyExchangeAlgorithms,
} from "./algorithms/kex/gssapi-key-exchange.js"
import {
    negotiateNoFlowControl,
    noFlowControlExtension,
    noFlowControlValue,
    normalizeNoFlowControlPreference,
    type NoFlowControlPreference,
} from "./NoFlowControl.js"
import {
    elevationExtension,
    ELEVATION_EXTENSION,
    normalizeElevationPreference,
    type ElevationPreference,
} from "./Elevation.js"
import {
    delayCompressionExtension,
    findDelayCompressionOffers,
    negotiateDelayCompression,
    normalizeDelayCompression,
    type DelayCompressionConfiguration,
    type NegotiatedDelayCompression,
    type NormalizedDelayCompression,
} from "./DelayCompression.js"
import {
    KexGSSAPIComplete,
    KexGSSAPIContinue,
    KexGSSAPIError,
    KexGSSAPIHostKey,
    KexGSSAPIInit,
    type KexGSSAPIErrorData,
} from "./packets/KexGSSAPI.js"
import PacketEventQueue, {
    emitPacketEvent,
    offPacketEvent,
    onPacketEvent,
} from "./utils/PacketEventQueue.js"
import { registerReplyTimeout, waitForReply } from "./ReplyTimeout.js"

export interface ClientHostbasedOptions {
    key: PrivateKey
    localHostname: string
    localUsername: string
    /** Signature algorithm; defaults to the strongest algorithm supported by the key. */
    algorithm?: string
}

function requireGSSAPIKeyExchangeToken(token: Buffer | undefined): Buffer {
    if (!token) {
        throw new KeyExchangeError("GSS-API context step did not produce a required token")
    }
    return normalizeGSSAPIToken(token)
}

function assertGSSAPIKeyExchangeClientContext(
    context: unknown,
): asserts context is GSSAPIKeyExchangeClientContext {
    if (
        typeof context !== "object" ||
        context === null ||
        typeof (context as { step?: unknown }).step !== "function" ||
        typeof (context as { verifyMIC?: unknown }).verifyMIC !== "function" ||
        ("getMIC" in context &&
            context.getMIC !== undefined &&
            typeof context.getMIC !== "function") ||
        ("close" in context && context.close !== undefined && typeof context.close !== "function")
    ) {
        throw new TypeError("Invalid SSH client GSS-API key-exchange context")
    }
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
    /** Signing agent object, Unix socket, Windows named pipe, or Cygwin socket descriptor path. */
    agent?: Agent | string
    /** Request agent forwarding by default for exec and shell sessions. */
    agentForward?: boolean
    /** RFC 8308 infinite channel windows. Both peers must opt in and one must prefer it. */
    noFlowControl?: NoFlowControlPreference
    /** RFC 8308 operating-system elevation preference. False disables the extension. */
    elevation?: ElevationPreference
    /** RFC 8308 post-authentication compression renegotiation. */
    delayCompression?: DelayCompressionConfiguration
    /** Private key object or encoded private-key container used for public-key authentication. */
    privateKey?: PrivateKey | string | Buffer
    /** Certificate public key paired with `privateKey` for certificate authentication. */
    certificate?: PublicKey | string | Buffer
    /** Passphrase for an encoded `privateKey`. */
    passphrase?: string | Buffer
    /** RFC 4252 host-based authentication identity. */
    hostbased?: Readonly<ClientHostbasedOptions>
    /** RFC 4462 GSS-API mechanisms, in preference order. */
    gssapi?: readonly GSSAPIClientMechanism[]
    /** Request credential delegation during RFC 4462 context establishment. */
    gssapiDelegateCredentials?: boolean
    /** Retain an initial GSS-API key-exchange context for gssapi-keyex authentication. */
    gssapiKeyExchangeAuthentication?: boolean
    protocolVersionExchange?: ProtocolVersionExchange
    serverClient?: boolean
    authenticationMethodsOrder?: readonly SSHAuthenticationMethods[]
    keepaliveInterval?: number
    keepaliveCountMax?: number
    /** Protected wire bytes allowed per key in either direction. Zero disables this limit. */
    rekeyBytes?: number
    /** Milliseconds a transport key may remain active. Zero disables this limit. */
    rekeyInterval?: number
    /** Maximum milliseconds for TCP connection, SSH handshake, and authentication. Zero disables. */
    readyTimeout?: number
    /** Maximum milliseconds for an ordered peer reply before the connection is closed. */
    replyTimeout?: number
    /** Maximum peer channel-open decisions allowed to remain pending. */
    maxPendingChannelOpens?: number
    /** Maximum simultaneous active and pending SSH channels. */
    maxChannels?: number
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
    hostbased?: Readonly<ClientHostbasedOptions>
    gssapi: readonly GSSAPIClientMechanism[]
    ident?: string | Buffer
    algorithms?: ClientAlgorithmOptions
    privateKey?: PrivateKey | string | Buffer
    certificate?: PublicKey | string | Buffer
    passphrase?: string | Buffer
    agent: Agent
    delayCompression: NormalizedDelayCompression
    debug?: (...message: unknown[]) => void
}

/** Normalize reusable authentication configuration without retaining encoded key containers. */
export function normalizeClientAuthenticationAgent(options: Readonly<ClientOptions>): Agent {
    const configuredAgent =
        typeof options.agent === "string" ? createSocketAgent(options.agent) : options.agent
    if (configuredAgent !== undefined && options.privateKey !== undefined) {
        throw new TypeError("SSH agent and privateKey options are mutually exclusive")
    }
    if (options.certificate !== undefined && options.privateKey === undefined) {
        throw new TypeError("SSH certificate option requires privateKey")
    }
    if (configuredAgent !== undefined) validateAuthenticationAgent(configuredAgent)
    if (options.privateKey !== undefined) {
        if (options.privateKey instanceof PrivateKey && options.passphrase !== undefined) {
            throw new TypeError("SSH passphrase is only valid for an encoded privateKey")
        }
        const key =
            options.privateKey instanceof PrivateKey
                ? options.privateKey
                : parseKey(options.privateKey, options.passphrase)
        if (!(key instanceof PrivateKey)) {
            throw new TypeError("SSH privateKey option must contain a private key")
        }
        let authenticationKey = key
        if (options.certificate !== undefined) {
            const certificate =
                options.certificate instanceof PublicKey
                    ? options.certificate
                    : parseKey(options.certificate)
            if (!(certificate instanceof PublicKey)) {
                throw new TypeError("SSH certificate option must contain a public key")
            }
            authenticationKey = key.withCertificate(certificate)
        }
        return new PrivateKeyAgent(authenticationKey)
    }
    if (options.passphrase !== undefined) {
        throw new TypeError("SSH passphrase option requires privateKey")
    }
    return configuredAgent ?? new NoneAgent()
}

function validateAuthenticationAgent(agent: unknown): asserts agent is Agent {
    if (typeof agent !== "object" || agent === null) {
        throw new TypeError("SSH agent option must be an Agent or socket path")
    }
    const candidate = agent as Record<string, unknown>
    if (candidate.type !== AgentType.Interactive && candidate.type !== AgentType.NonInteractive) {
        throw new TypeError("SSH agent type must be Interactive or NonInteractive")
    }
    for (const method of ["getPublicKeys", "getPublicKey", "sign"] as const) {
        if (typeof candidate[method] !== "function") {
            throw new TypeError(`SSH agent must implement ${method}()`)
        }
    }
    if (candidate.getStream !== undefined && typeof candidate.getStream !== "function") {
        throw new TypeError("SSH agent getStream must be a function when provided")
    }
}

export type ClientHostVerifier = (key: Buffer | string) => boolean | Promise<boolean>

export interface ClientEvents {
    debug: [...message: unknown[]]
    error: [error: Error]
    /** The peer transport reached EOF; terminal close cleanup follows. */
    end: []
    close: []
    /** Authenticated or unauthenticated terminal disconnect received from the peer. */
    disconnect: [info: Readonly<PeerDisconnectInfo>]
    /** Human-readable transport diagnostic sent by the peer. */
    protocolDebug: [info: Readonly<ProtocolDebugMessage>]
    connect: []
    /** Payload-free metadata for an inbound binary packet. */
    packet: [metadata: Readonly<ProtocolPacketMetadata>]
    /** The peer rejected an outbound packet with this sequence number. */
    unimplemented: [sequenceNumber: number]
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
    /** Diagnostic status sent by the server during RFC 4462 context establishment. */
    gssapiError: [error: Readonly<UserAuthGSSAPIErrorData>]
    /** Diagnostic status sent by the server during GSS-API key exchange. */
    gssapiKeyExchangeError: [error: Readonly<KexGSSAPIErrorData>]
    /** Complete replacement set from the latest valid server EXT_INFO message. */
    serverExtensions: [extensions: readonly Readonly<SSHExtension>[]]
    /** RFC 8308 operating-system elevation result reported after authentication. */
    elevation: [elevated: boolean]
    "tcp connection": [
        details: Readonly<TCPIPConnectionDetails>,
        channel: ClientForwardedTCPIPChannel,
    ]
    "unix connection": [
        details: Readonly<StreamLocalConnectionDetails>,
        channel: ClientForwardedStreamLocalChannel,
    ]
    x11: [details: Readonly<X11ConnectionDetails>, channel: ClientX11Channel]
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
export interface ClientHookerIncomingChannelController {
    allowOpen: boolean
    rejection?: ChannelOpenError
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
    tcpConnection: [
        channel: ClientForwardedTCPIPChannel,
        controller: ClientHookerIncomingChannelController,
    ]
    streamLocalConnection: [
        channel: ClientForwardedStreamLocalChannel,
        controller: ClientHookerIncomingChannelController,
    ]
    x11Connection: [channel: ClientX11Channel, controller: ClientHookerIncomingChannelController]
}

export type ClientEnvironment = Readonly<Record<string, string>>
export interface ClientSessionOptions {
    agentForward?: boolean
    allowHalfOpen?: boolean
    env?: ClientEnvironment
    pty?: boolean | ClientPtyOptions
    x11?: boolean | number | ClientX11Options
}

function snapshotSessionOptions(options: ClientSessionOptions): ClientSessionOptions {
    const pty =
        typeof options.pty === "object"
            ? {
                  ...options.pty,
                  modes:
                      options.pty.modes instanceof Map
                          ? new Map(options.pty.modes)
                          : options.pty.modes === undefined
                            ? undefined
                            : { ...options.pty.modes },
              }
            : options.pty
    const x11 =
        typeof options.x11 === "object"
            ? {
                  ...options.x11,
                  cookie: Buffer.isBuffer(options.x11.cookie)
                      ? Buffer.from(options.x11.cookie)
                      : options.x11.cookie,
              }
            : options.x11
    return {
        ...options,
        env: options.env === undefined ? undefined : { ...options.env },
        pty,
        x11,
    }
}

function validateEndpointText(value: unknown, field: "hostname" | "local address"): void {
    if (typeof value !== "string" || value.length === 0) {
        throw new TypeError(`SSH ${field} must be a non-empty string`)
    }
    encodeSSHUTF8(value, `SSH ${field}`)
    if (value.includes("\0")) throw new TypeError(`SSH ${field} must not contain NUL`)
}

function validateAddressFamilyFlag(value: unknown, field: "forceIPv4" | "forceIPv6"): void {
    if (typeof value !== "boolean") {
        throw new TypeError(`SSH ${field} option must be a boolean`)
    }
}

function clientDiagnosticSummary(
    options: ClientOptionsRequired,
): Readonly<Record<string, unknown>> {
    return Object.freeze({
        hostname: options.hostname,
        port: options.port,
        localAddress: options.localAddress,
        localPort: options.localPort,
        forceIPv4: options.forceIPv4,
        forceIPv6: options.forceIPv6,
        strictVendor: options.strictVendor,
        username: options.username,
        password: options.password ? "<redacted>" : "",
        agent: options.agent instanceof NoneAgent ? "" : "<configured>",
        agentForward: options.agentForward,
        hostVerifier: options.hostVerifier ? "<configured>" : "",
        hostbased: options.hostbased ? "<configured>" : "",
        gssapi: `${options.gssapi.length} configured mechanism(s)`,
        sock: options.sock ? "<configured>" : "",
        debug: options.debug ? "<configured>" : "",
    })
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
    readonly #options: ClientOptionsRequired
    peerDisconnect?: Readonly<PeerDisconnectInfo>
    private readonly explicitAuthenticationMethodsOrder: boolean

    constructor(options: ClientOptions) {
        super()

        this.explicitAuthenticationMethodsOrder = options.authenticationMethodsOrder !== undefined
        this.#options = { ...options } as ClientOptionsRequired
        if (this.#options.hostname === undefined) this.#options.hostname = "localhost"
        if (this.#options.port === undefined) this.#options.port = 22
        if (this.#options.forceIPv4 === undefined) this.#options.forceIPv4 = false
        if (this.#options.forceIPv6 === undefined) this.#options.forceIPv6 = false
        this.#options.strictVendor ??= true
        this.#options.username ??= "root"
        this.#options.password ??= ""
        validateEndpointText(this.#options.hostname, "hostname")
        if (
            !Number.isInteger(this.#options.port) ||
            this.#options.port < 1 ||
            this.#options.port > 65_535
        ) {
            throw new RangeError("SSH port must be an integer between 1 and 65535")
        }
        if (this.#options.localAddress !== undefined) {
            validateEndpointText(this.#options.localAddress, "local address")
        }
        validateAddressFamilyFlag(this.#options.forceIPv4, "forceIPv4")
        validateAddressFamilyFlag(this.#options.forceIPv6, "forceIPv6")
        if (this.#options.debug !== undefined && typeof this.#options.debug !== "function") {
            throw new TypeError("SSH debug option must be a function")
        }
        this.#options.agentForward ??= false
        this.#options.noFlowControl = normalizeNoFlowControlPreference(this.#options.noFlowControl)
        this.#options.elevation = normalizeElevationPreference(this.#options.elevation)
        this.#options.delayCompression = normalizeDelayCompression(this.#options.delayCompression)
        this.#options.gssapi = normalizeGSSAPIClientMechanisms(this.#options.gssapi ?? [])
        this.#options.gssapiDelegateCredentials ??= false
        this.#options.gssapiKeyExchangeAuthentication ??= true
        if (this.#options.hostbased !== undefined) {
            this.#options.hostbased = Object.freeze({ ...this.#options.hostbased })
        }
        this.#options.agent = normalizeClientAuthenticationAgent(this.#options)
        this.#options.privateKey = undefined
        this.#options.certificate = undefined
        this.#options.passphrase = undefined
        if (
            this.#options.ident !== undefined &&
            this.#options.protocolVersionExchange !== undefined
        ) {
            throw new TypeError(
                "SSH ident and protocolVersionExchange options are mutually exclusive",
            )
        }
        this.#options.protocolVersionExchange =
            this.#options.ident === undefined
                ? copyProtocolVersionExchange(
                      this.#options.protocolVersionExchange ?? ProtocolVersionExchange.defaultValue,
                  )
                : ProtocolVersionExchange.fromIdent(this.#options.ident)
        this.#options.authenticationMethodsOrder ??= [
            SSHAuthenticationMethods.None,
            ...(this.#options.gssapi.some(
                (mechanism) => mechanism.createKeyExchangeContext !== undefined,
            ) && this.#options.gssapiKeyExchangeAuthentication
                ? [SSHAuthenticationMethods.GSSAPIKeyExchange]
                : []),
            ...(this.#options.gssapi.some((mechanism) => mechanism.createContext !== undefined)
                ? [SSHAuthenticationMethods.GSSAPIWithMIC]
                : []),
            SSHAuthenticationMethods.PublicKey,
            SSHAuthenticationMethods.Password,
            SSHAuthenticationMethods.Hostbased,
        ]
        this.#options.authenticationMethodsOrder = [...this.#options.authenticationMethodsOrder]
        if (this.#options.authenticationMethodsOrder.length === 0) {
            throw new TypeError("SSH authentication method order must contain at least one method")
        }
        const configuredAuthenticationMethods = new Set<SSHAuthenticationMethods>()
        for (const method of this.#options.authenticationMethodsOrder) {
            if (!UserAuthRequest.auth_methods.has(method)) {
                throw new TypeError(
                    `SSH authentication method order contains an unsupported method: ${method}`,
                )
            }
            if (configuredAuthenticationMethods.has(method)) {
                throw new TypeError(
                    `SSH authentication method order contains duplicate method: ${method}`,
                )
            }
            configuredAuthenticationMethods.add(method)
        }
        if (
            this.#options.authenticationMethodsOrder.includes(
                SSHAuthenticationMethods.GSSAPIKeyExchange,
            ) &&
            !this.#options.gssapiKeyExchangeAuthentication
        ) {
            throw new TypeError(
                "gssapi-keyex authentication is disabled by gssapiKeyExchangeAuthentication",
            )
        }
        if (
            this.#options.authenticationMethodsOrder.includes(
                SSHAuthenticationMethods.GSSAPIKeyExchange,
            ) &&
            !this.#options.gssapi.some(
                (mechanism) => mechanism.createKeyExchangeContext !== undefined,
            )
        ) {
            throw new TypeError(
                "gssapi-keyex authentication requires a GSS-API key-exchange mechanism",
            )
        }
        this.#options.keepaliveInterval ??= 0
        this.#options.keepaliveCountMax ??= 3
        this.#options.rekeyBytes ??= DEFAULT_REKEY_BYTES
        this.#options.rekeyInterval ??= DEFAULT_REKEY_INTERVAL
        this.#options.readyTimeout ??= 20_000
        this.#options.replyTimeout ??= 30_000
        this.#options.maxPendingChannelOpens ??= 64
        this.#options.maxChannels ??= 1024
        if (
            !Number.isFinite(this.#options.keepaliveInterval) ||
            this.#options.keepaliveInterval < 0
        ) {
            throw new RangeError("SSH keepalive interval must be a non-negative number")
        }
        if (
            !Number.isInteger(this.#options.keepaliveCountMax) ||
            this.#options.keepaliveCountMax < 0
        ) {
            throw new RangeError("SSH keepalive count maximum must be a non-negative integer")
        }
        validateRekeyBytes(this.#options.rekeyBytes)
        validateRekeyInterval(this.#options.rekeyInterval)
        if (!Number.isFinite(this.#options.readyTimeout) || this.#options.readyTimeout < 0) {
            throw new RangeError("SSH ready timeout must be a non-negative number")
        }
        if (!Number.isFinite(this.#options.replyTimeout) || this.#options.replyTimeout <= 0) {
            throw new RangeError("SSH reply timeout must be a positive number")
        }
        if (
            !Number.isSafeInteger(this.#options.maxPendingChannelOpens) ||
            this.#options.maxPendingChannelOpens < 0
        ) {
            throw new RangeError(
                "SSH maximum pending channel opens must be a non-negative safe integer",
            )
        }
        if (!Number.isSafeInteger(this.#options.maxChannels) || this.#options.maxChannels < 0) {
            throw new RangeError(
                "SSH maximum simultaneous channels must be a non-negative safe integer",
            )
        }
        if (
            this.#options.localPort !== undefined &&
            (!Number.isInteger(this.#options.localPort) ||
                this.#options.localPort < 0 ||
                this.#options.localPort > 65_535)
        ) {
            throw new RangeError("SSH local port must be an integer between 0 and 65535")
        }
        if (this.#options.hostHash !== undefined) {
            try {
                crypto.createHash(this.#options.hostHash)
            } catch {
                throw new RangeError(
                    `Unsupported SSH host hash algorithm: ${this.#options.hostHash}`,
                )
            }
        }
        const gssapiKeyExchangeAlgorithms = createGSSAPIKeyExchangeAlgorithms(this.#options.gssapi)
        this.#kexAlgorithms = registerKeyExchanges(this, [
            ...kex_algorithms,
            ...gssapiKeyExchangeAlgorithms,
        ])
        this.algorithmOffer = resolveClientAlgorithmOptions(
            this.#options.algorithms,
            {
                kex: [...this.#kexAlgorithms.keys()],
                serverHostKey: [...host_key_algorithms.keys()],
                cipher: [...encryption_algorithms.keys()],
                hmac: [...mac_algorithm_names],
                compress: [...compression_algorithms.keys()],
            },
            {
                ...default_algorithm_names,
                kex: [...gssapiKeyExchangeAlgorithms.keys(), ...default_algorithm_names.kex],
            },
        )

        setImmediate(() => {
            this.debug("Client created with options:", clientDiagnosticSummary(this.#options))
        })

        if (this.#options.password) {
            this.hooker.hook("passwordAuth", async (controller, context, answer) => {
                // should not happen, but we've been given a
                // pair of username and password, we want them
                // to be used together.
                if (context.username != this.#options.username) return
                answer.password = this.#options.password
            })

            setImmediate(() => {
                this.debug("Password authentication handled by client options")
            })
        }
        registerClientConfiguration(this, this.#options)
        registerReplyTimeout(this, this.#options.replyTimeout, () => this.destroy())
    }

    hooker = new Hooker<ClientHooker>()

    private socket?: Duplex
    private identificationParser = new IdentificationParser({ allowPreamble: true })
    private readonly greetingChunks: Buffer[] = []
    readonly algorithmOffer: ResolvedAlgorithmOptions
    readonly #kexAlgorithms: ReadonlyMap<string, KexAlgorithmFactory>
    private packetDecoder = new BinaryPacketDecoder()
    private packetEncoder = new BinaryPacketEncoder()
    private packetProcessingPaused = false
    private strictKeyExchange = false
    private strictInitialExchange = false
    private readonly strictInitialPackets = new Set<PacketType>()

    serverProtocolVersion?: ProtocolVersionExchange
    #clientKexInit?: KexInit
    #clientKexInitPayload?: Buffer
    #serverKexInitPayload?: Buffer
    #kexAlgorithm?: KexAlgorithm
    #hostKeyAlgorithm?: HostKeyAlgorithm
    private initialHostKeySignatureAlgorithm?: string
    serverSignatureAlgorithms?: readonly string[]
    private negotiatedServerHostKey?: Buffer
    private hostboundAuthenticationSupported = false
    private negotiatedServerExtensions: readonly Readonly<SSHExtension>[] = Object.freeze([])
    private hostKeyUpdateSupported = false
    private hostKeysAdvertisementReceived = false
    private initialServerNewKeysReceived = false
    private serverExtInfoAfterNewKeys = false
    private serverExtInfoMustPrecedeSuccess = false
    private advertisedAuthenticationExtInfo = false
    private sentAuthenticationRequest = false
    private serverAuthenticationExtInfoReceived = false
    #clientEncryptionAlgorithm?: typeof EncryptionAlgorithm
    #serverEncryptionAlgorithm?: typeof EncryptionAlgorithm
    #clientEncryption?: EncryptionAlgorithm
    #serverEncryption?: EncryptionAlgorithm
    #clientMacAlgorithm?: typeof MACAlgorithm
    #serverMacAlgorithm?: typeof MACAlgorithm
    #clientMac?: MACAlgorithm
    #serverMac?: MACAlgorithm
    #clientCompressionAlgorithm?: CompressionAlgorithm
    #serverCompressionAlgorithm?: CompressionAlgorithm

    #exchangeHash?: Buffer
    #sessionID?: Buffer

    /** The most recent key exchange hash, returned as a defensive copy. */
    get exchangeHash(): Buffer | undefined {
        return this.#exchangeHash && Buffer.from(this.#exchangeHash)
    }

    /** The negotiated key exchange algorithm name. */
    get keyExchangeAlgorithm(): string | undefined {
        const kex = this.#kexAlgorithm
        return kex && (kex.constructor as typeof KexAlgorithm).alg_name
    }

    /** The currently active transport algorithm names. */
    get negotiatedAlgorithms(): Readonly<NegotiatedAlgorithms> | undefined {
        if (
            !this.#kexAlgorithm ||
            !this.#hostKeyAlgorithm ||
            !this.#clientEncryptionAlgorithm ||
            !this.#serverEncryptionAlgorithm ||
            !this.#clientCompressionAlgorithm ||
            !this.#serverCompressionAlgorithm
        ) {
            return undefined
        }
        return describeNegotiatedAlgorithms({
            keyExchange: this.#kexAlgorithm,
            hostKey: this.#hostKeyAlgorithm,
            clientEncryption: this.#clientEncryptionAlgorithm,
            serverEncryption: this.#serverEncryptionAlgorithm,
            clientMac: this.#clientMacAlgorithm,
            serverMac: this.#serverMacAlgorithm,
            clientCompression: this.#clientCompressionAlgorithm,
            serverCompression: this.#serverCompressionAlgorithm,
        })
    }

    get sessionID(): Buffer | undefined {
        return this.#sessionID && Buffer.from(this.#sessionID)
    }

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
    private readonly pendingRemoteChannelOpens = new Set<number>()
    private readonly pendingIncomingChannels = new Set<ClientChannel>()
    private readonly pendingGlobalRequests: PendingGlobalRequest[] = []
    private readonly pendingPings: PendingPing[] = []
    private transportPingSupported = false
    private rfc9987AgentForwardingSupported = false
    private noFlowControlEnabled = false
    private elevationResult?: boolean
    private pendingDelayCompression?: Readonly<NegotiatedDelayCompression>
    private delayCompressionRekeyBlocked = false
    private readonly remoteForwardings = new Map<string, RemoteForwarding>()
    private readonly pendingRemoteForwardings = new Set<string>()
    private readonly remoteStreamLocalForwardings = new Set<string>()
    private readonly pendingRemoteStreamLocalForwardings = new Set<string>()
    private readonly x11Forwardings = new Map<number, { single: boolean }>()
    agentForwardingEnabled = false
    private keepaliveTimer?: ReturnType<typeof setTimeout>
    private unansweredKeepalives = 0
    private readyTimer?: ReturnType<typeof setTimeout>
    private rekeyTimer?: ReturnType<typeof setTimeout>
    private automaticRekeyScheduled = false
    private keyExchangeInProgress = false
    private peerKexInitReceived = false
    private inboundNewKeysReady = false
    private readonly expectedInboundKeyExchangePackets = new Set<PacketType>()
    private discardNextGuessedKeyExchangePacket = false
    private readonly packetsQueuedDuringKeyExchange: Packet[] = []
    private actionQueue = new ActionQueue()
    private connectionGeneration = 0
    private initialGSSAPIKeyExchangeContext?: GSSAPIKeyExchangeClientContext

    get serverHostKey(): Buffer | undefined {
        return this.negotiatedServerHostKey ? Buffer.from(this.negotiatedServerHostKey) : undefined
    }

    get hostboundPublicKeyAuthentication(): boolean {
        return this.hostboundAuthenticationSupported
    }

    /** Whether the server advertised RFC 9987 agent forwarding version 0. */
    get rfc9987AgentForwarding(): boolean {
        return this.rfc9987AgentForwardingSupported
    }

    /** Whether RFC 8308 no-flow-control is active for this connection. */
    get noFlowControl(): boolean {
        return this.noFlowControlEnabled
    }

    async createGSSAPIKeyExchangeAuthenticationMIC(
        username: string,
        service: string,
    ): Promise<Buffer> {
        const context = this.initialGSSAPIKeyExchangeContext
        if (!context?.getMIC || !this.sessionID) {
            throw new Error("No initial GSS-API key-exchange context is available")
        }
        const input = buildGSSAPIKeyExchangeUserAuthMIC(this.sessionID, username, service)
        try {
            return normalizeGSSAPIToken(
                await context.getMIC(input),
                "GSS-API key-exchange authentication MIC",
            )
        } finally {
            if (this.initialGSSAPIKeyExchangeContext === context) {
                this.initialGSSAPIKeyExchangeContext = undefined
            }
            await closeGSSAPIContext(context)
        }
    }

    get serverExtensions(): readonly Readonly<SSHExtension>[] {
        return copySSHExtensions(this.negotiatedServerExtensions)
    }

    /** The server's RFC 8308 elevation result, once reported after authentication. */
    get elevated(): boolean | undefined {
        return this.elevationResult
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
        this.connectionGeneration++
        this.packetEncoder.dispose()
        this.packetDecoder.dispose()
        this.disposeTransportAlgorithms()
        void this.closeInitialGSSAPIKeyExchangeContext().catch(() =>
            this.debug("Could not close the initial GSS-API key-exchange context"),
        )
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
        this.#clientKexInit = undefined
        this.#clientKexInitPayload = undefined
        this.#serverKexInitPayload = undefined
        this.#kexAlgorithm = undefined
        this.#hostKeyAlgorithm = undefined
        this.initialHostKeySignatureAlgorithm = undefined
        this.serverSignatureAlgorithms = undefined
        this.negotiatedServerHostKey = undefined
        this.hostboundAuthenticationSupported = false
        this.negotiatedServerExtensions = Object.freeze([])
        this.hostKeyUpdateSupported = false
        this.hostKeysAdvertisementReceived = false
        this.initialServerNewKeysReceived = false
        this.serverExtInfoAfterNewKeys = false
        this.serverExtInfoMustPrecedeSuccess = false
        this.advertisedAuthenticationExtInfo = false
        this.sentAuthenticationRequest = false
        this.serverAuthenticationExtInfoReceived = false
        this.#clientEncryptionAlgorithm = undefined
        this.#serverEncryptionAlgorithm = undefined
        this.#clientEncryption = undefined
        this.#serverEncryption = undefined
        this.#clientMacAlgorithm = undefined
        this.#serverMacAlgorithm = undefined
        this.#clientMac = undefined
        this.#serverMac = undefined
        this.#clientCompressionAlgorithm = undefined
        this.#serverCompressionAlgorithm = undefined

        this.#exchangeHash = undefined
        this.#sessionID = undefined
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
        this.pendingRemoteChannelOpens.clear()
        for (const channel of this.pendingIncomingChannels) channel.abort()
        this.pendingIncomingChannels.clear()
        this.pendingGlobalRequests.length = 0
        this.pendingPings.length = 0
        this.transportPingSupported = false
        this.rfc9987AgentForwardingSupported = false
        this.noFlowControlEnabled = false
        this.elevationResult = undefined
        this.pendingDelayCompression = undefined
        this.delayCompressionRekeyBlocked = this.#options.delayCompression !== false
        this.remoteForwardings.clear()
        this.pendingRemoteForwardings.clear()
        this.remoteStreamLocalForwardings.clear()
        this.pendingRemoteStreamLocalForwardings.clear()
        this.x11Forwardings.clear()
        this.agentForwardingEnabled = false
        this.unansweredKeepalives = 0
        this.clearRekeyTimer()
        this.automaticRekeyScheduled = false
        this.keyExchangeInProgress = false
        this.inboundNewKeysReady = false
        this.expectedInboundKeyExchangePackets.clear()
        this.discardNextGuessedKeyExchangePacket = false
        this.packetsQueuedDuringKeyExchange.length = 0
        this.actionQueue.close(new Error("SSH connection action queue was reset"))
        this.actionQueue = new ActionQueue()
    }

    private assertConnectionGeneration(generation: number, operation: string): void {
        if (
            generation !== this.connectionGeneration ||
            this.state === SocketState.Closed ||
            this.state === SocketState.Disconnected ||
            !this.socket ||
            this.socket.destroyed
        ) {
            throw new Error(`SSH connection closed or was replaced during ${operation}`)
        }
    }

    private async closeInitialGSSAPIKeyExchangeContext(): Promise<void> {
        const context = this.initialGSSAPIKeyExchangeContext
        this.initialGSSAPIKeyExchangeContext = undefined
        if (context) await closeGSSAPIContext(context)
    }

    debug(...message: unknown[]): void {
        this.#options.debug?.(...message)
        this.emit("debug", ...message)
    }

    setNoDelay(noDelay = true): this {
        if (this.socket && "setNoDelay" in this.socket) {
            ;(this.socket as net.Socket).setNoDelay(noDelay)
        }
        return this
    }

    assertOpenSSHVendor(): void {
        if (!this.#options.strictVendor) return
        const software = this.serverProtocolVersion?.protocol_software ?? ""
        if (/^OpenSSH_(?:[5-9]|[1-9]\d)/u.test(software)) return
        throw new Error("strictVendor enabled and server is not OpenSSH or compatible version")
    }

    rekey(): Promise<void> {
        if (this.sessionID === undefined || !this.socket || this.socket.destroyed) {
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
        return waitForReply(this, this.performKeyExchange(), "key exchange").catch(
            (error: unknown) => {
                this.destroy()
                throw error
            },
        )
    }

    ping(data: Buffer = Buffer.alloc(0)): Promise<Buffer> {
        if (!this.isConnected) {
            return Promise.reject(new Error("Cannot ping before the SSH connection is ready"))
        }
        if (!this.transportPingSupported) {
            return Promise.reject(new Error("SSH server did not advertise transport ping support"))
        }
        if (!Buffer.isBuffer(data)) {
            return Promise.reject(new TypeError("SSH transport ping data must be a buffer"))
        }
        const sent = Buffer.from(data)
        const response = new Promise<Buffer>((resolve, reject) => {
            this.pendingPings.push({ data: sent, resolve, reject })
            try {
                this.sendPacket(new Ping({ data: sent }))
            } catch (error) {
                this.pendingPings.pop()
                reject(error as Error)
            }
        })
        return waitForReply(this, response, "transport ping reply")
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

    globalRequest(name: string, args: Buffer = Buffer.alloc(0)): Promise<Buffer> {
        try {
            this.validateGlobalRequest(name, args)
            return this.sendGlobalRequest(name, Buffer.from(args))
        } catch (error) {
            return Promise.reject(error as Error)
        }
    }

    openSession(): Promise<ClientSessionChannel> {
        return this.openSessionChannel()
    }

    exec(command: string, options: ClientSessionOptions = {}): Promise<ClientSessionChannel> {
        const sessionOptions = snapshotSessionOptions(options)
        return this.openSessionChannel().then(async (channel) => {
            try {
                await this.configureSession(channel, sessionOptions, false)
                await channel.exec(command)
                return channel
            } catch (error) {
                channel.close()
                throw error
            }
        })
    }

    shell(options: ClientSessionOptions = {}): Promise<ClientSessionChannel> {
        const sessionOptions = snapshotSessionOptions(options)
        return this.openSessionChannel().then(async (channel) => {
            try {
                await this.configureSession(channel, sessionOptions, true)
                await channel.shell()
                return channel
            } catch (error) {
                channel.close()
                throw error
            }
        })
    }

    subsystem(name: string): Promise<ClientSessionChannel> {
        return this.openSessionChannel().then(async (channel) => {
            try {
                await channel.subsystem(name)
                return channel
            } catch (error) {
                channel.close()
                throw error
            }
        })
    }

    subsys(name: string): Promise<ClientSessionChannel> {
        return this.subsystem(name)
    }

    openssh_noMoreSessions(): Promise<void> {
        return this.requestNoMoreSessions()
    }

    opensshNoMoreSessions(): Promise<void> {
        return this.requestNoMoreSessions()
    }

    sftp(
        environment: ClientEnvironment = {},
        options: SFTPClientOptions = {},
    ): Promise<SFTPClient> {
        const sessionEnvironment = { ...environment }
        const sftpOptions = { ...options }
        return this.openSessionChannel().then(async (channel) => {
            try {
                for (const [name, value] of Object.entries(sessionEnvironment)) {
                    await channel.setEnv(name, value, false)
                }
                await channel.subsystem("sftp")
                const software = this.serverProtocolVersion?.protocol_software ?? ""
                return await SFTPClient.connect(
                    channel,
                    /^(?:OpenSSH_|dropbear)/iu.test(software),
                    {
                        requestTimeout: sftpOptions.requestTimeout ?? this.#options.replyTimeout,
                    },
                )
            } catch (error) {
                channel.close()
                throw error
            }
        })
    }

    publicKeySubsystem(
        options: PublicKeySubsystemClientOptions = {},
    ): Promise<PublicKeySubsystemClient> {
        const subsystemOptions = { ...options }
        return this.openSessionChannel().then(async (channel) => {
            try {
                await channel.subsystem("publickey")
                return await PublicKeySubsystemClient.connect(channel, {
                    requestTimeout: subsystemOptions.requestTimeout ?? this.#options.replyTimeout,
                })
            } catch (error) {
                channel.close()
                throw error
            }
        })
    }

    forwardOut(
        sourceHost: string,
        sourcePort: number,
        destinationHost: string,
        destinationPort: number,
    ): Promise<ClientTCPIPChannel> {
        return this.openClientChannel(
            new ClientTCPIPChannel(this, {
                sourceHost,
                sourcePort,
                destinationHost,
                destinationPort,
            }),
        )
    }

    forwardIn(bindAddress: string, bindPort: number): Promise<number> {
        return this.requestRemoteForward(bindAddress, bindPort)
    }

    unforwardIn(bindAddress: string, bindPort: number): Promise<void> {
        return this.cancelRemoteForward(bindAddress, bindPort)
    }

    openssh_forwardOutStreamLocal(socketPath: string): Promise<ClientDirectStreamLocalChannel> {
        try {
            this.assertOpenSSHVendor()
        } catch (error) {
            return Promise.reject(error)
        }
        this.validateSocketPath(socketPath)
        return this.openClientChannel(new ClientDirectStreamLocalChannel(this, socketPath))
    }

    openssh_openTunnel(
        mode: TunnelMode,
        unit: number = AUTOMATIC_TUNNEL_UNIT,
    ): Promise<ClientTunnelChannel> {
        try {
            this.assertOpenSSHVendor()
            return this.openClientChannel(new ClientTunnelChannel(this, mode, unit))
        } catch (error) {
            return Promise.reject(error)
        }
    }

    openssh_forwardInStreamLocal(socketPath: string): Promise<void> {
        return this.requestRemoteStreamLocalForward(socketPath)
    }

    openssh_unforwardInStreamLocal(socketPath: string): Promise<void> {
        return this.cancelRemoteStreamLocalForward(socketPath)
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
        if (options.agentForward ?? this.#options.agentForward) {
            await channel.forwardAgent()
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
        this.assertChannelCapacity()

        this.channels.set(channel.localId, channel)
        try {
            this.sendPacket(channel.getOpenPacket())
            await waitForReply(this, channel.waitUntilOpen(), `channel ${channel.localId} open`)
            return channel
        } catch (error) {
            this.channels.delete(channel.localId)
            channel.destroy()
            throw error
        }
    }

    private async handleServerHostKeys(packet: GlobalRequest, generation: number): Promise<void> {
        const publicKeys: PublicKey[] = []
        const seen = new Set<string>()
        const parsed = new Set<string>()
        let count = 0
        let raw = packet.data.args
        while (raw.length !== 0) {
            let encoded: Buffer
            try {
                ;[encoded, raw] = readNextBuffer(raw)
            } catch {
                throw new ProtocolError("Malformed SSH host-key advertisement")
            }
            count++
            if (count > MAX_HOST_KEYS_PER_REQUEST) {
                throw new ProtocolError(
                    `SSH host-key advertisement exceeds the ${MAX_HOST_KEYS_PER_REQUEST}-key limit`,
                )
            }
            const identity = encoded.toString("base64")
            if (seen.has(identity)) {
                if (packet.data.request_name === HOST_KEYS_REQUEST) {
                    throw new ProtocolError("Standard SSH host-key advertisement repeats a key")
                }
                continue
            }
            seen.add(identity)
            try {
                const publicKey = PublicKey.parse(encoded)
                const parsedIdentity = publicKey.serialize().toString("base64")
                if (parsed.has(parsedIdentity)) {
                    if (packet.data.request_name === HOST_KEYS_REQUEST) {
                        throw new ProtocolError("Standard SSH host-key advertisement repeats a key")
                    }
                    continue
                }
                parsed.add(parsedIdentity)
                publicKeys.push(publicKey)
            } catch (error) {
                if (error instanceof ProtocolError) throw error
                this.debug("Ignoring an unsupported advertised SSH host key:", error)
            }
        }
        if (count === 0) {
            throw new ProtocolError("SSH host-key advertisement contains no keys")
        }
        if (publicKeys.length === 0) return
        if (generation !== this.connectionGeneration) return
        assert(this.sessionID, "SSH host-key proof requires an established session")
        const useStandardNames =
            packet.data.request_name === HOST_KEYS_REQUEST || this.hostKeyUpdateSupported
        const proofRequest = useStandardNames
            ? HOST_KEYS_PROOF_REQUEST
            : LEGACY_HOST_KEYS_PROOF_REQUEST
        const proofDomain: HostKeysProofDomain = useStandardNames
            ? HOST_KEYS_PROOF_DOMAIN
            : LEGACY_HOST_KEYS_PROOF_REQUEST
        const initialSignatureAlgorithm = this.initialHostKeySignatureAlgorithm
        if (initialSignatureAlgorithm === "ssh-rsa") {
            this.debug("Not requesting SSH host-key proofs after an initial RSA-SHA1 exchange")
            return
        }
        const rsaSignatureAlgorithm: RSASHA2SignatureAlgorithm | undefined =
            initialSignatureAlgorithm === "rsa-sha2-256" ||
            initialSignatureAlgorithm === "rsa-sha2-512"
                ? initialSignatureAlgorithm
                : undefined
        let response: Buffer
        try {
            response = await this.sendGlobalRequest(
                proofRequest,
                Buffer.concat(
                    publicKeys.map((publicKey) => serializeBuffer(publicKey.serialize())),
                ),
            )
        } catch (error) {
            if (error instanceof GlobalRequestError) {
                this.debug("SSH server declined the host-key proof request")
                return
            }
            throw error
        }
        if (generation !== this.connectionGeneration) return
        let verified: readonly PublicKey[]
        try {
            verified = parseHostKeysProofResponse(
                this.sessionID,
                publicKeys,
                response,
                proofDomain,
                rsaSignatureAlgorithm,
            )
        } catch {
            throw new ProtocolError("Malformed SSH host-key proof response")
        }
        this.debug(`Verified ${verified.length} of ${publicKeys.length} advertised SSH host keys`)
        if (verified.length !== 0) this.emit("hostKeys", verified)
    }

    private async handleServerGlobalRequest(
        packet: GlobalRequest,
        generation: number,
    ): Promise<void> {
        if (generation !== this.connectionGeneration) return
        this.debug(`Received global request packet:`, packet)

        if (packet.data.request_name === ELEVATION_EXTENSION && this.#options.elevation !== false) {
            if (packet.data.want_reply || packet.data.args.length !== 1) {
                throw new ProtocolError(
                    "SSH elevation result must be a one-way request containing one boolean",
                )
            }
            if (this.elevationResult !== undefined) {
                throw new ProtocolError("SSH server sent more than one elevation result")
            }
            ;[this.elevationResult] = readNextBinaryBoolean(packet.data.args)
            this.emit("elevation", this.elevationResult)
            return
        }

        if (
            packet.data.request_name === HOST_KEYS_REQUEST ||
            packet.data.request_name === LEGACY_HOST_KEYS_REQUEST
        ) {
            if (!this.isConnected) await this.#waitEvent("connect")
            if (generation !== this.connectionGeneration) return
            if (packet.data.want_reply) {
                throw new ProtocolError("SSH host-key advertisements must not request a reply")
            }
            if (this.hostKeysAdvertisementReceived) {
                throw new ProtocolError("SSH server sent more than one host-key advertisement")
            }
            this.hostKeysAdvertisementReceived = true
            await this.handleServerHostKeys(packet, generation)
            return
        }

        this.debug(`Unknown global request name: ${packet.data.request_name}`)
        const context: ClientHookerGlobalRequestContext = Object.freeze({
            name: packet.data.request_name,
            args: Buffer.from(packet.data.args),
            wantReply: packet.data.want_reply,
        })
        const controller: ClientHookerGlobalRequestController = { success: false }
        const policyCompleted = await this.hooker.triggerHookChecked(
            "globalRequest",
            context,
            controller,
        )
        if (!this.isConnected || generation !== this.connectionGeneration) return
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

    private async requestRemoteForward(bindAddress: string, bindPort: number): Promise<number> {
        this.validatePort(bindPort, "remote forwarding port")
        const requestedKey =
            bindPort === 0 ? undefined : this.remoteForwardingKey(bindAddress, bindPort)
        if (
            requestedKey !== undefined &&
            (this.remoteForwardings.has(requestedKey) ||
                this.pendingRemoteForwardings.has(requestedKey))
        ) {
            throw new Error(`Remote forwarding already exists for ${bindAddress}:${bindPort}`)
        }
        if (requestedKey !== undefined) this.pendingRemoteForwardings.add(requestedKey)
        try {
            const args = Buffer.concat([
                serializeBuffer(encodeSSHUTF8(bindAddress, "TCP forwarding bind address")),
                serializeUint32(bindPort),
            ])
            const response = await this.sendGlobalRequest("tcpip-forward", args)
            let actualPort = bindPort
            if (bindPort === 0) {
                if (response.length !== 4) {
                    this.failGlobalRequestResponse(
                        "Invalid allocated port in tcpip-forward success response",
                    )
                }
                ;[actualPort] = readNextUint32(response)
                if (actualPort === 0 || actualPort > 65_535) {
                    this.failGlobalRequestResponse(
                        "Invalid allocated port in tcpip-forward success response",
                    )
                }
            } else if (response.length !== 0) {
                this.failGlobalRequestResponse("Unexpected data in tcpip-forward success response")
            }

            const key = this.remoteForwardingKey(bindAddress, actualPort)
            if (this.remoteForwardings.has(key)) {
                this.failGlobalRequestResponse(
                    `Server allocated an active remote forwarding port for ${bindAddress}:${actualPort}`,
                )
            }
            this.remoteForwardings.set(key, { bindAddress, bindPort: actualPort })
            return actualPort
        } finally {
            if (requestedKey !== undefined) this.pendingRemoteForwardings.delete(requestedKey)
        }
    }

    private async requestNoMoreSessions(): Promise<void> {
        this.assertOpenSSHVendor()
        const response = await this.sendGlobalRequest(
            "no-more-sessions@openssh.com",
            Buffer.alloc(0),
        )
        if (response.length !== 0) {
            this.failGlobalRequestResponse("Unexpected data in no-more-sessions success response")
        }
    }

    private async cancelRemoteForward(bindAddress: string, bindPort: number): Promise<void> {
        this.validatePort(bindPort, "remote forwarding port")
        const key = this.remoteForwardingKey(bindAddress, bindPort)
        if (!this.remoteForwardings.has(key)) {
            throw new Error(`No remote forwarding exists for ${bindAddress}:${bindPort}`)
        }
        const response = await this.sendGlobalRequest(
            "cancel-tcpip-forward",
            Buffer.concat([
                serializeBuffer(encodeSSHUTF8(bindAddress, "TCP forwarding bind address")),
                serializeUint32(bindPort),
            ]),
        )
        if (response.length !== 0) {
            this.failGlobalRequestResponse(
                "Unexpected data in cancel-tcpip-forward success response",
            )
        }
        this.remoteForwardings.delete(key)
    }

    private async requestRemoteStreamLocalForward(socketPath: string): Promise<void> {
        this.assertOpenSSHVendor()
        this.validateSocketPath(socketPath)
        if (
            this.remoteStreamLocalForwardings.has(socketPath) ||
            this.pendingRemoteStreamLocalForwardings.has(socketPath)
        ) {
            throw new Error(`Remote stream-local forwarding already exists for ${socketPath}`)
        }
        this.pendingRemoteStreamLocalForwardings.add(socketPath)
        try {
            const response = await this.sendGlobalRequest(
                "streamlocal-forward@openssh.com",
                serializeBuffer(encodeSSHUTF8(socketPath, "stream-local forwarding socket path")),
            )
            if (response.length !== 0) {
                this.failGlobalRequestResponse(
                    "Unexpected data in streamlocal-forward success response",
                )
            }
            this.remoteStreamLocalForwardings.add(socketPath)
        } finally {
            this.pendingRemoteStreamLocalForwardings.delete(socketPath)
        }
    }

    private async cancelRemoteStreamLocalForward(socketPath: string): Promise<void> {
        this.assertOpenSSHVendor()
        this.validateSocketPath(socketPath)
        if (!this.remoteStreamLocalForwardings.has(socketPath)) {
            throw new Error(`No remote stream-local forwarding exists for ${socketPath}`)
        }
        const response = await this.sendGlobalRequest(
            "cancel-streamlocal-forward@openssh.com",
            serializeBuffer(encodeSSHUTF8(socketPath, "stream-local forwarding socket path")),
        )
        if (response.length !== 0) {
            this.failGlobalRequestResponse(
                "Unexpected data in cancel-streamlocal-forward success response",
            )
        }
        this.remoteStreamLocalForwardings.delete(socketPath)
    }

    private sendGlobalRequest(name: string, args: Buffer, bounded = true): Promise<Buffer> {
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
        return bounded ? waitForReply(this, response, `global request ${name} reply`) : response
    }

    private validateGlobalRequest(name: string, args: Buffer): void {
        if (!/^[\x21-\x7e]+$/u.test(name)) {
            throw new TypeError("SSH global request name must be non-empty printable ASCII")
        }
        if (!Buffer.isBuffer(args)) {
            throw new TypeError("SSH global request arguments must be a buffer")
        }
    }

    private failGlobalRequestResponse(message: string): never {
        const error = new ProtocolError(message)
        this.disconnect(error)
        throw error
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
                    language_tag: error.languageTag,
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

    private installDerivedTransportKeys(kex: KexAlgorithm, exchangeHash: Buffer): void {
        assert(this.#sessionID, "SSH session identifier is unavailable")
        assert(this.#clientEncryptionAlgorithm && this.#serverEncryptionAlgorithm)
        let keys: ReturnType<KexAlgorithm["deriveTransportKeys"]> | undefined
        try {
            keys = kex.deriveTransportKeys(exchangeHash, this.#sessionID, {
                clientIV: this.#clientEncryptionAlgorithm.iv_length,
                serverIV: this.#serverEncryptionAlgorithm.iv_length,
                clientEncryption: this.#clientEncryptionAlgorithm.key_length,
                serverEncryption: this.#serverEncryptionAlgorithm.key_length,
                clientIntegrity: this.#clientMacAlgorithm?.key_length ?? 0,
                serverIntegrity: this.#serverMacAlgorithm?.key_length ?? 0,
            })
            const instantiated = instantiateTransportAlgorithms(
                {
                    clientEncryption: this.#clientEncryptionAlgorithm,
                    serverEncryption: this.#serverEncryptionAlgorithm,
                    clientMac: this.#clientMacAlgorithm,
                    serverMac: this.#serverMacAlgorithm,
                },
                keys,
            )
            this.#clientEncryption = instantiated.clientEncryption
            this.#serverEncryption = instantiated.serverEncryption
            this.#clientMac = instantiated.clientMac
            this.#serverMac = instantiated.serverMac
        } finally {
            if (keys) for (const key of Object.values(keys)) key.fill(0)
            kex.dispose()
        }
    }

    private disposeTransportAlgorithms(): void {
        const algorithms = [
            this.#clientEncryption,
            this.#serverEncryption,
            this.#clientMac,
            this.#serverMac,
        ]
        this.#clientEncryption = undefined
        this.#serverEncryption = undefined
        this.#clientMac = undefined
        this.#serverMac = undefined
        for (const algorithm of algorithms) algorithm?.dispose?.()
    }

    private installOutboundCompression(): void {
        assert(this.#clientCompressionAlgorithm, "Client compression algorithm not selected")
        this.packetEncoder.setCompression(
            createPacketCompressor(this.#clientCompressionAlgorithm, this.hasAuthenticated),
        )
    }

    private installInboundCompression(): void {
        assert(this.#serverCompressionAlgorithm, "Server compression algorithm not selected")
        this.packetDecoder.setCompression(
            createPacketDecompressor(this.#serverCompressionAlgorithm, this.hasAuthenticated),
        )
    }

    private activateAuthenticatedServerCompression(): void {
        if (this.pendingDelayCompression) {
            this.#serverCompressionAlgorithm = compression_algorithms.get(
                this.pendingDelayCompression.serverToClient,
            )
            assert(this.#serverCompressionAlgorithm)
            this.installInboundCompression()
        } else if (this.#serverCompressionAlgorithm?.delayed) {
            this.installInboundCompression()
        }
    }

    private triggerAuthenticatedClientCompression(): void {
        if (this.pendingDelayCompression) {
            this.sendPacket(new NewCompress())
            this.#clientCompressionAlgorithm = compression_algorithms.get(
                this.pendingDelayCompression.clientToServer,
            )
            assert(this.#clientCompressionAlgorithm)
            this.installOutboundCompression()
            this.pendingDelayCompression = undefined
        } else if (this.#clientCompressionAlgorithm?.delayed) {
            this.installOutboundCompression()
        }
        this.delayCompressionRekeyBlocked = false
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

    private createKeyExchangeHashContext(
        serverHostKey: Buffer,
        clientExchangeValue?: Buffer,
        serverExchangeValue?: Buffer,
    ): Readonly<KeyExchangeHashContext> {
        assert(this.serverProtocolVersion, "Missing server protocol version")
        assert(this.#clientKexInitPayload, "Missing exact client KEXINIT payload")
        assert(this.#serverKexInitPayload, "Missing exact server KEXINIT payload")
        return {
            clientVersion: this.#options.protocolVersionExchange.toString().slice(0, -2),
            serverVersion: this.serverProtocolVersion.toString().slice(0, -2),
            clientKexInit: this.#clientKexInitPayload,
            serverKexInit: this.#serverKexInitPayload,
            serverHostKey,
            ...(clientExchangeValue === undefined ? {} : { clientExchangeValue }),
            ...(serverExchangeValue === undefined ? {} : { serverExchangeValue }),
        }
    }

    private async performGSSAPIKeyExchange(
        algorithm: GSSAPIKeyExchange,
        retainContext: boolean,
        generation: number,
    ): Promise<{
        hostKey: Buffer
        exchangeHash: Buffer
        context?: GSSAPIKeyExchangeClientContext
    }> {
        const context = await algorithm.createClientContext({
            hostname: this.#options.hostname,
            service: "host",
            delegateCredentials: this.#options.gssapiDelegateCredentials,
            anonymous: !retainContext,
            mutualAuthentication: true,
            integrity: true,
            replayDetection: false,
            sequenceDetection: false,
        })
        assertGSSAPIKeyExchangeClientContext(context)
        let packets: PacketEventQueue | undefined
        let hostKey: Buffer | undefined
        let receivedContextMessage = false
        let contextRetained = false
        try {
            this.assertConnectionGeneration(generation, "GSS-API key exchange")
            packets = new PacketEventQueue(
                this,
                () => new KeyExchangeError("Connection closed during GSS-API key exchange"),
            )
            algorithm.generateKeyPair("client")
            let step = normalizeGSSAPIKeyExchangeContextStep(await context.step())
            this.assertConnectionGeneration(generation, "GSS-API key exchange")
            const initialToken = requireGSSAPIKeyExchangeToken(step.token)
            this.expectInboundKeyExchange(
                KexGSSAPIContinue.type,
                KexGSSAPIComplete.type,
                KexGSSAPIHostKey.type,
                KexGSSAPIError.type,
            )
            const clientExchangeValue = algorithm.getPublicKey()
            this.sendPacket(
                new KexGSSAPIInit(
                    initialToken,
                    clientExchangeValue,
                    algorithm.exchangeValueEncoding,
                ),
            )

            while (true) {
                this.expectInboundKeyExchange(
                    KexGSSAPIContinue.type,
                    KexGSSAPIComplete.type,
                    KexGSSAPIHostKey.type,
                    KexGSSAPIError.type,
                )
                this.resumePacketProcessing()
                const packet = await packets.next()
                this.assertConnectionGeneration(generation, "GSS-API key exchange")
                if (packet instanceof KexGSSAPIHostKey) {
                    if (hostKey || receivedContextMessage) {
                        throw new KeyExchangeError("Server sent an out-of-order GSS-API host key")
                    }
                    hostKey = Buffer.from(packet.hostKey)
                    continue
                }
                if (packet instanceof KexGSSAPIError) {
                    receivedContextMessage = true
                    this.emit("gssapiKeyExchangeError", packet.data)
                    continue
                }
                if (packet instanceof KexGSSAPIContinue) {
                    receivedContextMessage = true
                    if (step.complete) {
                        throw new KeyExchangeError(
                            "Server continued after the GSS-API client context completed",
                        )
                    }
                    step = normalizeGSSAPIKeyExchangeContextStep(await context.step(packet.token))
                    this.assertConnectionGeneration(generation, "GSS-API key exchange")
                    this.sendPacket(
                        new KexGSSAPIContinue(requireGSSAPIKeyExchangeToken(step.token)),
                    )
                    continue
                }
                if (!(packet instanceof KexGSSAPIComplete)) {
                    throw new KeyExchangeError("Unexpected packet during GSS-API key exchange")
                }
                receivedContextMessage = true
                if (packet.token !== undefined) {
                    if (step.complete) {
                        throw new KeyExchangeError(
                            "Server sent a final token after the GSS-API client context completed",
                        )
                    }
                    step = normalizeGSSAPIKeyExchangeContextStep(await context.step(packet.token))
                    this.assertConnectionGeneration(generation, "GSS-API key exchange")
                    if (step.token !== undefined) {
                        throw new KeyExchangeError(
                            "GSS-API client produced a token after processing the final server token",
                        )
                    }
                }
                if (!step.complete) {
                    throw new KeyExchangeError(
                        "Server completed key exchange before the GSS-API client context",
                    )
                }
                if (!step.integrity || !step.mutualAuthentication) {
                    throw new KeyExchangeError(
                        "GSS-API key exchange requires integrity and mutual authentication",
                    )
                }
                const authenticatedHostKey = hostKey ?? Buffer.alloc(0)
                algorithm.computeSharedSecret(packet.publicKey)
                const exchangeHash = algorithm.computeExchangeHash(
                    this.createKeyExchangeHashContext(
                        authenticatedHostKey,
                        clientExchangeValue,
                        packet.publicKey,
                    ),
                )
                const validMIC = await context.verifyMIC(exchangeHash, packet.mic)
                this.assertConnectionGeneration(generation, "GSS-API key exchange")
                if (!validMIC) {
                    throw new KeyExchangeError("Invalid GSS-API key-exchange MIC")
                }
                if (retainContext) {
                    if (!context.getMIC) {
                        throw new KeyExchangeError(
                            "GSS-API context cannot authenticate with gssapi-keyex",
                        )
                    }
                    contextRetained = true
                }
                return {
                    hostKey: authenticatedHostKey,
                    exchangeHash,
                    context: contextRetained ? context : undefined,
                }
            }
        } catch (error) {
            if (
                generation === this.connectionGeneration &&
                error instanceof GSSAPIError &&
                error.token &&
                this.socket?.writable
            ) {
                this.sendPacket(new KexGSSAPIContinue(error.token))
            }
            if (error instanceof KeyExchangeError) throw error
            throw new KeyExchangeError(
                error instanceof Error ? error.message : "GSS-API key exchange failed",
            )
        } finally {
            packets?.close()
            if (!contextRetained) await closeGSSAPIContext(context)
        }
    }

    private async performKeyExchange(peerInitiated = false): Promise<void> {
        if (this.keyExchangeInProgress) {
            throw new Error("SSH key exchange is already in progress")
        }
        const generation = this.connectionGeneration
        const isRekey = this.sessionID !== undefined
        let negotiatedKeyExchange: KexAlgorithm | undefined
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
        this.clearKeepalive()
        this.hasReceivedNewKeys = false
        this.hasSentNewKeys = false

        try {
            this.#clientKexInit = this.createKexInit()
            this.sendPacket(this.#clientKexInit)
            if (!peerInitiated) {
                await this.#waitEvent("serverKexInit")
                this.assertConnectionGeneration(generation, "key exchange")
            }
            const serverKexInitBuffer = this.#serverKexInitPayload
            assert(serverKexInitBuffer, "Missing exact server KEXINIT payload")
            const serverKexInit = KexInit.parse(serverKexInitBuffer)
            this.strictKeyExchange ||= negotiatesStrictKeyExchange(
                this.#clientKexInit.data.kex_algorithms,
                serverKexInit.data.kex_algorithms,
            )
            const algorithms = chooseAlgorithms({
                clientOffer: this.#clientKexInit.data,
                serverOffer: serverKexInit.data,
                keyExchanges: this.#kexAlgorithms,
                debug: this.debug.bind(this),
            })
            this.#kexAlgorithm = algorithms.keyExchange
            this.#hostKeyAlgorithm = algorithms.hostKey
            if (!isRekey) {
                this.initialHostKeySignatureAlgorithm = algorithms.hostKey.signature_algorithm
            }
            this.#clientEncryptionAlgorithm = algorithms.clientEncryption
            this.#serverEncryptionAlgorithm = algorithms.serverEncryption
            this.#clientMacAlgorithm = algorithms.clientMac
            this.#serverMacAlgorithm = algorithms.serverMac
            this.#clientCompressionAlgorithm = algorithms.clientCompression
            this.#serverCompressionAlgorithm = algorithms.serverCompression
            this.discardNextGuessedKeyExchangePacket =
                this.shouldDiscardGuessedPacket(serverKexInit)

            const kexAlgorithm = this.#kexAlgorithm
            assert(kexAlgorithm, "No key exchange algorithm was negotiated")
            negotiatedKeyExchange = kexAlgorithm
            let hostKeyBlob: Buffer
            let signatureBlob: Buffer | undefined
            let h: Buffer | undefined
            let clientExchangeValue: Buffer | undefined
            let serverExchangeValue: Buffer | undefined
            if (kexAlgorithm instanceof GSSAPIKeyExchange) {
                const result = await this.performGSSAPIKeyExchange(
                    kexAlgorithm,
                    !isRekey &&
                        this.#options.authenticationMethodsOrder.includes(
                            SSHAuthenticationMethods.GSSAPIKeyExchange,
                        ),
                    generation,
                )
                this.assertConnectionGeneration(generation, "GSS-API key exchange")
                hostKeyBlob = result.hostKey
                h = result.exchangeHash
                this.initialGSSAPIKeyExchangeContext = result.context
            } else if (kexAlgorithm instanceof DiffieHellmanGroupExchange) {
                this.expectInboundKeyExchange(PacketNameToType.SSH_MSG_KEXDH_REPLY)
                kexAlgorithm.setRequest(defaultGroupExchangeRequest)
                this.sendPacket(new KexDHGexRequest(defaultGroupExchangeRequest))
                const [group] = await this.#waitEvent("serverKexDHGexGroup")
                this.assertConnectionGeneration(generation, "key exchange")
                kexAlgorithm.acceptServerGroup(group.data.p, group.data.g)
                kexAlgorithm.generateKeyPair()
                clientExchangeValue = kexAlgorithm.getPublicKey()
                this.sendPacket(new KexDHGexInit({ e: clientExchangeValue }))
                this.expectInboundKeyExchange(PacketNameToType.SSH_MSG_KEX_DH_GEX_REPLY)
                const reply = (await this.#waitEvent("serverKexDHGexReply"))[0]
                this.assertConnectionGeneration(generation, "key exchange")
                kexAlgorithm.computeSharedSecret(reply.data.f)
                serverExchangeValue = reply.data.f
                hostKeyBlob = reply.data.K_S
                signatureBlob = reply.data.H_sig
            } else if (kexAlgorithm instanceof RSA2048SHA256) {
                this.expectInboundKeyExchange(PacketNameToType.SSH_MSG_KEXDH_INIT)
                const [publicKey] = await this.#waitEvent("serverKexRSAPublicKey")
                this.assertConnectionGeneration(generation, "key exchange")
                kexAlgorithm.setServerKeys(publicKey.data.hostKey, publicKey.data.transientKey)
                this.sendPacket(
                    new KexRSASecret({ encryptedSecret: kexAlgorithm.generateSecret() }),
                )
                this.expectInboundKeyExchange(PacketNameToType.SSH_MSG_KEX_DH_GEX_INIT)
                const [done] = await this.#waitEvent("serverKexRSADone")
                this.assertConnectionGeneration(generation, "key exchange")
                hostKeyBlob = publicKey.data.hostKey
                signatureBlob = done.data.signature
            } else {
                this.expectInboundKeyExchange(PacketNameToType.SSH_MSG_KEXDH_REPLY)
                kexAlgorithm.generateKeyPair("client")
                clientExchangeValue = kexAlgorithm.getPublicKey()
                this.sendPacket(
                    new KexDHInit({
                        e: clientExchangeValue,
                        encoding: kexAlgorithm.exchangeValueEncoding,
                    }),
                )
                const reply = (await this.#waitEvent("serverKexDHReply"))[0]
                this.assertConnectionGeneration(generation, "key exchange")
                kexAlgorithm.computeSharedSecret(reply.data.f)
                serverExchangeValue = reply.data.f
                hostKeyBlob = reply.data.K_S
                signatureBlob = reply.data.H_sig
            }
            if (!(kexAlgorithm instanceof GSSAPIKeyExchange)) {
                h = kexAlgorithm.computeExchangeHash(
                    this.createKeyExchangeHashContext(
                        hostKeyBlob,
                        clientExchangeValue,
                        serverExchangeValue,
                    ),
                )
            }
            assert(h, "Key exchange hash was not computed")
            if (hostKeyBlob.length === 0) {
                assert(
                    kexAlgorithm instanceof GSSAPIKeyExchange &&
                        this.#hostKeyAlgorithm!.alg_name === "null",
                    "Server omitted the negotiated host key",
                )
                this.negotiatedServerHostKey = undefined
            } else {
                const hostKey = PublicKey.parse(hostKeyBlob)
                assert(
                    hostKey.data.alg === this.#hostKeyAlgorithm!.key_format,
                    "Server did not use the negotiated host key algorithm",
                )
                if (signatureBlob !== undefined) {
                    const signature = EncodedSignature.parse(signatureBlob)
                    assert(
                        signature.data.alg === this.#hostKeyAlgorithm!.signature_algorithm,
                        "Server did not use the negotiated signature algorithm",
                    )
                    assert(
                        hostKey.verifySignature(h, signature),
                        "Invalid host key signature from server",
                    )
                }

                const certificateAlgorithm = hostKey.data.algorithm
                if (certificateAlgorithm instanceof SSHCertificatePublicKey) {
                    const now = BigInt(Math.floor(Date.now() / 1000))
                    assert(
                        certificateAlgorithm.data.role === "host",
                        "Invalid host certificate role",
                    )
                    assert(
                        now >= certificateAlgorithm.data.validAfter &&
                            now < certificateAlgorithm.data.validBefore,
                        "Host certificate is outside its validity interval",
                    )
                    assert(
                        certificateAlgorithm.verifyCertificateSignature(),
                        "Invalid host certificate authority signature",
                    )
                    assert(
                        certificateAlgorithm.data.criticalOptions.length === 0,
                        "Host certificate contains unsupported critical options",
                    )
                    assert(
                        certificateAlgorithm.data.principals.length === 0 ||
                            certificateAlgorithm.data.principals.some(
                                (principal) =>
                                    principal.toLowerCase() ===
                                    this.#options.hostname.toLowerCase(),
                            ),
                        "Host certificate is not valid for the requested hostname",
                    )
                }

                await this.verifyConfiguredHostKey(hostKeyBlob)
                this.assertConnectionGeneration(generation, "key exchange")
                this.negotiatedServerHostKey = Buffer.from(hostKeyBlob)

                if (this.hooker.hasHooks("hostKey")) {
                    const controller: ClientHookerHostKeyController = { allowHostKey: false }
                    const policyCompleted = await this.hooker.triggerHookChecked(
                        "hostKey",
                        controller,
                        hostKey,
                    )
                    this.assertConnectionGeneration(generation, "host-key policy")
                    if (!policyCompleted || !controller.allowHostKey) {
                        throw new Error("Host key not allowed by hook")
                    }
                }
            }

            this.#exchangeHash = Buffer.from(h)
            this.#sessionID ??= Buffer.from(h)
            this.installDerivedTransportKeys(kexAlgorithm, h)
            assert(this.#clientEncryption)
            this.inboundNewKeysReady = true
            this.expectInboundKeyExchange(PacketNameToType.SSH_MSG_NEWKEYS)
            this.resumePacketProcessing()

            this.sendPacket(new NewKeys({}))
            if (this.strictKeyExchange) this.packetEncoder.resetSequenceNumber()
            this.hasSentNewKeys = true
            this.packetEncoder.setProtection(
                createOutboundPacketProtection(
                    this.#clientEncryptionAlgorithm!,
                    this.#clientEncryption,
                    this.#clientMacAlgorithm,
                    this.#clientMac,
                ),
            )
            this.installOutboundCompression()
            if (!isRekey && serverKexInit.data.kex_algorithms.includes("ext-info-s")) {
                const noFlowControl = noFlowControlExtension(this.#options.noFlowControl)
                const elevation = elevationExtension(this.#options.elevation)
                const delayCompression =
                    this.#options.delayCompression === false
                        ? undefined
                        : delayCompressionExtension(this.#options.delayCompression)
                this.sendPacket(
                    new ExtInfo({
                        extensions: [
                            {
                                name: AUTHENTICATION_EXT_INFO_EXTENSION,
                                value: Buffer.alloc(0),
                            },
                            ...(noFlowControl ? [noFlowControl] : []),
                            ...(elevation ? [elevation] : []),
                            ...(delayCompression ? [delayCompression] : []),
                        ],
                    }),
                )
                this.advertisedAuthenticationExtInfo = true
                if (delayCompression) this.delayCompressionRekeyBlocked = true
            }
            while (this.packetsQueuedDuringKeyExchange.length > 0) {
                this.writePacket(this.packetsQueuedDuringKeyExchange.shift()!)
            }
            this.emit("clientNewKeys")
            if (!this.hasReceivedNewKeys) {
                await this.#waitEvent("serverNewKeys")
                this.assertConnectionGeneration(generation, "key exchange")
            }
            while (this.packetsQueuedDuringKeyExchange.length > 0) {
                this.writePacket(this.packetsQueuedDuringKeyExchange.shift()!)
            }
            this.keyExchangeInProgress = false
            this.strictInitialExchange = false
            this.resetRekeyTimer()
            this.checkRekeyByteLimit()
            this.emit("handshake", describeNegotiatedAlgorithms(algorithms))
            if (isRekey) this.emit("rekey")
        } catch (error) {
            if (generation !== this.connectionGeneration) throw error
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
            negotiatedKeyExchange?.dispose()
            if (generation === this.connectionGeneration) {
                this.keyExchangeInProgress = false
                this.strictInitialExchange = false
                this.expectedInboundKeyExchangePackets.clear()
                this.resetKeepalive()
            }
        }
    }

    async connect(): Promise<void> {
        if (!this.canConnect) {
            throw new Error("Cannot initiate connection; client is not in a state to connect")
        }
        this.resetConnectionState()
        const generation = this.connectionGeneration
        this.state = SocketState.Connecting
        const suppliedSocket = this.#options.sock
        if (
            suppliedSocket !== undefined &&
            (!isReadable(suppliedSocket) || !suppliedSocket.writable || suppliedSocket.destroyed)
        ) {
            this.state = SocketState.Closed
            throw new Error("The supplied SSH transport must be open, readable, and writable")
        }
        this.socket =
            suppliedSocket ??
            net.createConnection({
                host: this.#options.hostname,
                port: this.#options.port,
                localAddress: this.#options.localAddress,
                localPort: this.#options.localPort,
                family:
                    this.#options.forceIPv4 === this.#options.forceIPv6
                        ? undefined
                        : this.#options.forceIPv4
                          ? 4
                          : 6,
            })
        if (this.#options.readyTimeout > 0) {
            this.readyTimer = setTimeout(() => {
                this.socket?.destroy(new Error("Timed out while waiting for handshake"))
            }, this.#options.readyTimeout)
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
            this.socket!.on("end", () => {
                this.emit("end")
                this.socket?.destroy()
            })
            const closeListener = () => {
                this.clearReadyTimeout()
                this.clearKeepalive()
                this.clearRekeyTimer()
                this.packetEncoder.dispose()
                this.packetDecoder.dispose()
                this.disposeTransportAlgorithms()
                this.state = SocketState.Closed
                this.debug("Socket closed")
                this.socket = undefined
                const closeError = this.connectionClosedError("SSH connection closed")
                this.actionQueue.close(closeError)
                for (const channel of this.channels.values()) channel.abort(closeError)
                this.channels.clear()
                for (const channel of this.pendingIncomingChannels) channel.abort()
                this.pendingIncomingChannels.clear()
                this.remoteChannelIds.clear()
                this.pendingRemoteChannelOpens.clear()
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
                this.pendingRemoteForwardings.clear()
                this.remoteStreamLocalForwardings.clear()
                this.pendingRemoteStreamLocalForwardings.clear()
                this.x11Forwardings.clear()
                this.agentForwardingEnabled = false
                void this.closeInitialGSSAPIKeyExchangeContext().catch(() =>
                    this.debug("Could not close the initial GSS-API key-exchange context"),
                )
                this.emit("close")
                if (!connected) reject(closeError)
            }
            this.socket!.on("close", closeListener)
            if (suppliedSocket !== undefined) resolve()
        })
        this.assertConnectionGeneration(generation, "connection setup")

        this.socket!.on("data", (data) => {
            try {
                this.onMessage(data)
            } catch (error) {
                this.handleMessageError(error as Error)
            }
        })

        this.debug(`Socket connected, sending protocol version exchange packet...`)
        this.socket!.write(this.#options.protocolVersionExchange.toString())

        const [serverProtocolVersion] = await this.#waitEvent("serverProtocolVersion")
        this.assertConnectionGeneration(generation, "connection setup")
        this.debug("Server protocol version:", serverProtocolVersion)

        await this.performKeyExchange()
        this.assertConnectionGeneration(generation, "connection setup")

        this.debug("Starting authentication...")

        this.awaitingServiceAccept = true
        let serviceAnswer: ServiceAccept
        try {
            this.sendPacket(
                new ServiceRequest({
                    service_name: SSHServiceNames.UserAuth,
                }),
            )

            serviceAnswer = await this.#waitForPackets(
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
            this.assertConnectionGeneration(generation, "authentication")
        } finally {
            if (generation === this.connectionGeneration) this.awaitingServiceAccept = false
        }
        assert(serviceAnswer.data.service_name == SSHServiceNames.UserAuth)

        const methodList = [...this.#options.authenticationMethodsOrder]
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
                    const policyCompleted = await this.hooker.triggerHookChecked(
                        "authenticationMethod",
                        context,
                        selection,
                    )
                    this.assertConnectionGeneration(generation, "authentication policy")
                    if (!policyCompleted) {
                        throw new Error("Authentication method policy failed.")
                    }
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
                    success = await m.handleAuthentication(this, () =>
                        this.assertConnectionGeneration(generation, "authentication"),
                    )
                    this.assertConnectionGeneration(generation, "authentication")
                } finally {
                    if (generation === this.connectionGeneration) {
                        this.activeAuthenticationMethod = undefined
                    }
                }
                if (success) {
                    this.debug(`Authentication successful with method`, m.method_name)
                    this.debug("Authenticated as", this.#options.username)

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
            if (generation === this.connectionGeneration) this.authenticationInProgress = false
        }
        this.hasAuthenticated = true
        await this.closeInitialGSSAPIKeyExchangeContext()
        this.assertConnectionGeneration(generation, "authentication")

        // we are connected and logged in
        // we can now open channels
        this.state = SocketState.Connected
        this.clearReadyTimeout()
        this.resetKeepalive()
        this.emit("connect")
    }

    end(): this {
        return this.disconnect(
            new DisconnectError(DisconnectReason.SSH_DISCONNECT_BY_APPLICATION, ""),
        )
    }

    disconnect(error?: DisconnectError): this {
        this.clearReadyTimeout()
        this.clearKeepalive()
        this.clearRekeyTimer()
        if (this.socket && !this.socket.destroyed && this.socket.writable) {
            if (this.serverProtocolVersion && error) {
                this.sendPacket(
                    new Disconnect({
                        reason_code: error.reason_code,
                        description: error.message,
                        language_tag: error.languageTag,
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
        this.clearRekeyTimer()
        if (this.socket && !this.socket.destroyed) {
            this.state = SocketState.Disconnected
            this.socket.destroy()
        }
        return this
    }

    #waitEvent<event extends Exclude<keyof ClientEvents, "error" | "close">>(
        event: event,
    ): Promise<ClientEvents[event]> {
        return new Promise((resolve, reject) => {
            if (
                this.state === SocketState.Closed ||
                this.state === SocketState.Disconnected ||
                this.socket?.destroyed
            ) {
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
            const handler = (...values: ClientEvents[event]) => {
                resolve(values)
                cleanup()
            }
            const cleanup = () => {
                // @ts-expect-error the generic event key and tuple keep this listener aligned
                this.off(event, handler)
                this.off("error", onError)
                this.off("close", onClose)
            }
            // This direct listener bridge queues the protocol continuation before the packet
            // decoder schedules the next coalesced packet. node:events once() adds a scheduling
            // step that can let post-KEX traffic overtake key-exchange completion.
            // @ts-expect-error the generic event key and tuple keep this listener aligned
            this.once(event, handler)
            this.once("error", onError)
            this.once("close", onClose)
        })
    }

    #waitForPackets<
        Predicates extends {
            [Name in keyof typeof packets]?: {
                predicate: (packet: InstanceType<(typeof packets)[Name]>) => boolean
            }
        },
    >(
        Predicates: Predicates,
        timeout: number,
    ): Promise<InstanceType<(typeof packets)[Extract<keyof Predicates, keyof typeof packets>]>> {
        return new Promise((resolve, reject) => {
            if (
                this.state === SocketState.Closed ||
                this.state === SocketState.Disconnected ||
                this.socket?.destroyed
            ) {
                reject(
                    this.connectionClosedError("SSH connection closed while waiting for message"),
                )
                return
            }
            const cleanup = () => {
                offPacketEvent(this, onPacket)
                this.off("error", onError)
                this.off("close", onClose)
                clearTimeout(timer)
            }
            // Run protocol predicates in the receive path. A predicate may detect a protocol
            // violation and throw; that must reach the transport error handler synchronously so
            // the peer receives the corresponding disconnect message.
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

                resolve(
                    packet as InstanceType<
                        (typeof packets)[Extract<keyof Predicates, keyof typeof packets>]
                    >,
                )
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
            timer.unref()
            onPacketEvent(this, onPacket)
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
        const payload = packet.serialize()
        if (packet === this.#clientKexInit) this.#clientKexInitPayload = Buffer.from(payload)
        const encoded = this.packetEncoder.encode(payload)
        this.socket!.write(encoded.data)
        if (packet instanceof UserAuthRequest) this.sentAuthenticationRequest = true
        this.checkRekeyByteLimit()
        return encoded.sequenceNumber
    }

    onMessage(message: Buffer): void {
        if (!this.serverProtocolVersion) {
            const result = this.identificationParser.push(message)
            for (const lineBuf of result.preamble) {
                this.greetingChunks.push(Buffer.from(lineBuf))
                const line = lineBuf.toString("utf8").replace(/\r?\n$/u, "")
                this.emit("tcpWrapperLog", line)
                this.debug("TCP Wrapper log:", line)
            }

            if (!result.version || !result.identification) return

            if (this.greetingChunks.length > 0) {
                this.emit("greeting", Buffer.concat(this.greetingChunks).toString("utf8"))
            }

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
        this.checkRekeyByteLimit()

        const { payload } = decoded
        const packetType = payload[0] as PacketType
        this.debug("Receiving packet:", packetType)
        this.emit("packet", protocolPacketMetadata(packetType, decoded.sequenceNumber))

        if (this.discardNextGuessedKeyExchangePacket) {
            this.discardNextGuessedKeyExchangePacket = false
            this.debug("Discarding incorrectly guessed key-exchange packet")
            if (this.packetDecoder.bufferedLength > 0) {
                this.scheduleMessageProcessing(Buffer.alloc(0))
            }
            return
        }
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
        this.validateKeyExchangeMessageBoundary(packetType)
        this.validateHigherLayerPhase(packetType)
        let p: Packet
        if (
            this.#kexAlgorithm instanceof GSSAPIKeyExchange &&
            packetType >= 31 &&
            packetType <= 34
        ) {
            if (packetType === KexGSSAPIContinue.type) {
                p = KexGSSAPIContinue.parse(payload)
            } else if (packetType === KexGSSAPIComplete.type) {
                p = KexGSSAPIComplete.parse(payload, this.#kexAlgorithm.exchangeValueEncoding)
            } else if (packetType === KexGSSAPIHostKey.type) {
                p = KexGSSAPIHostKey.parse(payload)
            } else {
                p = KexGSSAPIError.parse(payload)
            }
        } else {
            let packet: typeof Packet
            if (
                packetType === PacketNameToType.SSH_MSG_KEXDH_INIT &&
                this.#kexAlgorithm instanceof RSA2048SHA256
            ) {
                packet = KexRSAPublicKey
            } else if (
                packetType === PacketNameToType.SSH_MSG_KEX_DH_GEX_INIT &&
                this.#kexAlgorithm instanceof RSA2048SHA256
            ) {
                packet = KexRSADone
            } else if (
                packetType === PacketNameToType.SSH_MSG_KEXDH_REPLY &&
                this.#kexAlgorithm instanceof DiffieHellmanGroupExchange
            ) {
                packet = KexDHGexGroup
            } else if (packetType === PacketNameToType.SSH_MSG_USERAUTH_PK_OK) {
                switch (this.activeAuthenticationMethod) {
                    case SSHAuthenticationMethods.GSSAPIWithMIC:
                        packet = UserAuthGSSAPIResponse
                        break
                    case SSHAuthenticationMethods.Password:
                        packet = UserAuthPasswordChangeRequest
                        break
                    case SSHAuthenticationMethods.KeyboardInteractive:
                        packet = UserAuthInfoRequest
                        break
                    default:
                        packet = UserAuthPKOK
                }
            } else if (
                packetType === PacketNameToType.SSH_MSG_USERAUTH_INFO_RESPONSE &&
                this.activeAuthenticationMethod === SSHAuthenticationMethods.GSSAPIWithMIC
            ) {
                packet = UserAuthGSSAPIToken
            } else {
                packet = packets[packetName as keyof typeof packets]
            }
            p = packet.parse(payload)
        }
        if (
            p instanceof KexGSSAPIContinue ||
            p instanceof KexGSSAPIComplete ||
            p instanceof KexGSSAPIHostKey ||
            p instanceof KexGSSAPIError
        ) {
            this.packetProcessingPaused = true
        }
        if (p instanceof KexInit) this.#serverKexInitPayload = Buffer.from(payload)
        if (p instanceof KexInit) this.peerKexInitReceived = true
        this.debug("Parsing packet:", this.packetForDebug(p))

        if (packetType === PacketNameToType.SSH_MSG_KEXINIT && this.strictInitialExchange) {
            const serverAlgorithms = (p as KexInit).data.kex_algorithms
            const negotiated = negotiatesStrictKeyExchange(
                this.#clientKexInit!.data.kex_algorithms,
                serverAlgorithms,
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
                this.#kexAlgorithm instanceof GSSAPIKeyExchange &&
                packetType === KexGSSAPIContinue.type
            if (!repeatableGSSContinuation && this.strictInitialPackets.has(packetType)) {
                throw new KeyExchangeError("Received a duplicate packet during strict key exchange")
            }
            this.strictInitialPackets.add(packetType)
        }

        if (p instanceof UserAuthFailure) {
            this.authenticationMethodsRemaining = new Set(p.data.auth_methods)
            this.partialAuthenticationSuccess = p.data.partial_success
            this.authenticationFailureSequence++
        }

        emitPacketEvent(this, p)
        if (p instanceof Unimplemented) this.emit("unimplemented", p.data.sequence_number)

        if (p instanceof GlobalRequest) {
            const generation = this.connectionGeneration
            void this.actionQueue
                .queueAction("globalRequest", () => this.handleServerGlobalRequest(p, generation))
                .catch((error: Error) => {
                    if (
                        generation === this.connectionGeneration &&
                        this.socket !== undefined &&
                        !this.socket.destroyed
                    ) {
                        this.socket?.destroy(error)
                    }
                })
        }
        this.routeGlobalRequestReply(p)
        this.routeChannelPacket(p)

        switch (packetType) {
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
                this.activateAuthenticatedServerCompression()
                this.triggerAuthenticatedClientCompression()
                break

            case PacketNameToType.SSH_MSG_NEWCOMPRESS:
                throw new ProtocolError("SSH server sent the client-only NEWCOMPRESS message")

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
                if (this.sessionID !== undefined && !this.keyExchangeInProgress) {
                    const generation = this.connectionGeneration
                    void waitForReply(this, this.performKeyExchange(true), "key exchange").catch(
                        (error: Error) => {
                            if (generation === this.connectionGeneration) {
                                this.socket?.destroy(error)
                            }
                        },
                    )
                }
                this.emit("serverKexInit", p as KexInit, Buffer.from(this.#serverKexInitPayload!))
                break

            case PacketNameToType.SSH_MSG_KEXDH_INIT:
                if (!(this.#kexAlgorithm instanceof RSA2048SHA256)) {
                    throw new Error("Received an RSA public key for another key exchange")
                }
                this.emit("serverKexRSAPublicKey", p as KexRSAPublicKey)
                break

            case PacketNameToType.SSH_MSG_NEWKEYS:
                this.hasReceivedNewKeys = true
                this.inboundNewKeysReady = false
                this.packetDecoder.setProtection(
                    createInboundPacketProtection(
                        this.#serverEncryptionAlgorithm!,
                        this.#serverEncryption!,
                        this.#serverMacAlgorithm,
                        this.#serverMac,
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
                if (p instanceof KexGSSAPIContinue) {
                    break
                } else if (p instanceof KexDHGexGroup) {
                    this.emit("serverKexDHGexGroup", p)
                } else {
                    this.packetProcessingPaused = true
                    this.emit("serverKexDHReply", p as KexDHReply)
                }
                break

            case PacketNameToType.SSH_MSG_KEX_DH_GEX_REPLY:
                if (p instanceof KexGSSAPIHostKey) break
                if (!(this.#kexAlgorithm instanceof DiffieHellmanGroupExchange)) {
                    throw new Error("Received a group-exchange reply for another key exchange")
                }
                this.packetProcessingPaused = true
                this.emit("serverKexDHGexReply", p as KexDHGexReply)
                break

            case PacketNameToType.SSH_MSG_KEX_DH_GEX_INIT:
                if (p instanceof KexGSSAPIComplete) break
                if (!(this.#kexAlgorithm instanceof RSA2048SHA256)) {
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
                if (
                    this.advertisedAuthenticationExtInfo &&
                    this.sentAuthenticationRequest &&
                    this.authenticationInProgress
                ) {
                    if (this.serverAuthenticationExtInfoReceived) {
                        throw new Error(
                            "Server sent duplicate authentication extension information",
                        )
                    }
                    this.serverAuthenticationExtInfoReceived = true
                    return
                }
                if (this.serverAuthenticationExtInfoReceived) {
                    throw new Error(
                        "Server sent duplicate pre-authentication extension information",
                    )
                }
                this.serverAuthenticationExtInfoReceived = true
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
        if (packetType === PacketNameToType.SSH_MSG_KEXINIT) {
            if (!this.keyExchangeInProgress) return
            if (!this.expectedInboundKeyExchangePackets.delete(packetType)) {
                throw new DisconnectError(
                    DisconnectReason.SSH_DISCONNECT_PROTOCOL_ERROR,
                    "SSH server sent an unexpected KEXINIT during key exchange",
                )
            }
            return
        }
        if (exchangeOnly && !this.keyExchangeInProgress) {
            throw new DisconnectError(
                DisconnectReason.SSH_DISCONNECT_PROTOCOL_ERROR,
                "SSH server sent a key-exchange message outside key exchange",
            )
        }
        if (packetType === PacketNameToType.SSH_MSG_NEWKEYS && !this.inboundNewKeysReady) {
            throw new DisconnectError(
                DisconnectReason.SSH_DISCONNECT_PROTOCOL_ERROR,
                "SSH server sent NEWKEYS before fresh inbound keys were ready",
            )
        }
        if (exchangeOnly && !this.expectedInboundKeyExchangePackets.delete(packetType)) {
            throw new DisconnectError(
                DisconnectReason.SSH_DISCONNECT_PROTOCOL_ERROR,
                "SSH server sent an out-of-order key-exchange message",
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
            "SSH server sent a non-key-exchange message after KEXINIT",
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
        const negotiatedKex = (this.#kexAlgorithm!.constructor as typeof KexAlgorithm).alg_name
        return (
            peerKexInit.data.kex_algorithms[0] !== negotiatedKex ||
            peerKexInit.data.server_host_key_algorithms[0] !== this.#hostKeyAlgorithm!.alg_name
        )
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
                packetType !== PacketNameToType.SSH_MSG_USERAUTH_PK_OK &&
                !(
                    this.activeAuthenticationMethod === SSHAuthenticationMethods.GSSAPIWithMIC &&
                    (packetType === PacketNameToType.SSH_MSG_USERAUTH_INFO_RESPONSE ||
                        packetType === PacketNameToType.SSH_MSG_USERAUTH_GSSAPI_ERROR ||
                        packetType === PacketNameToType.SSH_MSG_USERAUTH_GSSAPI_ERRTOK)
                )
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
        this.rfc9987AgentForwardingSupported = false
        this.hostKeyUpdateSupported = false
        this.noFlowControlEnabled = false

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
        const agentForwarding = extensions.find(({ name }) => name === AGENT_FORWARDING_EXTENSION)
        this.rfc9987AgentForwardingSupported =
            agentForwarding?.value.equals(AGENT_FORWARDING_EXTENSION_VERSION) === true
        const hostKeys = extensions.find(({ name }) => name === HOST_KEYS_EXTENSION)
        this.hostKeyUpdateSupported = hostKeys?.value.equals(HOST_KEYS_EXTENSION_VERSION) === true
        this.noFlowControlEnabled = negotiateNoFlowControl(
            noFlowControlValue(this.#options.noFlowControl),
            extensions,
        )
        try {
            this.pendingDelayCompression = negotiateDelayCompression(
                this.#options.delayCompression === false
                    ? undefined
                    : this.#options.delayCompression,
                findDelayCompressionOffers(extensions),
            )
        } catch (error) {
            if (!(error instanceof KeyExchangeError)) throw error
            throw new DisconnectError(
                DisconnectReason.SSH_DISCONNECT_KEY_EXCHANGE_FAILED,
                error.message,
            )
        }
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
            const generation = this.connectionGeneration
            void this.actionQueue
                .queueAction(`channelRequest:${recipient}`, () => channel.receiveRequest(packet))
                .catch((error: Error) => {
                    if (generation === this.connectionGeneration && this.isConnected) {
                        this.handleMessageError(error)
                    }
                })
        } else if (packet instanceof ChannelSuccess) {
            channel.receiveRequestSuccess()
        } else if (packet instanceof ChannelFailure) {
            channel.receiveRequestFailure()
        }
    }

    private routeGlobalRequestReply(packet: Packet): void {
        if (!(packet instanceof RequestSuccess) && !(packet instanceof RequestFailure)) return
        const request = this.pendingGlobalRequests.shift()
        if (!request) {
            throw new ProtocolError("Received an unexpected SSH global request response")
        }
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
        if (this.#options.keepaliveInterval === 0 || !this.isConnected) return
        this.keepaliveTimer = setTimeout(
            () => this.sendKeepalive(),
            this.#options.keepaliveInterval,
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
            this.#options.rekeyInterval === 0 ||
            this.sessionID === undefined ||
            !this.socket ||
            this.socket.destroyed
        ) {
            return
        }
        this.rekeyTimer = setTimeout(
            () => this.scheduleAutomaticRekey("time limit"),
            this.#options.rekeyInterval,
        )
        this.rekeyTimer.unref()
    }

    private clearRekeyTimer(): void {
        if (this.rekeyTimer !== undefined) clearTimeout(this.rekeyTimer)
        this.rekeyTimer = undefined
    }

    private checkRekeyByteLimit(): void {
        const limit = this.#options.rekeyBytes
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
            !this.socket ||
            this.socket.destroyed
        ) {
            return
        }
        this.automaticRekeyScheduled = true
        queueMicrotask(() => {
            this.automaticRekeyScheduled = false
            if (this.keyExchangeInProgress || !this.socket || this.socket.destroyed) return
            this.debug(`Starting automatic SSH rekey after ${reason}`)
            void this.rekey().catch((error: unknown) => {
                this.debug("Automatic SSH rekey failed:", error)
            })
        })
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

    private assertRemoteChannelIdAvailable(remoteId: number): void {
        if (this.remoteChannelIds.has(remoteId)) {
            throw new DisconnectError(
                DisconnectReason.SSH_DISCONNECT_PROTOCOL_ERROR,
                `SSH peer reused active channel identifier ${remoteId}`,
            )
        }
    }

    private reserveRemoteChannelId(remoteId: number): void {
        this.assertRemoteChannelIdAvailable(remoteId)
        this.remoteChannelIds.add(remoteId)
    }

    private reserveIncomingRemoteChannelId(remoteId: number): boolean {
        this.assertRemoteChannelIdAvailable(remoteId)
        if (this.channels.size + this.pendingRemoteChannelOpens.size >= this.#options.maxChannels) {
            return false
        }
        if (this.pendingRemoteChannelOpens.size >= this.#options.maxPendingChannelOpens) {
            return false
        }
        this.remoteChannelIds.add(remoteId)
        this.pendingRemoteChannelOpens.add(remoteId)
        return true
    }

    private assertChannelCapacity(): void {
        if (this.channels.size + this.pendingRemoteChannelOpens.size >= this.#options.maxChannels) {
            throw new ChannelOpenError(
                ChannelOpenFailureReasonCodes.SSH_OPEN_RESOURCE_SHORTAGE,
                `SSH simultaneous channel limit of ${this.#options.maxChannels} reached`,
            )
        }
        if (
            this.noFlowControlEnabled &&
            (this.channels.size !== 0 || this.remoteChannelIds.size !== 0)
        ) {
            throw new Error("RFC 8308 no-flow-control permits only one simultaneous SSH channel")
        }
    }

    private async verifyConfiguredHostKey(serializedHostKey: Buffer): Promise<void> {
        const verifier = this.#options.hostVerifier
        if (!verifier) return

        const presentedKey: Buffer | string = this.#options.hostHash
            ? crypto.createHash(this.#options.hostHash).update(serializedHostKey).digest("hex")
            : Buffer.from(serializedHostKey)
        let rejectClosed!: (error: Error) => void
        const closed = new Promise<never>((_resolve, reject) => {
            rejectClosed = reject
        })
        const fail = (error: Error) => rejectClosed(error)
        const close = () =>
            rejectClosed(new Error("SSH connection closed during host verification"))
        this.once("error", fail)
        this.once("close", close)
        let allowed: boolean
        try {
            allowed =
                (await Promise.race([Promise.resolve(verifier(presentedKey)), closed])) === true
        } finally {
            this.off("error", fail)
            this.off("close", close)
        }
        if (!allowed) throw new Error("Host key not allowed by verifier")
    }

    private sendKeepalive(): void {
        this.keepaliveTimer = undefined
        if (!this.isConnected) return
        this.unansweredKeepalives++
        if (this.unansweredKeepalives > this.#options.keepaliveCountMax) {
            this.emit("error", new Error("SSH keepalive timeout"))
            this.destroy()
            return
        }

        void this.sendGlobalRequest("keepalive@openssh.com", Buffer.alloc(0), false).then(
            () => this.resetKeepalive(),
            (error: unknown) => {
                if (error instanceof GlobalRequestError) this.resetKeepalive()
            },
        )
        this.scheduleKeepalive()
    }

    private handleIncomingChannelOpen(packet: ChannelOpen): void {
        if (!this.reserveIncomingRemoteChannelId(packet.data.sender_channel_id)) {
            this.rejectIncomingChannel(
                packet,
                ChannelOpenFailureReasonCodes.SSH_OPEN_RESOURCE_SHORTAGE,
                this.channels.size + this.pendingRemoteChannelOpens.size >=
                    this.#options.maxChannels
                    ? `SSH simultaneous channel limit of ${this.#options.maxChannels} reached`
                    : "Too many SSH channel opens are awaiting decisions",
            )
            return
        }
        if (
            this.noFlowControlEnabled &&
            (this.channels.size !== 0 || this.remoteChannelIds.size > 1)
        ) {
            this.rejectIncomingChannel(
                packet,
                ChannelOpenFailureReasonCodes.SSH_OPEN_RESOURCE_SHORTAGE,
                "RFC 8308 no-flow-control permits only one simultaneous SSH channel",
            )
            return
        }
        if (packet.data.channel_type === ClientX11Channel.channelType) {
            const generation = this.connectionGeneration
            void this.actionQueue
                .queueAction(`incomingChannel:${packet.data.sender_channel_id}`, () =>
                    this.handleIncomingX11ChannelOpen(packet, generation),
                )
                .catch((error: Error) => {
                    if (generation === this.connectionGeneration && this.isConnected) {
                        this.handleMessageError(error)
                    }
                })
            return
        }
        if (
            packet.data.channel_type === ClientAgentChannel.channelType ||
            packet.data.channel_type === RFC9987_AGENT_CHANNEL
        ) {
            const generation = this.connectionGeneration
            void this.handleIncomingAgentChannelOpen(packet, generation).catch((error: unknown) => {
                if (generation !== this.connectionGeneration) return
                this.handleMessageError(error instanceof Error ? error : new Error(String(error)))
            })
            return
        }
        if (packet.data.channel_type === ClientForwardedStreamLocalChannel.channelType) {
            const generation = this.connectionGeneration
            void this.actionQueue
                .queueAction(`incomingChannel:${packet.data.sender_channel_id}`, () =>
                    this.handleIncomingStreamLocalChannelOpen(packet, generation),
                )
                .catch((error: Error) => {
                    if (generation === this.connectionGeneration && this.isConnected) {
                        this.handleMessageError(error)
                    }
                })
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

        const generation = this.connectionGeneration
        void this.actionQueue
            .queueAction(`incomingChannel:${packet.data.sender_channel_id}`, () =>
                this.handleIncomingTCPChannelOpen(packet, generation),
            )
            .catch((error: Error) => {
                if (generation === this.connectionGeneration && this.isConnected) {
                    this.handleMessageError(error)
                }
            })
    }

    private async handleIncomingTCPChannelOpen(
        packet: ChannelOpen,
        generation: number,
    ): Promise<void> {
        const details = Object.freeze(ClientForwardedTCPIPChannel.parseDetails(packet.data.args))
        if (!this.isRemoteForwardAuthorized(details)) {
            this.rejectIncomingChannel(
                packet,
                ChannelOpenFailureReasonCodes.SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
                "No matching remote forwarding was requested",
            )
            return
        }
        const channel = new ClientForwardedTCPIPChannel(this, packet)
        this.pendingIncomingChannels.add(channel)
        void channel.waitUntilOpen().catch(() => undefined)
        try {
            const controller: ClientHookerIncomingChannelController = { allowOpen: false }
            const policyCompleted = await this.hooker.triggerHookChecked(
                "tcpConnection",
                channel,
                controller,
            )
            if (!this.canReplyToIncomingChannel(packet, generation)) return
            if (!policyCompleted || !controller.allowOpen || channel.destroyed) {
                const rejection =
                    policyCompleted && controller.rejection
                        ? controller.rejection
                        : new ChannelOpenError(
                              ChannelOpenFailureReasonCodes.SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
                              "Remote forwarding connection was rejected",
                          )
                this.rejectIncomingChannel(
                    packet,
                    rejection.reasonCode,
                    rejection.message,
                    rejection.languageTag,
                )
                channel.abort()
                return
            }

            channel.acceptOpen(packet)
            this.pendingRemoteChannelOpens.delete(packet.data.sender_channel_id)
            this.channels.set(channel.localId, channel)
            this.sendPacket(channel.getOpenConfirmationPacket())
            this.emit("tcp connection", channel.details, channel)
        } finally {
            this.pendingIncomingChannels.delete(channel)
            if (!channel.isOpen && !channel.destroyed) channel.abort()
        }
    }

    private async handleIncomingX11ChannelOpen(
        packet: ChannelOpen,
        generation: number,
    ): Promise<void> {
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

        let channel: ClientX11Channel
        try {
            channel = new ClientX11Channel(this, packet)
        } catch (error) {
            this.debug("Invalid incoming X11 channel", error)
            this.rejectIncomingChannel(
                packet,
                ChannelOpenFailureReasonCodes.SSH_OPEN_CONNECT_FAILED,
                "Invalid X11 channel metadata",
            )
            return
        }
        this.pendingIncomingChannels.add(channel)
        void channel.waitUntilOpen().catch(() => undefined)
        try {
            const controller: ClientHookerIncomingChannelController = { allowOpen: false }
            const policyCompleted = await this.hooker.triggerHookChecked(
                "x11Connection",
                channel,
                controller,
            )
            if (!this.canReplyToIncomingChannel(packet, generation)) return
            if (!policyCompleted || !controller.allowOpen || channel.destroyed) {
                const rejection =
                    policyCompleted && controller.rejection
                        ? controller.rejection
                        : new ChannelOpenError(
                              ChannelOpenFailureReasonCodes.SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
                              "X11 forwarding connection was rejected",
                          )
                this.rejectIncomingChannel(
                    packet,
                    rejection.reasonCode,
                    rejection.message,
                    rejection.languageTag,
                )
                channel.abort()
                return
            }

            channel.acceptOpen(packet)
            this.pendingRemoteChannelOpens.delete(packet.data.sender_channel_id)
            this.channels.set(channel.localId, channel)
            this.sendPacket(channel.getOpenConfirmationPacket())
            this.emit("x11", channel.details, channel)
        } finally {
            this.pendingIncomingChannels.delete(channel)
            if (!channel.isOpen && !channel.destroyed) channel.abort()
        }
    }

    private async handleIncomingAgentChannelOpen(
        packet: ChannelOpen,
        generation: number,
    ): Promise<void> {
        if (packet.data.args.length !== 0) {
            this.rejectIncomingChannel(
                packet,
                ChannelOpenFailureReasonCodes.SSH_OPEN_CONNECT_FAILED,
                "Authentication agent channel has trailing data",
            )
            return
        }
        const getStream = this.#options.agent.getStream
        if (!this.agentForwardingEnabled || !getStream) {
            this.rejectIncomingChannel(
                packet,
                ChannelOpenFailureReasonCodes.SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
                "Agent forwarding was not requested",
            )
            return
        }

        let candidate: unknown
        try {
            candidate = await getStream.call(this.#options.agent)
        } catch {
            this.debug("Could not connect an incoming channel to the SSH agent")
            if (!this.canReplyToIncomingChannel(packet, generation)) return
            this.rejectIncomingChannel(
                packet,
                ChannelOpenFailureReasonCodes.SSH_OPEN_CONNECT_FAILED,
                "Could not connect to the authentication agent",
            )
            return
        }

        if (!this.canReplyToIncomingChannel(packet, generation)) {
            if (candidate instanceof Duplex) candidate.destroy()
            return
        }
        if (!(candidate instanceof Duplex)) {
            this.debug("Authentication agent returned an invalid forwarding stream")
            this.rejectIncomingChannel(
                packet,
                ChannelOpenFailureReasonCodes.SSH_OPEN_CONNECT_FAILED,
                "Could not connect to the authentication agent",
            )
            return
        }
        const stream = candidate
        if (stream.destroyed || !stream.readable || !stream.writable) {
            stream.destroy()
            this.debug("Authentication agent returned a closed forwarding stream")
            this.rejectIncomingChannel(
                packet,
                ChannelOpenFailureReasonCodes.SSH_OPEN_CONNECT_FAILED,
                "Could not connect to the authentication agent",
            )
            return
        }

        let channel: ClientAgentChannel | undefined
        try {
            const acceptedChannel = new ClientAgentChannel(this, packet)
            channel = acceptedChannel
            this.pendingRemoteChannelOpens.delete(packet.data.sender_channel_id)
            this.channels.set(acceptedChannel.localId, acceptedChannel)
            stream.on("error", () => acceptedChannel.destroy())
            stream.on("close", () => acceptedChannel.close())
            channel.on("error", () => stream.destroy())
            channel.on("close", () => stream.destroy())
            stream.pipe(channel).pipe(stream)
            this.sendPacket(channel.getOpenConfirmationPacket())
        } catch (error) {
            if (channel !== undefined) {
                this.channels.delete(channel.localId)
                channel.abort(error instanceof Error ? error : new Error(String(error)))
            }
            stream.destroy()
            this.debug("Could not accept an incoming SSH agent channel")
            if (!this.canReplyToIncomingChannel(packet, generation)) return
            this.rejectIncomingChannel(
                packet,
                ChannelOpenFailureReasonCodes.SSH_OPEN_CONNECT_FAILED,
                "Invalid authentication agent channel",
            )
        }
    }

    private canReplyToIncomingChannel(packet: ChannelOpen, generation: number): boolean {
        return (
            generation === this.connectionGeneration &&
            this.isConnected &&
            this.socket !== undefined &&
            !this.socket.destroyed &&
            this.remoteChannelIds.has(packet.data.sender_channel_id)
        )
    }

    private async handleIncomingStreamLocalChannelOpen(
        packet: ChannelOpen,
        generation: number,
    ): Promise<void> {
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
        const channel = new ClientForwardedStreamLocalChannel(this, packet)
        this.pendingIncomingChannels.add(channel)
        void channel.waitUntilOpen().catch(() => undefined)
        try {
            const controller: ClientHookerIncomingChannelController = { allowOpen: false }
            const policyCompleted = await this.hooker.triggerHookChecked(
                "streamLocalConnection",
                channel,
                controller,
            )
            if (!this.canReplyToIncomingChannel(packet, generation)) return
            if (!policyCompleted || !controller.allowOpen || channel.destroyed) {
                const rejection =
                    policyCompleted && controller.rejection
                        ? controller.rejection
                        : new ChannelOpenError(
                              ChannelOpenFailureReasonCodes.SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
                              "Remote stream-local forwarding connection was rejected",
                          )
                this.rejectIncomingChannel(
                    packet,
                    rejection.reasonCode,
                    rejection.message,
                    rejection.languageTag,
                )
                channel.abort()
                return
            }

            channel.acceptOpen(packet)
            this.pendingRemoteChannelOpens.delete(packet.data.sender_channel_id)
            this.channels.set(channel.localId, channel)
            this.sendPacket(channel.getOpenConfirmationPacket())
            this.emit("unix connection", channel.details, channel)
        } finally {
            this.pendingIncomingChannels.delete(channel)
            if (!channel.isOpen && !channel.destroyed) channel.abort()
        }
    }

    private rejectIncomingChannel(
        packet: ChannelOpen,
        reasonCode: number,
        description: string,
        languageTag = "",
    ): void {
        this.remoteChannelIds.delete(packet.data.sender_channel_id)
        this.pendingRemoteChannelOpens.delete(packet.data.sender_channel_id)
        this.sendPacket(
            new ChannelOpenFailure({
                recipient_channel_id: packet.data.sender_channel_id,
                reason_code: reasonCode,
                description,
                language_tag: languageTag,
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
