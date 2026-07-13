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
} from "./algorithms.js"
import KexDHInit from "./packets/KexDHInit.js"
import KexDHReply from "./packets/KexDHReply.js"
import EncodedSignature from "./utils/Signature.js"
import ExtInfo from "./packets/ExtInfo.js"
import PublicKey from "./utils/PublicKey.js"
import { Hooker } from "./utils/Hooker.js"
import NewKeys from "./packets/NewKeys.js"
import { KeyExchangeError } from "./algorithms/kex/key-exchange.js"
import UserAuthRequest from "./packets/UserAuthRequest.js"
import Disconnect, { DisconnectReason } from "./packets/Disconnect.js"
import ServiceRequest from "./packets/ServiceRequest.js"
import Agent from "./publickey/Agent.js"
import NoneAgent from "./publickey/NoneAgent.js"
import GlobalRequest from "./packets/GlobalRequest.js"
import RequestFailure from "./packets/RequestFailure.js"
import RequestSuccess from "./packets/RequestSuccess.js"
import Debug from "./packets/Debug.js"
import { readNextBuffer, readNextUint32, serializeBuffer, serializeUint32 } from "./utils/Buffer.js"
import IdentificationParser from "./IdentificationParser.js"
import { BinaryPacketDecoder, BinaryPacketEncoder } from "./BinaryPacket.js"
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
    agent?: Agent
    protocolVersionExchange?: ProtocolVersionExchange
    serverClient?: boolean
    authenticationMethodsOrder?: SSHAuthenticationMethods[]
    keepaliveInterval?: number
    keepaliveCountMax?: number
    /** Maximum milliseconds for TCP connection, SSH handshake, and authentication. Zero disables. */
    readyTimeout?: number
    /** Already-connected duplex transport, such as an SSH direct-tcpip channel. */
    sock?: Duplex
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
            | "ident"
            | "algorithms"
        >
    > {
    sock?: Duplex
    localAddress?: string
    localPort?: number
    hostHash?: string
    hostVerifier?: ClientHostVerifier
    ident?: string | Buffer
    algorithms?: ClientAlgorithmOptions
}

export type ClientHostVerifier = (
    key: Buffer | string,
    callback: (verified: boolean) => void,
) => boolean | void

export interface ClientEvents {
    debug: [...message: unknown[]]
    error: [error: Error]
    close: []
    connect: []
    message: [message: Buffer]
    packet: [packet: Packet]
    tcpWrapperLog: [message: string]
    serverProtocolVersion: [protocolVersion: ProtocolVersionExchange]
    serverKexInit: [serverKexInit: KexInit, payload: Buffer]
    serverKexDHReply: [serverKexDHReply: KexDHReply]
    clientNewKeys: []
    serverNewKeys: []
    handshake: [negotiated: Readonly<NegotiatedAlgorithms>]
    rekey: []
    /** Complete server pre-identification greeting, including its line endings. */
    greeting: [greeting: string]
    banner: [message: string, languageTag: string]
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

interface RemoteForwarding {
    bindAddress: string
    bindPort: number
}

export default class Client extends EventEmitter<ClientEvents> {
    options: ClientOptionsRequired

    constructor(options: ClientOptions) {
        super()

        this.options = options as ClientOptionsRequired
        this.options.hostname ??= "localhost"
        this.options.port ??= 22
        this.options.forceIPv4 ??= false
        this.options.forceIPv6 ??= false
        this.options.strictVendor ??= true
        this.options.username ??= "root"
        this.options.password ??= ""
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
        this.algorithmOffer = resolveClientAlgorithmOptions(this.options.algorithms, {
            kex: [...kex_algorithms.keys()],
            serverHostKey: [...host_key_algorithms.keys()],
            cipher: [...encryption_algorithms.keys()],
            hmac: [...mac_algorithms.keys()],
            compress: [...compression_algorithms.keys()],
        })

        setImmediate(() => {
            this.debug("Client created with options:", {
                ...this.options,
                password: this.options.password ? "<redacted>" : "",
                agent: this.options.agent.constructor.name,
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

    serverProtocolVersion?: ProtocolVersionExchange
    serverKexDHReply?: KexDHReply
    // TODO: Assess if these should be private properties
    clientKexInit?: KexInit
    serverKexInit?: KexInit
    kexAlgorithm?: KexAlgorithm
    hostKeyAlgorithm?: HostKeyAlgorithm
    serverSignatureAlgorithms?: readonly string[]
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

    localChannelIndex = 0
    channels = new Map<number, ClientChannel>()
    private readonly pendingGlobalRequests: PendingGlobalRequest[] = []
    private readonly remoteForwardings = new Map<string, RemoteForwarding>()
    private readonly remoteStreamLocalForwardings = new Set<string>()
    private readonly x11Forwardings = new Map<number, { single: boolean }>()
    agentForwardingEnabled = false
    private keepaliveTimer?: ReturnType<typeof setTimeout>
    private unansweredKeepalives = 0
    private readyTimer?: ReturnType<typeof setTimeout>
    private keyExchangeInProgress = false
    private readonly packetsQueuedDuringKeyExchange: Packet[] = []

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

    debug(...message: unknown[]): void {
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
        if (options.agentForward) await channel.openssh_forwardAgent()
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
                this.socket?.destroy(error as Error)
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
                ...(this.sessionID === undefined ? ["ext-info-c"] : []),
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
            chooseAlgorithms(this)

            const kexAlgorithm = this.kexAlgorithm
            assert(kexAlgorithm, "No key exchange algorithm was negotiated")
            kexAlgorithm.generateKeyPair()
            this.sendPacket(
                new KexDHInit({
                    e: kexAlgorithm.getPublicKey(),
                    encoding: kexAlgorithm.exchangeValueEncoding,
                }),
            )

            const [serverKexDHReply] = await this.waitEvent("serverKexDHReply")
            this.serverKexDHReply = serverKexDHReply
            kexAlgorithm.computeSharedSecret(serverKexDHReply.data.f)
            const hostKey = PublicKey.parse(serverKexDHReply.data.K_S)
            assert(
                hostKey.data.alg === this.hostKeyAlgorithm!.key_format,
                "Server did not use the negotiated host key algorithm",
            )
            const signature = EncodedSignature.parse(serverKexDHReply.data.H_sig)
            assert(
                signature.data.alg === this.hostKeyAlgorithm!.signature_algorithm,
                "Server did not use the negotiated signature algorithm",
            )
            const h = kexAlgorithm.computeHClient(this, serverKexInitBuffer)
            assert(hostKey.verifySignature(h, signature), "Invalid host key signature from server")

            await this.verifyConfiguredHostKey(serverKexDHReply.data.K_S)

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
            while (this.packetsQueuedDuringKeyExchange.length > 0) {
                this.writePacket(this.packetsQueuedDuringKeyExchange.shift()!)
            }
            this.emit("clientNewKeys")
            if (!this.hasReceivedNewKeys) await this.waitEvent("serverNewKeys")
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
            this.resetKeepalive()
        }
    }

    async connect(): Promise<void> {
        if (!this.canConnect) {
            throw new Error("Cannot initiate connection; client is not in a state to connect")
        }
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
                for (const channel of this.channels.values()) channel.abort()
                this.channels.clear()
                while (this.pendingGlobalRequests.length > 0) {
                    const request = this.pendingGlobalRequests.shift()!
                    request.reject(
                        new Error(`SSH connection closed during global request ${request.name}`),
                    )
                }
                this.remoteForwardings.clear()
                this.remoteStreamLocalForwardings.clear()
                this.x11Forwardings.clear()
                this.agentForwardingEnabled = false
                this.emit("close")
            }
            this.socket!.on("close", closeListener)
            if (suppliedSocket !== undefined) resolve()
        })

        this.socket!.on("data", (data) => {
            try {
                this.onMessage(data)
            } catch (error) {
                this.socket?.destroy(error as Error)
            }
        })

        this.debug(`Socket connected, sending protocol version exchange packet...`)
        this.socket!.write(this.options.protocolVersionExchange.toString())

        const [serverProtocolVersion] = await this.waitEvent("serverProtocolVersion")
        this.debug("Server protocol version:", serverProtocolVersion)

        await this.performKeyExchange()

        this.debug("Starting authentication...")

        this.sendPacket(
            new ServiceRequest({
                service_name: SSHServiceNames.UserAuth,
            }),
        )

        const serviceAnswer = await this.waitForPackets(
            {
                SSH_MSG_SERVICE_ACCEPT: {
                    predicate: (packet) => {
                        return packet.data.service_name == SSHServiceNames.UserAuth
                    },
                },
            },
            10000,
        )
        assert(serviceAnswer.data.service_name == SSHServiceNames.UserAuth)

        const methodList = this.options.authenticationMethodsOrder
        const attemptedMethods = new Set<SSHAuthenticationMethods>()
        authentication: {
            while (true) {
                const method = methodList.find(
                    (candidate) =>
                        !attemptedMethods.has(candidate) &&
                        (!this.authenticationMethodsRemaining ||
                            this.authenticationMethodsRemaining.has(candidate)),
                )
                if (!method) throw new Error("All authentication methods failed.")
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
        }
        this.hasAuthenticated = true

        // now that we have received USERAUTH_SUCCESS, we need
        // to handle GLOBAL_REQUEST.

        this.on("packet", (packet) => {
            if (!(packet instanceof GlobalRequest)) return

            this.debug(`Received global request packet:`, packet)

            switch (packet.data.request_name) {
                case "hostkeys-00@openssh.com": {
                    const hostkeys = []
                    let raw = packet.data.args
                    while (raw.length != 0) {
                        let arg: Buffer
                        ;[arg, raw] = readNextBuffer(raw)

                        try {
                            hostkeys.push(PublicKey.parse(arg))
                        } catch (err) {
                            // unsupported host key algorithm
                            // or parse error
                            // either way don't care and silently fail.
                            this.debug(`Error while trying to parse host key:`, err)
                        }
                    }

                    this.debug(`Received ${hostkeys.length} host keys from global request`)

                    // Do we care ?
                    // at this point, most usage will be
                    // from people ignoring host keys
                    // so ig 👍

                    // TODO: need to implement verifying host keys reliably
                    // this could take the form of an "KnownHostsAgent" or something
                    // that stores known hosts in a file (.ssh/known_hosts) or in
                    // memory, or in a database.

                    // https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL?annotate=HEAD
                    // section 2.5 (ctrl + f search for "hostkeys-00@openssh.com")
                    break
                }
                default: {
                    this.debug(`Unknown global request name: ${packet.data.request_name}`)
                    if (packet.data.want_reply) {
                        // this might be a keep alive lol
                        // shitty spec
                        // either way, send a failure response.
                        this.sendPacket(new RequestFailure({}))
                    }
                }
            }
        })

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
            const handler = (...values: ClientEvents[event]) => {
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
    waitForPacket<Name extends keyof typeof packets>(name: Name): Promise<(typeof packets)[Name]> {
        return new Promise((resolve, reject) => {
            const classType = packets[name]
            const onError = (error: Error) => {
                cleanup()
                reject(error)
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
            }
            this.on("packet", handler)
            this.once("error", onError)
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
            const timer = setTimeout(() => {
                cleanup()
                reject(new Error("Timed out waiting for message"))
            }, timeout)
            this.on("packet", onPacket)
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

        if (!(packetType in PacketTypeToName)) {
            throw new Error("Invalid packet type: " + packetType)
        }
        const packetName = PacketTypeToName[packetType]
        if (!(packetName in packets)) {
            throw new Error("Not implemented: " + packetName)
        }
        let packet: typeof Packet
        if (packetType === PacketNameToType.SSH_MSG_USERAUTH_PK_OK) {
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

        if (p instanceof UserAuthFailure) {
            this.authenticationMethodsRemaining = new Set(p.data.auth_methods)
            this.partialAuthenticationSuccess = p.data.partial_success
            this.authenticationFailureSequence++
        }

        this.emit("packet", p)

        this.routeGlobalRequestReply(p)
        this.routeChannelPacket(p)

        switch (packet.type) {
            case PacketNameToType.SSH_MSG_DISCONNECT: {
                const disconnect = p as Disconnect
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
                this.debug(`Received debug packet:`, [debug.data.message])
                break
            }

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
                const extension = (p as ExtInfo).data.extensions.find(
                    ({ name }) => name === "server-sig-algs",
                )
                if (extension) {
                    this.serverSignatureAlgorithms = Object.freeze(
                        extension.value
                            .toString("ascii")
                            .split(",")
                            .filter((name) => name.length > 0),
                    )
                }
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
                this.emit("serverNewKeys")
                break

            case PacketNameToType.SSH_MSG_KEXDH_REPLY:
                this.packetProcessingPaused = true
                this.emit("serverKexDHReply", p as KexDHReply)
                break
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

    private routeChannelPacket(packet: Packet): void {
        if (packet instanceof ChannelOpen) {
            this.handleIncomingChannelOpen(packet)
            return
        }

        if (packet instanceof ChannelOpenConfirmation) {
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
            if (channel.isFullyClosed) this.channels.delete(channel.localId)
        } else if (packet instanceof ChannelRequest) {
            channel.receiveRequest(packet)
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
        if (!channel) throw new Error(`Received a packet for unknown SSH channel ${localId}`)
        return channel
    }
}
