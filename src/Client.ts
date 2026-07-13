import crypto from "crypto"
import EventEmitter from "node:events"
import net from "node:net"
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
    encryption_algorithms,
    kex_algorithms,
    mac_algorithms,
} from "./algorithms.js"
import KexDHInit from "./packets/KexDHInit.js"
import KexDHReply from "./packets/KexDHReply.js"
import EncodedSignature from "./utils/Signature.js"
import PublicKey, { PublicKeyAlgoritm } from "./utils/PublicKey.js"
import { Hooker } from "./utils/Hooker.js"
import DiffieHellmanGroupN from "./algorithms/kex/diffie-hellman-groupN.js"
import NewKeys from "./packets/NewKeys.js"
import UserAuthRequest from "./packets/UserAuthRequest.js"
import Disconnect, { DisconnectReason } from "./packets/Disconnect.js"
import ServiceRequest from "./packets/ServiceRequest.js"
import Agent from "./publickey/Agent.js"
import NoneAgent from "./publickey/NoneAgent.js"
import GlobalRequest from "./packets/GlobalRequest.js"
import RequestFailure from "./packets/RequestFailure.js"
import Debug from "./packets/Debug.js"
import { readNextBuffer } from "./utils/Buffer.js"
import Channel from "./Channel.js"
import IdentificationParser from "./IdentificationParser.js"
import { BinaryPacketDecoder, BinaryPacketEncoder } from "./BinaryPacket.js"

export interface ClientOptions {
    hostname: string
    port?: number
    username?: string
    password?: string
    agent?: Agent
    protocolVersionExchange?: ProtocolVersionExchange
    serverClient?: boolean
    authenticationMethodsOrder?: SSHAuthenticationMethods[]
}

// eslint-disable-next-line @typescript-eslint/no-empty-object-type
export interface ClientOptionsRequired extends Required<ClientOptions> {}

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
}

export default class Client extends EventEmitter<ClientEvents> {
    options: ClientOptionsRequired

    constructor(options: ClientOptions) {
        super()

        this.options = options as ClientOptionsRequired
        this.options.port ??= 22
        this.options.username ??= "root"
        this.options.password ??= ""
        this.options.agent ??= new NoneAgent()
        this.options.protocolVersionExchange ??= ProtocolVersionExchange.defaultValue
        this.options.authenticationMethodsOrder ??= [
            SSHAuthenticationMethods.None,
            SSHAuthenticationMethods.PublicKey,
            SSHAuthenticationMethods.Password,
        ]

        setImmediate(() => {
            this.debug("Client created with options:", this.options)
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

    private socket?: net.Socket
    private identificationParser = new IdentificationParser({ allowPreamble: true })
    private packetDecoder = new BinaryPacketDecoder()
    private packetEncoder = new BinaryPacketEncoder()

    serverProtocolVersion?: ProtocolVersionExchange
    serverKexDHReply?: KexDHReply
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

    localChannelIndex = 0
    channels = new Map<number, Channel>()

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

    private scheduleMessageProcessing(message: Buffer): void {
        queueMicrotask(() => {
            try {
                this.onMessage(message)
            } catch (error) {
                this.socket?.destroy(error as Error)
            }
        })
    }

    async connect(): Promise<void> {
        if (!this.canConnect) {
            throw new Error("Cannot initiate connection; client is not in a state to connect")
        }
        this.state = SocketState.Connecting
        this.socket = net.createConnection({
            host: this.options.hostname,
            port: this.options.port,
        })

        let connected = false
        await new Promise<void>((resolve, reject) => {
            const connectListener = () => {
                connected = true
                resolve()
            }
            this.socket!.on("connect", connectListener)
            const errorListener = (error: Error) => {
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
                this.state = SocketState.Closed
                this.debug("Socket closed")
                this.socket = undefined
                this.emit("close")
            }
            this.socket!.on("close", closeListener)
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

        this.clientKexInit = new KexInit({
            cookie: crypto.getRandomValues(Buffer.alloc(16)),
            kex_algorithms: [...kex_algorithms.keys()],
            // TODO: Disable ssh-rsa. Most vendors already do.
            // They do it because ssh-rsa uses sha1 as a hashing algorithm
            // for signature. This is insecure.
            server_host_key_algorithms: [...PublicKey.algorithms.keys()],
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
        this.sendPacket(this.clientKexInit)

        const [serverKexInit, serverKexInitBuffer] = await this.waitEvent("serverKexInit")
        this.serverKexInit = serverKexInit
        this.debug("Server KexInit:", serverKexInit)
        chooseAlgorithms(this)

        if (this.kexAlgorithm instanceof DiffieHellmanGroupN) {
            this.debug(
                "Using DiffieHellmanGroupN key exchange algorithm",
                (this.kexAlgorithm.constructor as typeof KexAlgorithm).alg_name,
            )
            this.kexAlgorithm.generateKeyPair()
            this.sendPacket(
                new KexDHInit({
                    e: this.kexAlgorithm.keyPair!.getPublicKey(),
                }),
            )

            const [serverKexDHReply] = await this.waitEvent("serverKexDHReply")
            this.debug("Server KexDHReply:", serverKexDHReply)
            this.serverKexDHReply = serverKexDHReply

            this.kexAlgorithm.sharedSecret = this.kexAlgorithm.keyPair!.computeSecret(
                serverKexDHReply.data.f,
            )
            const hostKey = PublicKey.parse(serverKexDHReply.data.K_S)
            assert(
                hostKey.data.alg === this.hostKeyAlgorithm!.alg_name,
                "Invalid host key algorithm (Server did not send the negotiated algorithm)",
            )
            this.debug("Host key:", hostKey.toString())
            const signature = EncodedSignature.parse(serverKexDHReply.data.H_sig)
            this.debug("Signature:", signature)
            assert(
                signature.data.alg === this.hostKeyAlgorithm!.alg_name,
                "Invalid signature algorithm (Server did not send the negotiated algorithm)",
            )

            const h = this.kexAlgorithm.computeHClient(
                this,

                serverKexInitBuffer,
            )

            assert(hostKey.verifySignature(h, signature), "Invalid host key signature from server!")
            this.debug("Host key signature verified")

            if (this.hooker.hasHooks("hostKey")) {
                const controller: ClientHookerHostKeyController = {
                    allowHostKey: false,
                }
                await this.hooker.triggerHook("hostKey", controller, hostKey)

                if (!controller.allowHostKey) {
                    this.debug("Hook rejected host key")
                    throw new Error("Host key not allowed by hook")
                } else {
                    this.debug("Hook allowed host key")
                }
            } else {
                this.debug("Host key implicitly allowed; No host key hooks registered")
            }

            // at this point, we're good to go
            this.H = h
            this.sessionID = h
        } else {
            throw new Error("Unsupported key exchange algorithm (Not Implemented in Client)")
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

        this.sendPacket(new NewKeys({}))
        this.hasSentNewKeys = true
        this.packetEncoder.setProtection({
            cipher: this.clientEncryption,
            mac: this.clientMac,
            blockSize: this.clientEncryptionAlgorithm!.block_size,
            macLength: this.clientMacAlgorithm!.digest_length,
        })
        this.emit("clientNewKeys")
        if (!this.hasReceivedNewKeys) {
            await this.waitEvent("serverNewKeys")
        }

        this.debug("Keys exchanged, encryption and MAC algorithms set up")
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

        // TODO: Maybe get list of auth methods from server
        // can be done through UserAuthFailure.auth_methods
        const methodList: string[] = [...UserAuthRequest.auth_methods.keys()]
        authentication: {
            for (const method of methodList) {
                const m = UserAuthRequest.auth_methods.get(method)!
                this.debug(`Trying auth method`, m.method_name)

                const success = await m.handleAuthentication(this)
                if (success) {
                    this.debug(`Authentication successful with method`, m.method_name)
                    this.debug("Authenticated as", this.options.username)

                    break authentication
                }
            }

            // we could not authenticate.
            throw new Error("All authentication methods failed.")
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
        this.emit("connect")
    }

    end(): this {
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
        this.debug("Sending packet:", packet)
        const encoded = this.packetEncoder.encode(packet.serialize())
        this.socket!.write(encoded.data)
        return encoded.sequenceNumber
    }

    onMessage(message: Buffer): void {
        if (!this.serverProtocolVersion) {
            const result = this.identificationParser.push(message)
            for (const lineBuf of result.preamble) {
                this.emit("message", lineBuf)
                const line = lineBuf.toString("utf8").replace(/\r?\n$/u, "")
                this.emit("tcpWrapperLog", line)
                this.debug("TCP Wrapper log:", line)
            }

            if (!result.version || !result.identification) return

            this.emit("message", result.identification)
            this.serverProtocolVersion = result.version
            this.emit("serverProtocolVersion", result.version)

            if (result.remainder.length > 0) {
                this.scheduleMessageProcessing(result.remainder)
            }
            return
        }

        this.packetDecoder.push(message)
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
        this.debug("Parsing packet:", p)

        this.emit("packet", p)

        switch (packet.type) {
            case PacketNameToType.SSH_MSG_DISCONNECT: {
                const disconnect = p as Disconnect
                this.debug(
                    "Server disconnected:",
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
                this.emit("serverKexInit", p as KexInit, payload)
                break

            case PacketNameToType.SSH_MSG_NEWKEYS:
                this.hasReceivedNewKeys = true
                this.packetDecoder.setProtection({
                    cipher: this.serverEncryption!,
                    mac: this.serverMac!,
                    blockSize: this.serverEncryptionAlgorithm!.block_size,
                    macLength: this.serverMacAlgorithm!.digest_length,
                })
                this.emit("serverNewKeys")
                break

            case PacketNameToType.SSH_MSG_KEXDH_REPLY:
                // handle key exchange
                this.emit("serverKexDHReply", p as KexDHReply)
                break
        }

        if (this.packetDecoder.bufferedLength > 0) {
            this.scheduleMessageProcessing(Buffer.alloc(0))
        }
    }
}
