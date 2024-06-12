import crypto, { timingSafeEqual } from "crypto"
import EventEmitter from "node:events"
import os from "node:os"
import TypedEmitter from "typed-emitter"
import net from "node:net"
import { SEQUENCE_NUMBER_MODULO, SocketState, SSHPacketType, SSHServiceNames } from "./constants.js"
import ProtocolVersionExchange from "./ProtocolVersionExchange.js"
import assert from "node:assert"
import Packet, { packets } from "./packet.js"
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
import Unimplemented from "./packets/Unimplemented.js"
import UserAuthFailure from "./packets/UserAuthFailure.js"
import ServiceRequest from "./packets/ServiceRequest.js"
import ServiceAccept from "./packets/ServiceAccept.js"
import UserAuthSuccess from "./packets/UserAuthSuccess.js"
import Agent from "./publickey/Agent.js"
import DiskAgent from "./publickey/DiskAgent.js"
import UserAuthPKOK from "./packets/UserAuthPKOK.js"
import PublicKeyAuthMethod from "./auth/publickey.js"

export interface ClientOptions {
    hostname: string
    port?: number
    username?: string
    password?: string
    agent?: Agent
    protocolVersionExchange?: ProtocolVersionExchange
    serverClient?: boolean
}
export interface ClientOptionsRequired extends Required<ClientOptions> {}

export type ClientEvents = {
    debug: (...message: any[]) => void
    error: (error: Error) => void
    close: () => void
    connect: () => void
    message: (message: Buffer) => void
    packet: (packet: Packet) => void
    tcpWrapperLog: (message: string) => void
    serverProtocolVersion: (protocolVersion: ProtocolVersionExchange) => void
    serverKexInit: (serverKexInit: KexInit, payload: Buffer) => void
    serverKexDHReply: (serverKexDHReply: KexDHReply) => void
    clientNewKeys: () => void
    serverNewKeys: () => void
}

export type ClientHookerHostKeyController = {
    allowHostKey: boolean
}
export type ClientHookerPasswordAuthContext = Readonly<{
    username: string
}>
export type ClientHookerPasswordAuthController = {
    password: string | undefined
}
export type ClientHooker = {
    hostKey: [hostKeyController: ClientHookerHostKeyController, serverPublicKey: PublicKey]
    passwordAuth: [
        passwordAuthContext: ClientHookerPasswordAuthContext,
        passwordAuthController: ClientHookerPasswordAuthController,
    ]
}

export default class Client extends (EventEmitter as new () => TypedEmitter<ClientEvents>) {
    options: ClientOptionsRequired

    constructor(options: ClientOptions) {
        super()

        this.options = options as ClientOptionsRequired
        this.options.port ??= 22
        this.options.username ??= os.userInfo({ encoding: "utf8" }).username
        this.options.password ??= ""
        this.options.agent ??= new DiskAgent()
        this.options.protocolVersionExchange ??= ProtocolVersionExchange.defaultValue

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

    hooker: Hooker<ClientHooker> = new Hooker()

    private socket?: net.Socket
    private buffering: Buffer = Buffer.alloc(0)
    private buffering_decrypted: Buffer = Buffer.alloc(0)
    private in_sequence_number = 0
    private out_sequence_number = 0

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

    hasReceivedNewKeys: boolean = false
    hasSentNewKeys: boolean = false

    state = SocketState.Closed
    get isConnected(): boolean {
        return this.state === SocketState.Connected
    }
    get canConnect(): boolean {
        return this.state === SocketState.Closed
    }

    debug(...message: any[]): void {
        this.emit("debug", ...message)
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
                    this.emit("close")
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

        // TODO: onMessage can throw errors, handle them
        this.socket!.on("data", this.onMessage.bind(this))

        this.debug(`Socket connected, sending protocol version exchange packet...`)
        this.socket!.write(this.options.protocolVersionExchange.toString())

        const [serverProtocolVersion] = await this.waitEvent("serverProtocolVersion")
        this.debug("Server protocol version:", serverProtocolVersion)

        this.clientKexInit = new KexInit({
            cookie: crypto.getRandomValues(Buffer.alloc(16)),
            kex_algorithms: [...kex_algorithms.keys()],
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

        this.sendPacket(new NewKeys({}))
        this.hasSentNewKeys = true
        this.emit("clientNewKeys")
        if (!this.hasReceivedNewKeys) {
            await this.waitEvent("serverNewKeys")
        }

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

        this.debug("Keys exchanged, encryption and MAC algorithms set up")
        this.debug("Starting authentication...")

        this.sendPacket(
            new ServiceRequest({
                service_name: SSHServiceNames.UserAuth,
            }),
        )

        const serviceAnswer: ServiceAccept = await this.waitForPackets(
            {
                [SSHPacketType.SSH_MSG_SERVICE_ACCEPT]: {
                    predicate: (packet: ServiceAccept) => {
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
        for (const method of methodList) {
            const m = UserAuthRequest.auth_methods.get(method)!
            this.debug(`Trying auth method`, m.method_name)

            const iterator = m.getPackets(this)
            // eslint-disable-next-line no-constant-condition
            while (true) {
                const { value, done } = await iterator.next()
                if (done) break

                let packet: UserAuthRequest | undefined = value

                while (packet) {
                    const seqno = this.sendPacket(packet)

                    const answer: Unimplemented | UserAuthFailure | UserAuthSuccess =
                        await this.waitForPackets(
                            {
                                [SSHPacketType.SSH_MSG_UNIMPLEMENTED]: {
                                    predicate: (packet: Unimplemented) => {
                                        return packet.data.sequence_number === seqno
                                    },
                                },
                                [SSHPacketType.SSH_MSG_USERAUTH_FAILURE]: {
                                    predicate: () => true,
                                },
                                [SSHPacketType.SSH_MSG_USERAUTH_SUCCESS]: {
                                    predicate: () => true,
                                },
                                [SSHPacketType.SSH_MSG_USERAUTH_PK_OK]: {
                                    predicate: () => true,
                                },
                            },
                            10000,
                        )

                    console.log(answer)

                    if (answer instanceof UserAuthSuccess) {
                        this.debug(`Authentication successful with method`, m.method_name)
                        this.debug("Authenticated as", this.options.username)

                        // stops the getPackets generator
                        iterator.return(undefined)

                        this.emit("connect")
                        return
                    } else if (answer instanceof UserAuthPKOK) {
                        const method = packet.data.method as PublicKeyAuthMethod
                        assert(
                            method instanceof PublicKeyAuthMethod,
                            "Server returned an UserAuthPKOK packet but the method was not a PublicKeyAuthMethod",
                        )

                        const keys = await this.options.agent.getPublicKeys()
                        const key = keys.find((key) => key[1].equals(method.data.publicKey))
                        assert(
                            key,
                            "Server requested a public key that was not provided by the agent",
                        )
                        method.data.signature = await this.options.agent.sign(
                            key[0],
                            packet.serializeForSignature(this),
                        )
                    } else {
                        packet = undefined
                    }
                }
            }
        }

        //
    }

    waitEvent<event extends keyof ClientEvents>(
        event: event,
    ): Promise<Parameters<ClientEvents[event]>> {
        return new Promise((resolve, reject) => {
            const onError = (error: Error) => {
                cleanup()
                reject(error)
            }
            const handler = (...values: any) => {
                resolve(values)
                cleanup()
            }
            const cleanup = () => {
                this.off(event, handler)
                this.off("error", onError)
            }
            this.once(event, handler)
            this.once("error", onError)
        })
    }
    waitForPacket<packet extends Packet>(packet: SSHPacketType): Promise<packet> {
        return new Promise((resolve, reject) => {
            const onError = (error: Error) => {
                cleanup()
                reject(error)
            }
            const handler = (p: Packet) => {
                // eslint-disable-next-line @typescript-eslint/ban-ts-comment
                // @ts-expect-error
                // type is a static property on every packet class
                if (p.constructor.type === packet) {
                    resolve(p as packet)
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
    waitForPackets<
        packets extends {
            [key in SSHPacketType]?: {
                predicate: (packet: any) => boolean
            }
        },
    >(packets: packets, timeout: number): Promise<any> {
        return new Promise((resolve, reject) => {
            const cleanup = () => {
                this.off("packet", onPacket)
                this.off("error", onError)
                clearTimeout(timer)
            }
            const onPacket = (packet: Packet) => {
                // toString to convert the number to a string
                // because the type key in the packets object
                // is transformed to a stirng by javascript
                // could also use a loose == but I prefer to be explicit
                const packetType = (packet.constructor as typeof Packet).type.toString()
                for (const [type, { predicate }] of Object.entries(packets)) {
                    if (packetType === type && predicate(packet)) {
                        resolve(packet)
                        cleanup()
                        return
                    }
                }
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
        const payload = packet.serialize()
        const padding_multiple = Math.max(8, this.clientEncryptionAlgorithm?.block_size ?? 8)
        let padding_length = padding_multiple - ((4 + 1 + payload.length) % padding_multiple)
        if (padding_length < 4) {
            padding_length += padding_multiple
        }
        const padding = crypto.getRandomValues(Buffer.allocUnsafe(padding_length))

        const packet_length = Buffer.allocUnsafe(4)
        packet_length.writeUInt32BE(1 + payload.length + padding_length, 0)

        let packet_buf = Buffer.concat([
            packet_length,
            Buffer.from([padding_length]),
            payload,
            padding,
        ])

        const seqno = this.out_sequence_number
        let mac: Buffer
        if (this.hasReceivedNewKeys && this.hasSentNewKeys) {
            // we'll also encrypt here
            mac = this.clientMac!.computeMAC(seqno, packet_buf)
            packet_buf = this.clientEncryption!.encrypt(packet_buf)
        } else {
            mac = Buffer.allocUnsafe(0)
        }

        this.socket!.write(Buffer.concat([packet_buf, mac]))
        this.out_sequence_number++
        this.out_sequence_number %= SEQUENCE_NUMBER_MODULO

        return seqno
    }

    onMessage(message: Buffer): void {
        if (!this.serverProtocolVersion) {
            // split("\n") but for buffers
            const lines: Buffer[] = []
            let index = 0
            for (let i = 0; i < message.length; i++) {
                if (message[i] === 0x0a) {
                    lines.push(message.subarray(index, i + 1))
                    index += i + 1
                }
            }
            if (index < message.length) {
                lines.push(message.subarray(index))
            }

            while (lines[0]) {
                const lineBuf = lines.shift()!
                this.emit("message", lineBuf)
                let line = lineBuf!.toString("utf8")
                if (line?.startsWith("SSH-")) {
                    // protocol version exchange
                    this.serverProtocolVersion = ProtocolVersionExchange.parse(line)
                    this.emit("serverProtocolVersion", this.serverProtocolVersion)
                    break // no utf8 message after that.
                } else {
                    // remove trailing whitespace and newlines
                    line = line.replace(/[\r\s]+\n$/, "")
                    this.emit("tcpWrapperLog", line)
                    this.debug("TCP Wrapper log:", line)
                }
            }

            if (!this.serverProtocolVersion) {
                return
            }

            if (lines.length == 0) {
                return
            }

            // process the remaining lines
            message = Buffer.concat(lines)
            return this.onMessage(message)
        } else {
            // binary packet protocol
            message = Buffer.concat([this.buffering, message])
            const padding_multiple = Math.max(8, this.serverEncryptionAlgorithm?.block_size ?? 8)
            if (message.length < Math.max(16, padding_multiple)) {
                this.buffering = message
                this.debug("Partial message, buffering...")
                return
            }

            const macsize =
                this.hasReceivedNewKeys && this.hasSentNewKeys
                    ? this.serverMacAlgorithm!.digest_length
                    : 0

            let packet_length: number
            let padding_length: number
            if (this.hasReceivedNewKeys && this.hasSentNewKeys) {
                let first16: Buffer
                if (this.buffering_decrypted.length >= 16) {
                    first16 = this.buffering_decrypted.subarray(0, 16)
                } else {
                    first16 = this.serverEncryption!.decrypt(message.subarray(0, 16))
                    this.buffering_decrypted = first16
                }
                packet_length = first16.readUInt32BE(0)
                padding_length = first16[4]
            } else {
                packet_length = message.readUInt32BE(0)
                padding_length = message[4]
            }

            // TODO: Comply with 6.1. Maximum Packet Length
            // https://datatracker.ietf.org/doc/html/rfc4253#section-6.1
            if (message.length < packet_length + 4 + macsize) {
                this.buffering = message
                this.debug("Partial message, buffering...")
                return
            }
            assert(padding_length <= 255, "Invalid padding length (too long)")
            assert(padding_length >= 4, "Invalid padding length (too short)")

            const n1 = packet_length - padding_length - 1
            const n2 = padding_length
            const cipher_mul = 4 + 1 + n1 + n2
            assert(cipher_mul % padding_multiple === 0, "Invalid cipher multiplication")

            let decrypted_message = message
            if (this.hasReceivedNewKeys && this.hasSentNewKeys) {
                decrypted_message = Buffer.concat([
                    this.buffering_decrypted,
                    this.serverEncryption!.decrypt(
                        message.subarray(this.buffering_decrypted.length, 5 + n1 + n2),
                    ),
                ])
                this.buffering_decrypted = Buffer.alloc(0)
            }

            const payload = decrypted_message.subarray(5, 5 + n1)
            //const padding = decrypted_message.subarray(5 + n1, 5 + n1 + n2)
            const mac = message.subarray(5 + n1 + n2, 5 + n1 + n2 + macsize)
            if (this.hasReceivedNewKeys && this.hasSentNewKeys) {
                // verify MAC
                const computed_mac = this.serverMac!.computeMAC(
                    this.in_sequence_number,
                    decrypted_message.subarray(0, 5 + n1 + n2),
                )
                assert(computed_mac.length === mac.length, "Invalid MAC size")
                assert(timingSafeEqual(computed_mac, mac), "Invalid MAC")
            }

            this.buffering = message.subarray(5 + n1 + n2 + macsize)
            message = message.subarray(0, 5 + n1 + n2 + macsize)
            this.emit("message", message)

            this.debug("Receiving packet:", SSHPacketType[payload[0]])

            this.in_sequence_number++
            this.in_sequence_number %= SEQUENCE_NUMBER_MODULO

            const packet = packets.get(payload[0])
            if (!packet) {
                throw new Error("Invalid packet type (" + payload[0] + ")")
            }

            const p = packet.parse(payload)
            this.emit("packet", p)
            this.debug("Parsing packet:", p)

            switch (packet.type) {
                case SSHPacketType.SSH_MSG_KEXINIT:
                    // handle key exchange
                    this.emit("serverKexInit", p as KexInit, payload)
                    break
                case SSHPacketType.SSH_MSG_KEXDH_REPLY:
                    // handle key exchange
                    this.emit("serverKexDHReply", p as KexDHReply)
                    break
                case SSHPacketType.SSH_MSG_NEWKEYS:
                    this.hasReceivedNewKeys = true
                    this.emit("serverNewKeys")
                    // handle key exchange
                    break
                case SSHPacketType.SSH_MSG_DISCONNECT: {
                    const disconnect = p as Disconnect
                    this.debug(
                        "Server disconnected:",
                        DisconnectReason[disconnect.data.reason_code],
                        disconnect.data.description,
                        disconnect.data.language_tag,
                    )
                    // TODO: Handle disconnect
                }
            }

            if (this.buffering.length > 0) {
                this.onMessage(Buffer.alloc(0))
            }
        }
    }
}
