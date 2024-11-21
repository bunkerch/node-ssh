import { Socket } from "node:net"
import Server, {
    ServerHookerNoneAuthenticationContext,
    ServerHookerNoneAuthenticationController,
    ServerHookerPasswordAuthenticationContext,
    ServerHookerPasswordAuthenticationController,
    ServerHookerPublicKeyAuthenticationContext,
    ServerHookerPublicKeyAuthenticationController,
} from "./Server.js"
import ProtocolVersionExchange from "./ProtocolVersionExchange.js"
import { timingSafeEqual } from "node:crypto"
import EventEmitter from "node:events"
import TypedEventEmitter from "typed-emitter"
import {
    SEQUENCE_NUMBER_MODULO,
    SSHAuthenticationMethods,
    SSHPacketType,
    SSHServiceNames,
    SocketState,
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
import { readNextBuffer, serializeBuffer } from "./utils/Buffer.js"
import RequestFailure from "./packets/RequestFailure.js"
import RequestSuccess from "./packets/RequestSuccess.js"

export type ServerClientEvents = {
    error: (error: Error) => void
    close: () => void
    connect: () => void
    debug: (...message: any[]) => void
    message: (message: Buffer) => void
    clientProtocolVersion: (version: ProtocolVersionExchange) => void
    tcpWrapperLog: (message: string) => void
    packet: (packet: Packet) => void
    clientKexInit: (kexInit: KexInit, payload: Buffer) => void
    clientNewKeys: () => void
    serverNewKeys: () => void
}

export default class ServerClient extends (EventEmitter as new () => TypedEventEmitter<ServerClientEvents>) {
    private socket: Socket
    connectionId: string
    server: Server

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
            this.emit("close")
        })
    }

    private buffering: Buffer = Buffer.alloc(0)
    private buffering_decrypted: Buffer = Buffer.alloc(0)
    private in_sequence_number = 0
    private out_sequence_number = 0

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

    hasReceivedNewKeys: boolean = false
    hasSentNewKeys: boolean = false
    hasAuthenticated: boolean = false
    credentials: UserAuthRequest | undefined

    localChannelIndex = 0
    channels = new Map<number, Channel>()

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

        this.sendPacket(new NewKeys({}))
        this.hasSentNewKeys = true
        this.emit("serverNewKeys")
        if (!this.hasReceivedNewKeys) {
            await this.waitEvent("clientNewKeys")
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
        // emit the event
        this.emit("connect")

        // now that we have received USERAUTH_SUCCESS, we need
        // to handle GLOBAL_REQUEST.

        this.on("packet", (packet) => {
            if (!(packet instanceof GlobalRequest)) return

            this.debug(`Received global request packet:`, packet)

            switch (packet.data.request_name) {
                case "hostkeys-prove-00@openssh.com": {
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

                    this.debug(`Client asked us to prove ownership of`, hostkeys.length, `keys.`)

                    const signatures = []
                    for (const pubkey of hostkeys) {
                        const hostkey = this.server.options.hostKeys.find((privkey) =>
                            privkey.data.publicKey.equals(pubkey),
                        )

                        if (!hostkey) {
                            this.debug(
                                `Client asked us to prove ownership of a public key we do not control!`,
                            )
                            this.sendPacket(new RequestFailure({}))
                            return
                        }

                        const message = Buffer.concat([
                            serializeBuffer(Buffer.from("hostkeys-prove-00@openssh.com", "utf8")),
                            serializeBuffer(this.sessionID!),
                            serializeBuffer(pubkey.serialize()),
                        ])
                        signatures.push(serializeBuffer(hostkey.sign(message).serialize()))
                    }

                    this.sendPacket(
                        new RequestSuccess({
                            args: Buffer.concat(signatures),
                        }),
                    )
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
    ): Promise<Parameters<ServerClientEvents[event]>> {
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

    sendPacket(packet: Packet): number {
        this.debug("Sending packet:", packet)
        const payload = packet.serialize()
        const padding_multiple = Math.max(8, this.serverEncryptionAlgorithm?.block_size ?? 8)
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
            mac = this.serverMac!.computeMAC(seqno, packet_buf)
            packet_buf = this.serverEncryption!.encrypt(packet_buf)
        } else {
            mac = Buffer.allocUnsafe(0)
        }

        this.socket!.write(Buffer.concat([packet_buf, mac]))
        this.out_sequence_number++
        this.out_sequence_number %= SEQUENCE_NUMBER_MODULO

        return seqno
    }

    debug(...message: any[]): void {
        this.server.debug(`[${this.connectionId}]`, ...message)
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
                    this.clientProtocolVersion = ProtocolVersionExchange.parse(line)
                    this.emit("clientProtocolVersion", this.clientProtocolVersion)
                    this.debug("Client protocol version:", this.clientProtocolVersion)
                    break // no utf8 message after that.
                } else {
                    // remove trailing whitespace and newlines
                    line = line.replace(/[\r\s]+\n$/, "")
                    this.emit("tcpWrapperLog", line)
                    this.debug("TCP Wrapper log:", line)
                }
            }

            if (!this.clientProtocolVersion) {
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
            const padding_multiple = Math.max(8, this.clientEncryptionAlgorithm?.block_size ?? 8)
            if (message.length < Math.max(16, padding_multiple)) {
                this.buffering = message
                this.debug("Partial message, buffering...")
                return
            }

            const macsize =
                this.hasReceivedNewKeys && this.hasSentNewKeys
                    ? this.clientMacAlgorithm!.digest_length
                    : 0

            let packet_length: number
            let padding_length: number
            if (this.hasReceivedNewKeys && this.hasSentNewKeys) {
                let first16: Buffer
                if (this.buffering_decrypted.length >= 16) {
                    first16 = this.buffering_decrypted.subarray(0, 16)
                } else {
                    first16 = this.clientEncryption!.decrypt(message.subarray(0, 16))
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
                    this.clientEncryption!.decrypt(
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
                const computed_mac = this.clientMac!.computeMAC(
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
                case SSHPacketType.SSH_MSG_DISCONNECT: {
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

                case SSHPacketType.SSH_MSG_IGNORE:
                    this.debug(`Received Ignore packet. Ignoring.`)
                    break

                case SSHPacketType.SSH_MSG_DEBUG: {
                    const debug = p as Debug
                    this.debug(`Received debug packet:`, [debug.data.message])
                    break
                }

                case SSHPacketType.SSH_MSG_KEXINIT:
                    // handle key exchange
                    this.emit("clientKexInit", p as KexInit, payload)
                    break

                case SSHPacketType.SSH_MSG_NEWKEYS:
                    this.hasReceivedNewKeys = true
                    this.emit("clientNewKeys")
                    // handle key exchange
                    break
            }

            if (this.buffering.length > 0) {
                this.onMessage(Buffer.alloc(0))
            }
        }
    }
}
