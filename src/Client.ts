import crypto, { timingSafeEqual } from "crypto"
import EventEmitter from "node:events"
import os from "node:os"
import TypedEmitter from "typed-emitter"
import net from "node:net"
import { SEQUENCE_NUMBER_MODULO, SocketState, SSHPacketType } from "./constants.js"
import ProtocolVersionExchange from "./ProtocolVersionExchange.js"
import assert from "node:assert"
import Packet, { packets } from "./packet.js"
import KexInit from "./packets/KexInit.js"
import {
    EncryptionAlgorithm,
    HostKeyAlgorithm,
    KexAlgorithm,
    MACAlgorithm,
    encryption_algorithms,
    host_key_algorithms,
    kex_algorithms,
    mac_algorithms,
} from "./algorithms.js"
import KexDHInit from "./packets/KexDHInit.js"
import KexDHReply from "./packets/KexDHReply.js"
import EncodedSignature from "./utils/Signature.js"
import PublicKey from "./utils/PublicKey.js"
import { Hooker } from "./utils/Hooker.js"
import DiffieHellmanGroupN from "./algorithms/kex/diffie-hellman-groupN.js"
import NewKeys from "./packets/NewKeys.js"
import UserAuthRequest from "./packets/UserAuthRequest.js"
import NoneAuthMethod from "./auth/none.js"

export interface ClientOptions {
    hostname: string
    port?: number
    username?: string
    protocolVersionExchange?: ProtocolVersionExchange
}
export interface ClientOptionsRequired extends Required<ClientOptions> {}

export type ClientEvents = {
    debug: (...message: any[]) => void
    error: (error: Error) => void
    close: () => void
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
export type ClientHooker = {
    hostKey: [ClientHookerHostKeyController, PublicKey]
}

export default class Client extends (EventEmitter as new () => TypedEmitter<ClientEvents>) {
    options: ClientOptionsRequired
    constructor(options: ClientOptions) {
        super()
        this.options = options as ClientOptionsRequired
        this.options.port = options.port ?? 22
        this.options.username = options.username ?? os.userInfo({ encoding: "utf8" }).username
        this.options.protocolVersionExchange =
            options.protocolVersionExchange ?? ProtocolVersionExchange.defaultValue
        setImmediate(() => {
            this.debug("Client created with options:", this.options)
        })
    }

    hooker: Hooker<ClientHooker> = new Hooker()

    private socket: net.Socket | undefined
    private buffering: Buffer = Buffer.alloc(0)
    private in_sequence_number = 0
    private out_sequence_number = 0

    serverProtocolVersion: ProtocolVersionExchange | undefined
    serverKexDHReply: KexDHReply | undefined

    // TODO: Assess if these should be private properties
    clientKexInit: KexInit | undefined
    serverKexInit: KexInit | undefined
    kexAlgorithm: KexAlgorithm | undefined
    hostKeyAlgorithm: typeof HostKeyAlgorithm | undefined
    clientEncryptionAlgorithm: typeof EncryptionAlgorithm | undefined
    serverEncryptionAlgorithm: typeof EncryptionAlgorithm | undefined
    clientEncryption: EncryptionAlgorithm | undefined
    serverEncryption: EncryptionAlgorithm | undefined
    clientMacAlgorithm: typeof MACAlgorithm | undefined
    serverMacAlgorithm: typeof MACAlgorithm | undefined
    clientMac: MACAlgorithm | undefined
    serverMac: MACAlgorithm | undefined

    // TODO: Set those as private properties (Need to be accessed by the algorithms only)
    H: Buffer | undefined
    sessionID: Buffer | undefined
    ivClientToServer: Buffer | undefined
    ivServerToClient: Buffer | undefined
    encryptionKeyClientToServer: Buffer | undefined
    encryptionKeyServerToClient: Buffer | undefined
    integrityKeyClientToServer: Buffer | undefined
    integrityKeyServerToClient: Buffer | undefined

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
            server_host_key_algorithms: [...host_key_algorithms.keys()],
            encryption_algorithms_client_to_server: [...encryption_algorithms.keys()],
            encryption_algorithms_server_to_client: [...encryption_algorithms.keys()],
            mac_algorithms_client_to_server: [...mac_algorithms.keys()],
            mac_algorithms_server_to_client: [...mac_algorithms.keys()],
            compression_algorithms_client_to_server: ["none"],
            compression_algorithms_server_to_client: ["none"],
            languages_client_to_server: [],
            languages_server_to_client: [],
            first_kex_packet_follows: false,
        })
        this.sendPacket(this.clientKexInit)

        const [serverKexInit, serverKexInitBuffer] = await this.waitEvent("serverKexInit")
        this.serverKexInit = serverKexInit
        this.debug("Server KexInit:", serverKexInit)
        this.chooseAlgorithms()

        if (this.kexAlgorithm instanceof DiffieHellmanGroupN) {
            this.debug(
                "Using DiffieHellmanGroupN key exchange algorithm",
                // @ts-expect-error alg_name is a static property
                this.kexAlgorithm.constructor.alg_name,
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

            const h = this.kexAlgorithm.computeHClient(
                this,

                serverKexInitBuffer,
            )

            assert(hostKey.verifySignature(h, signature), "Invalid host key signature from server!")

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
            new UserAuthRequest({
                username: this.options.username!,
                service_name: "ssh-userauth",
                method: new NoneAuthMethod(),
            }),
        )
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

    sendPacket(packet: Packet): void {
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

        let mac: Buffer
        if (this.hasReceivedNewKeys && this.hasSentNewKeys) {
            // we'll also encrypt here
            mac = this.clientMac!.computeMAC(this.out_sequence_number, packet_buf)
            packet_buf = this.clientEncryption!.encrypt(packet_buf)
        } else {
            mac = Buffer.allocUnsafe(0)
        }

        this.socket!.write(Buffer.concat([packet_buf, mac]))
        this.out_sequence_number++
        this.out_sequence_number %= SEQUENCE_NUMBER_MODULO
    }

    chooseAlgorithms() {
        assert(this.clientKexInit, "Client KexInit not set")
        assert(this.serverKexInit, "Server KexInit not set")
        this.debug("Choosing algorithms...")

        const server_host_key_algorithms: (typeof HostKeyAlgorithm)[] = []
        for (const alg of this.serverKexInit.data.server_host_key_algorithms) {
            const algorithm = host_key_algorithms.get(alg)
            if (!algorithm) continue

            server_host_key_algorithms.push(algorithm)
        }

        if (
            this.clientKexInit.data.kex_algorithms[0] == this.serverKexInit.data.kex_algorithms[0]
        ) {
            this.debug(
                "Key Exchange Algorithm guessed right:",
                this.clientKexInit.data.kex_algorithms[0],
            )

            const algorithm = kex_algorithms.get(this.clientKexInit.data.kex_algorithms[0])!
            assert(algorithm, "Invalid key exchange algorithm")
            this.kexAlgorithm = algorithm.instantiate()

            const host_key_algorithm = server_host_key_algorithms.find((alg) => {
                if (algorithm.requires_encryption && !alg.has_encryption) {
                    return false
                }
                if (algorithm.requires_signature && !alg.has_signature) {
                    return false
                }
                return true
            })
            assert(host_key_algorithm, "No compatible host key algorithm found")
            this.hostKeyAlgorithm = host_key_algorithm
        } else {
            for (const alg of this.clientKexInit.data.kex_algorithms) {
                if (!this.serverKexInit.data.kex_algorithms.includes(alg)) {
                    continue
                }
                const algorithm = kex_algorithms.get(alg)!
                // this is the client algorithms
                // we shouldn't have put an algorithm we don't support
                // assert is fine, it means we have a bug if it throws
                assert(algorithm, "Invalid key exchange algorithm")

                // need a compatible host key to provide encryption and signature if needed
                const host_key_algorithm = server_host_key_algorithms.find((alg) => {
                    if (algorithm.requires_encryption && !alg.has_encryption) {
                        return false
                    }
                    if (algorithm.requires_signature && !alg.has_signature) {
                        return false
                    }
                    return true
                })
                if (!host_key_algorithm) {
                    continue
                }

                this.kexAlgorithm = algorithm.instantiate()
                this.hostKeyAlgorithm = host_key_algorithm
                break
            }
            assert(this.kexAlgorithm, "No key exchange algorithm found")
            assert(this.hostKeyAlgorithm, "No host key algorithm found")
        }

        for (const alg of this.clientKexInit.data.encryption_algorithms_client_to_server) {
            if (!this.serverKexInit.data.encryption_algorithms_client_to_server.includes(alg)) {
                continue
            }

            const algorithm = encryption_algorithms.get(alg)!
            assert(algorithm, "Invalid encryption algorithm")

            this.clientEncryptionAlgorithm = algorithm
        }
        assert(this.clientEncryptionAlgorithm, "No client to server encryption algorithm found")
        for (const alg of this.clientKexInit.data.encryption_algorithms_server_to_client) {
            if (!this.serverKexInit.data.encryption_algorithms_server_to_client.includes(alg)) {
                continue
            }

            const algorithm = encryption_algorithms.get(alg)!
            assert(algorithm, "Invalid encryption algorithm")

            this.serverEncryptionAlgorithm = algorithm
        }
        assert(this.serverEncryptionAlgorithm, "No server to client encryption algorithm found")

        for (const alg of this.clientKexInit.data.mac_algorithms_client_to_server) {
            if (!this.serverKexInit.data.mac_algorithms_client_to_server.includes(alg)) {
                continue
            }

            const algorithm = mac_algorithms.get(alg)!
            assert(algorithm, "Invalid mac algorithm")

            this.clientMacAlgorithm = algorithm
        }
        assert(this.clientMacAlgorithm, "No client to server mac algorithm found")
        for (const alg of this.clientKexInit.data.mac_algorithms_server_to_client) {
            if (!this.serverKexInit.data.mac_algorithms_server_to_client.includes(alg)) {
                continue
            }

            const algorithm = mac_algorithms.get(alg)!
            assert(algorithm, "Invalid mac algorithm")

            this.serverMacAlgorithm = algorithm
        }
        assert(this.serverMacAlgorithm, "No server to client mac algorithm found")

        // TODO: Implement languages (?)
        // TODO: Implement compression

        this.debug("Key Exchange Algorithm chosen:", this.kexAlgorithm)
        this.debug("Host Key Algorithm chosen:", this.hostKeyAlgorithm)
        this.debug("Client to Server Encryption Algorithm chosen:", this.clientEncryptionAlgorithm)
        this.debug("Server to Client Encryption Algorithm chosen:", this.serverEncryptionAlgorithm)
        this.debug("Client to Server MAC Algorithm chosen:", this.clientMacAlgorithm)
        this.debug("Server to Client MAC Algorithm chosen:", this.serverMacAlgorithm)
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

            let packet_length: number
            let padding_length: number
            if (this.hasReceivedNewKeys && this.hasSentNewKeys) {
                const first16 = this.serverEncryption!.decrypt(message.subarray(0, 16))
                packet_length = first16.readUInt32BE(0)
                padding_length = first16[4]
            } else {
                packet_length = message.readUInt32BE(0)
                padding_length = message[4]
            }

            // TODO: Comply with 6.1. Maximum Packet Length
            // https://datatracker.ietf.org/doc/html/rfc4253#section-6.1
            if (message.length < packet_length + 4) {
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
                decrypted_message = this.serverEncryption!.decrypt(message.subarray(0, 5 + n1 + n2))
            }

            const payload = decrypted_message.subarray(5, 5 + n1)
            const padding = decrypted_message.subarray(5 + n1, 5 + n1 + n2)
            const macsize =
                this.hasReceivedNewKeys && this.hasSentNewKeys
                    ? this.serverMacAlgorithm!.digest_length
                    : 0
            const mac = decrypted_message.subarray(5 + n1 + n2, 5 + n1 + n2 + macsize)
            if (this.hasReceivedNewKeys && this.hasSentNewKeys) {
                // verify MAC
                const computed_mac = this.serverMac!.computeMAC(
                    this.in_sequence_number,
                    message.subarray(0, 5 + n1 + n2),
                )
                assert(computed_mac.length === mac.length, "Invalid MAC size")
                assert(timingSafeEqual(computed_mac, mac), "Invalid MAC")
            }

            this.buffering = message.subarray(5 + n1 + n2 + macsize)
            message = message.subarray(0, 5 + n1 + n2 + macsize)
            this.emit("message", message)
            this.debug("Message:", [message.toString("utf8")])

            this.debug("Packet:", SSHPacketType[payload[0]], {
                packet_length,
                padding_length,
                payload,
                padding,
                mac,
            })

            this.in_sequence_number++
            this.in_sequence_number %= SEQUENCE_NUMBER_MODULO

            const packet = packets.get(payload[0])
            if (!packet) {
                throw new Error("Invalid packet type (" + payload[0] + ")")
            }

            const p = packet.parse(payload)
            this.emit("packet", p)

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
            }

            if (this.buffering.length > 0) {
                this.onMessage(Buffer.alloc(0))
            }
        }
    }
}
