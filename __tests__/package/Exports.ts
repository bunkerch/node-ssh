import { execFile } from "node:child_process"
import { mkdir, mkdtemp, readFile, readdir, rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { promisify } from "node:util"
import {
    AllowedSigners,
    Agent,
    buildGSSAPIKeyExchangeUserAuthMIC,
    Channel,
    ChannelOpenError,
    ChannelOpenFailureReasonCodes,
    Client,
    ClientAgentChannel,
    ClientDirectStreamLocalChannel,
    ClientForwardedStreamLocalChannel,
    ClientForwardedTCPIPChannel,
    ClientTCPIPChannel,
    ClientX11Channel,
    createSocketAgent,
    CygwinAgent,
    CygwinAgentError,
    DirectTCPIPChannel,
    DirectStreamLocalChannel,
    DisconnectError,
    DisconnectReason,
    decodeSFTPLimits,
    DELAY_COMPRESSION_EXTENSION,
    delayCompressionExtension,
    DiskAgent,
    ELEVATION_EXTENSION,
    EncodedSignature,
    encodeSFTPPacket,
    flagsToString,
    ForwardedTCPIPChannel,
    ForwardedAgentChannel,
    ForwardedStreamLocalChannel,
    ForwardedX11Channel,
    generateKeyPair,
    generateKeyPairSync,
    GSSAPIError,
    GSSAPI_KEYEX,
    HTTPAgent,
    HTTPSAgent,
    KERBEROS_V5_GSSAPI_OID,
    KeyRevocationList,
    KnownHosts,
    MAX_OPENSSH_AGENT_SESSION_BINDINGS,
    MAX_OPENSSH_AGENT_SESSION_IDENTIFIER_LENGTH,
    MAX_SSH_AGENT_MESSAGE_LENGTH,
    NO_FLOW_CONTROL_EXTENSION,
    OnePasswordAgent,
    PageantAgent,
    OPENSSH_AGENT_ASSOCIATED_CERTIFICATES,
    OPENSSH_AGENT_RESTRICT_DESTINATION,
    OPENSSH_AGENT_SESSION_BIND,
    OPEN_MODE,
    parseKey,
    parseKeys,
    parseRFC4716PublicKeyFile,
    PrivateKey,
    PrivateKeyAgent,
    ProtocolVersionExchange,
    PublicKey,
    PublicKeyAlgorithm,
    PublicKeySubsystemClient,
    SecurityKeyAttestation,
    serializeRFC4716PublicKey,
    PublicKeySubsystemServer,
    PublicKeySubsystemStatusCode,
    Server,
    ServerClient,
    SessionChannel,
    Shell,
    SFTPPacketParser,
    SFTPPacketType,
    SFTPClient,
    SFTPReadStream,
    SFTPServer,
    SFTPStats,
    SFTPWriteStream,
    STATUS_CODE,
    stringToFlags,
    SSHAgent,
    SSHAgentConstraintType,
    SSHAgentExtensionFailureError,
    SSHAgentMessageType,
    SSHAgentProtocolClient,
    SSHAgentProtocolError,
    SSHAgentProtocolServer,
    SSHHTTPAgent,
    SSHHTTPSAgent,
    SSHSignature,
    SSHAuthenticationMethods,
    TerminalMode,
    TerminalModes,
    type AllowedSignerPrincipalLookupOptions,
    type ClientOptions,
    type AllowedSignerVerificationOptions,
    type ClientSessionOptions,
    type ClientHookerIncomingChannelController,
    type CygwinAgentOptions,
    type DelayCompressionOptions,
    type ElevationPreference,
    type GSSAPIKeyExchangeClientContextOptions,
    type NoFlowControlPreference,
    type OpenSSHAgentDestinationConstraint,
    type OpenSSHAgentSessionBinding,
    type SSHAgentProtocolOptions,
    type SSHAgentProtocolServerOptions,
    type SSHAgentConstraint,
    type SSHSignatureOptions,
    type SFTPServerOptions,
    type ServerConnectionInfo,
    type ServerOptions,
    type PublicKeySubsystemAddOptions,
    type PublicKeySubsystemServerOptions,
} from "../../src/index.js"

const execFileAsync = promisify(execFile)

describe("package exports", () => {
    test("exposes the supported source API without executing a demo", () => {
        const clientOptions: ClientOptions = { hostname: "example.test" }
        const sessionOptions: ClientSessionOptions = { env: { LANG: "C" }, pty: true }
        const serverOptions: ServerOptions = { sendAllHostKeys: false }
        const connectionInfo: ServerConnectionInfo = { remoteAddress: "127.0.0.1" }
        const incomingChannelDecision: ClientHookerIncomingChannelController = {
            allowOpen: false,
        }
        const noFlowControl: NoFlowControlPreference = "supported"
        const elevation: ElevationPreference = "unelevated"
        const delayCompression: DelayCompressionOptions = {
            clientToServer: ["zlib", "none"],
            serverToClient: ["none"],
        }
        clientOptions.noFlowControl = noFlowControl
        clientOptions.elevation = elevation
        clientOptions.delayCompression = delayCompression
        serverOptions.noFlowControl = noFlowControl
        serverOptions.bannerLanguageTag = "en-US"
        const keyExchangeOptions: GSSAPIKeyExchangeClientContextOptions = {
            hostname: "example.test",
            service: "host",
            delegateCredentials: false,
            anonymous: true,
            mutualAuthentication: true,
            integrity: true,
            replayDetection: false,
            sequenceDetection: false,
        }
        const agentProtocolOptions: SSHAgentProtocolOptions = {
            maxMessageLength: 1024,
            requestTimeout: 250,
        }
        const agentProtocolServerOptions: SSHAgentProtocolServerOptions = {
            maxMessageLength: 2048,
        }
        const agentConstraint: SSHAgentConstraint = { type: "confirm" }
        const destinationConstraint: OpenSSHAgentDestinationConstraint = {
            type: "openssh-restrict-destination",
            destinations: [],
        }
        const sessionBinding: OpenSSHAgentSessionBinding | undefined = undefined
        const cygwinAgentOptions: CygwinAgentOptions = {
            handshakeTimeout: 500,
            maxSocketFileLength: 512,
        }
        const publicKeyAddOptions: PublicKeySubsystemAddOptions = { overwrite: true }
        const publicKeyServerOptions: PublicKeySubsystemServerOptions = {
            attributes: [{ name: "comment" }],
        }
        const sftpServerOptions: SFTPServerOptions = { maxConcurrentRequests: 32 }
        const detachedSignatureOptions: SSHSignatureOptions = { namespace: "package" }
        const allowedSignerOptions: AllowedSignerVerificationOptions = {
            principal: "packed@example.test",
            namespace: "package",
        }
        const allowedSignerLookupOptions: AllowedSignerPrincipalLookupOptions = { at: 0n }

        expect(clientOptions.hostname).toBe("example.test")
        expect(sessionOptions.pty).toBe(true)
        expect(serverOptions.sendAllHostKeys).toBe(false)
        expect(serverOptions.bannerLanguageTag).toBe("en-US")
        expect(connectionInfo.remoteAddress).toBe("127.0.0.1")
        expect(incomingChannelDecision.allowOpen).toBe(false)
        expect(keyExchangeOptions.service).toBe("host")
        expect(agentProtocolOptions.requestTimeout).toBe(250)
        expect(agentProtocolServerOptions.maxMessageLength).toBe(2048)
        expect(agentConstraint.type).toBe("confirm")
        expect(destinationConstraint.type).toBe("openssh-restrict-destination")
        expect(sessionBinding).toBeUndefined()
        expect(cygwinAgentOptions.handshakeTimeout).toBe(500)
        expect(publicKeyAddOptions.overwrite).toBe(true)
        expect(publicKeyServerOptions.attributes?.[0]?.name).toBe("comment")
        expect(sftpServerOptions.maxConcurrentRequests).toBe(32)
        expect(detachedSignatureOptions.namespace).toBe("package")
        expect(allowedSignerOptions.principal).toBe("packed@example.test")
        expect(allowedSignerLookupOptions.at).toBe(0n)
        expect([
            AllowedSigners,
            Agent,
            Channel,
            ChannelOpenError,
            ChannelOpenFailureReasonCodes,
            Client,
            ClientAgentChannel,
            ClientDirectStreamLocalChannel,
            ClientForwardedStreamLocalChannel,
            ClientForwardedTCPIPChannel,
            ClientTCPIPChannel,
            ClientX11Channel,
            DirectTCPIPChannel,
            DirectStreamLocalChannel,
            DisconnectError,
            DisconnectReason,
            DiskAgent,
            EncodedSignature,
            ForwardedTCPIPChannel,
            ForwardedAgentChannel,
            ForwardedStreamLocalChannel,
            ForwardedX11Channel,
            generateKeyPair,
            generateKeyPairSync,
            GSSAPIError,
            HTTPAgent,
            HTTPSAgent,
            KERBEROS_V5_GSSAPI_OID,
            KeyRevocationList,
            KnownHosts,
            OnePasswordAgent,
            PageantAgent,
            parseKey,
            parseKeys,
            parseRFC4716PublicKeyFile,
            PrivateKey,
            PrivateKeyAgent,
            ProtocolVersionExchange,
            PublicKey,
            PublicKeyAlgorithm,
            SecurityKeyAttestation,
            serializeRFC4716PublicKey,
            Server,
            ServerClient,
            SessionChannel,
            Shell,
            SSHAgent,
            SSHHTTPAgent,
            SSHHTTPSAgent,
            SSHSignature,
        ]).toHaveLength(50)
        expect(
            new ChannelOpenError(
                ChannelOpenFailureReasonCodes.SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
                "policy denied",
                "en-US",
            ).languageTag,
        ).toBe("en-US")
        expect(
            new DisconnectError(
                DisconnectReason.SSH_DISCONNECT_BY_APPLICATION,
                "maintenance",
                "en-US",
            ).languageTag,
        ).toBe("en-US")
        expect(SSHAuthenticationMethods.PublicKey).toBe("publickey")
        expect(SSHAuthenticationMethods.KeyboardInteractive).toBe("keyboard-interactive")
        expect(SSHAuthenticationMethods.GSSAPIWithMIC).toBe("gssapi-with-mic")
        expect(SSHAuthenticationMethods.GSSAPIKeyExchange).toBe("gssapi-keyex")
        expect(GSSAPI_KEYEX).toBe("gssapi-keyex")
        expect(
            buildGSSAPIKeyExchangeUserAuthMIC(Buffer.from("session"), "user", "ssh-connection"),
        ).toBeInstanceOf(Buffer)
        expect(KERBEROS_V5_GSSAPI_OID.toString("hex")).toBe("06092a864886f712010202")
        expect(TerminalMode.ECHO).toBe(53)
        expect(TerminalModes).toBe(TerminalMode)
        expect(encodeSFTPPacket).toBeFunction()
        expect(decodeSFTPLimits).toBeFunction()
        expect(SFTPPacketParser).toBeFunction()
        expect(SFTPPacketType.Init).toBe(1)
        expect(SFTPClient).toBeFunction()
        expect(SFTPReadStream).toBeFunction()
        expect(SFTPServer).toBeFunction()
        expect(SFTPStats).toBeFunction()
        expect(SFTPWriteStream).toBeFunction()
        expect(stringToFlags("r")).toBe(OPEN_MODE.READ)
        expect(flagsToString(OPEN_MODE.READ)).toBe("r")
        expect(STATUS_CODE.OK).toBe(0)
        expect(SSHAgentProtocolClient).toBeFunction()
        expect(SSHAgentProtocolServer).toBeFunction()
        expect(SSHAgentProtocolError).toBeFunction()
        expect(SSHAgentExtensionFailureError).toBeFunction()
        expect(SSHAgentMessageType.SignRequest).toBe(13)
        expect(SSHAgentMessageType.ExtensionResponse).toBe(29)
        expect(SSHAgentConstraintType.Extension).toBe(255)
        expect(MAX_SSH_AGENT_MESSAGE_LENGTH).toBe(256 * 1024)
        expect(MAX_OPENSSH_AGENT_SESSION_BINDINGS).toBe(16)
        expect(MAX_OPENSSH_AGENT_SESSION_IDENTIFIER_LENGTH).toBe(128)
        expect(OPENSSH_AGENT_SESSION_BIND).toBe("session-bind@openssh.com")
        expect(OPENSSH_AGENT_RESTRICT_DESTINATION).toBe("restrict-destination-v00@openssh.com")
        expect(OPENSSH_AGENT_ASSOCIATED_CERTIFICATES).toBe("associated-certs-v00@openssh.com")
        expect(CygwinAgent).toBeFunction()
        expect(CygwinAgentError).toBeFunction()
        expect(createSocketAgent).toBeFunction()
        expect(NO_FLOW_CONTROL_EXTENSION).toBe("no-flow-control")
        expect(ELEVATION_EXTENSION).toBe("elevation")
        expect(DELAY_COMPRESSION_EXTENSION).toBe("delay-compression")
        expect(delayCompressionExtension(delayCompression).name).toBe("delay-compression")
        expect(PublicKeySubsystemClient).toBeFunction()
        expect(PublicKeySubsystemServer).toBeFunction()
        expect(PublicKeySubsystemStatusCode.Success).toBe(0)
    })

    test("compiled entry point provides the same side-effect-free API", async () => {
        const entry = await import("../../dist/index.js")

        expect(entry.AllowedSigners).toBeFunction()
        expect(entry.Client).toBeDefined()
        expect(entry.ClientAgentChannel).toBeDefined()
        expect(entry.ClientDirectStreamLocalChannel).toBeDefined()
        expect(entry.ClientForwardedStreamLocalChannel).toBeDefined()
        expect(entry.ClientForwardedTCPIPChannel).toBeDefined()
        expect(entry.ClientTCPIPChannel).toBeDefined()
        expect(entry.ClientX11Channel).toBeDefined()
        expect(entry.ChannelOpenError).toBeFunction()
        expect(entry.ChannelOpenFailureReasonCodes.SSH_OPEN_RESOURCE_SHORTAGE).toBe(4)
        expect(entry.SSHHTTPAgent).toBeDefined()
        expect(entry.SSHHTTPSAgent).toBeDefined()
        expect(entry.HTTPAgent).toBe(entry.SSHHTTPAgent)
        expect(entry.HTTPSAgent).toBe(entry.SSHHTTPSAgent)
        expect(entry.generateKeyPair).toBeFunction()
        expect(entry.generateKeyPairSync).toBeFunction()
        expect(entry.GSSAPIError).toBeFunction()
        expect(entry.GSSAPI_KEYEX).toBe("gssapi-keyex")
        expect(entry.buildGSSAPIKeyExchangeUserAuthMIC).toBeFunction()
        expect(entry.KERBEROS_V5_GSSAPI_OID).toBeInstanceOf(Buffer)
        expect(entry.PublicKeySubsystemClient).toBeFunction()
        expect(entry.PublicKeySubsystemServer).toBeFunction()
        expect(entry.PublicKeySubsystemStatusCode.Success).toBe(0)
        expect(entry.KeyRevocationList).toBeFunction()
        expect(entry.SecurityKeyAttestation).toBeFunction()
        expect(entry.SSHSignature).toBeFunction()
        expect(entry.KnownHosts).toBeFunction()
        expect(entry.parseKeys).toBeFunction()
        expect(entry.parseRFC4716PublicKeyFile).toBeFunction()
        expect(entry.serializeRFC4716PublicKey).toBeFunction()
        expect(entry.DirectTCPIPChannel).toBeDefined()
        expect(entry.DirectStreamLocalChannel).toBeDefined()
        expect(entry.DisconnectError).toBeFunction()
        expect(entry.DisconnectReason.SSH_DISCONNECT_BY_APPLICATION).toBe(11)
        expect(entry.ForwardedTCPIPChannel).toBeDefined()
        expect(entry.ForwardedAgentChannel).toBeDefined()
        expect(entry.ForwardedStreamLocalChannel).toBeDefined()
        expect(entry.ForwardedX11Channel).toBeDefined()
        expect(entry.Server).toBeDefined()
        expect(entry.PrivateKey).toBeDefined()
        expect(entry.PublicKeyAlgorithm).toBeDefined()
        expect("PublicKeyAlgoritm" in entry).toBe(false)
        expect(entry.ProtocolVersionExchange).toBeDefined()
        expect(entry.SSHAgent).toBeDefined()
        expect(entry.OnePasswordAgent).toBeDefined()
        expect(entry.PageantAgent).toBeDefined()
        expect(entry.SFTPPacketParser).toBeDefined()
        expect(entry.SFTPPacketType.Status).toBe(101)
        expect(entry.SFTPClient).toBeDefined()
        expect(entry.SFTPReadStream).toBeDefined()
        expect(entry.SFTPServer).toBeDefined()
        expect(entry.SFTPStats).toBeDefined()
        expect(entry.SFTPWriteStream).toBeDefined()
        expect(entry.OPEN_MODE.READ).toBe(1)
        expect(entry.STATUS_CODE.OK).toBe(0)
        expect(entry.decodeSFTPLimits).toBeDefined()
        expect(entry.TerminalMode.TTY_OP_OSPEED).toBe(129)
        expect(entry.TerminalModes).toBe(entry.TerminalMode)
        expect(entry.SSHAgentProtocolClient).toBeFunction()
        expect(entry.SSHAgentProtocolServer).toBeFunction()
        expect(entry.SSHAgentProtocolError).toBeFunction()
        expect(entry.SSHAgentMessageType.IdentitiesAnswer).toBe(12)
        expect(entry.MAX_SSH_AGENT_MESSAGE_LENGTH).toBe(256 * 1024)
        expect(entry.OPENSSH_AGENT_SESSION_BIND).toBe("session-bind@openssh.com")
        expect(entry.CygwinAgent).toBeFunction()
        expect(entry.CygwinAgentError).toBeFunction()
        expect(entry.createSocketAgent).toBeFunction()
        expect(entry.NO_FLOW_CONTROL_EXTENSION).toBe("no-flow-control")
        expect(entry.ELEVATION_EXTENSION).toBe("elevation")
        expect(entry.DELAY_COMPRESSION_EXTENSION).toBe("delay-compression")
        expect(entry.delayCompressionExtension).toBeFunction()
        expect("waitEvent" in Client.prototype).toBe(false)
        expect("waitForPacket" in Client.prototype).toBe(false)
        expect("waitForPackets" in Client.prototype).toBe(false)
        expect("waitEvent" in ServerClient.prototype).toBe(false)
    })

    test("compiled declarations expose Promise-only completion APIs", async () => {
        const client = await readFile("dist/Client.d.ts", "utf8")
        const clientChannel = await readFile("dist/channels/ClientChannel.d.ts", "utf8")
        const clientSession = await readFile("dist/channels/ClientSessionChannel.d.ts", "utf8")
        const channel = await readFile("dist/Channel.d.ts", "utf8")
        const serverClient = await readFile("dist/ServerClient.d.ts", "utf8")
        const server = await readFile("dist/Server.d.ts", "utf8")
        const streams = await readFile("dist/sftp/streams.d.ts", "utf8")
        const sftpClient = await readFile("dist/sftp/SFTPClient.d.ts", "utf8")
        const shell = await readFile("dist/channels/Session/Shell.d.ts", "utf8")
        const privateKey = await readFile("dist/utils/PrivateKey.d.ts", "utf8")
        const publicKey = await readFile("dist/utils/PublicKey.d.ts", "utf8")
        const index = await readFile("dist/index.d.ts", "utf8")
        const knownHosts = await readFile("dist/KnownHosts.d.ts", "utf8")
        const keyRevocationList = await readFile("dist/KeyRevocationList.d.ts", "utf8")
        const securityKeyAttestation = await readFile("dist/SecurityKeyAttestation.d.ts", "utf8")
        const sshSignature = await readFile("dist/SSHSignature.d.ts", "utf8")
        const allowedSigners = await readFile("dist/AllowedSigners.d.ts", "utf8")
        const agentProtocol = await readFile("dist/publickey/SSHAgentProtocol.d.ts", "utf8")
        const cygwinAgent = await readFile("dist/publickey/CygwinAgent.d.ts", "utf8")
        const pageantAgent = await readFile("dist/publickey/PageantAgent.d.ts", "utf8")
        const sftpServer = await readFile("dist/sftp/SFTPServer.d.ts", "utf8")
        const publicKeySubsystemClient = await readFile(
            "dist/publickey/PublicKeySubsystemClient.d.ts",
            "utf8",
        )
        const channelOpenFailure = await readFile("dist/packets/ChannelOpenFailure.d.ts", "utf8")

        expect(client).not.toContain("ClientSessionCallback")
        expect(client).not.toContain("ClientGlobalRequestCallback")
        expect(client).not.toContain("message: [message: Buffer]")
        expect(client).not.toContain("packet: [packet: Packet]")
        expect(client).toContain("packet: [metadata: Readonly<ProtocolPacketMetadata>]")
        expect(client).not.toContain("waitForPacket")
        expect(client).not.toContain("waitEvent<")
        expect(serverClient).not.toContain("message: [message: Buffer]")
        expect(serverClient).not.toContain("packet: [packet: Packet]")
        expect(serverClient).toContain("packet: [metadata: Readonly<ProtocolPacketMetadata>]")
        expect(serverClient).not.toContain("waitEvent<")
        expect(serverClient).not.toContain("channelOpenRequest: [packet: ChannelOpen]")
        expect(serverClient).not.toContain("channelRequest: [packet: ChannelRequest]")
        expect(serverClient).not.toContain("channelData: [packet: ChannelData]")
        expect(index).toContain("export type { ProtocolPacketMetadata }")
        expect(client).not.toContain("options: ClientOptionsRequired")
        expect(server).not.toContain("options: ServerOptionsRequired")
        expect(client).toContain("globalRequest(name: string, args?: Buffer): Promise<Buffer>")
        expect(client).toContain("tcpConnection: [")
        expect(client).toContain("channel: ClientForwardedTCPIPChannel")
        expect(client).not.toContain("accept: () => ClientForwardedTCPIPChannel")
        expect(client).toContain("streamLocalConnection: [")
        expect(client).toContain("channel: ClientForwardedStreamLocalChannel")
        expect(client).not.toContain("accept: () => ClientForwardedStreamLocalChannel")
        expect(client).toContain("x11Connection: [")
        expect(client).toContain("channel: ClientX11Channel")
        expect(client).not.toContain("accept: () => ClientX11Channel")
        expect(client).toContain("disconnect(error?: DisconnectError): this")
        expect(client).toContain("authenticationMethodsOrder?: readonly SSHAuthenticationMethods[]")
        expect(client).toContain("replyTimeout?: number")
        expect(client).toContain("maxPendingChannelOpens?: number")
        expect(client).toContain("maxChannels?: number")
        expect(client).toContain("options?: SFTPClientOptions")
        expect(client).toContain("publicKeySubsystem(options?: PublicKeySubsystemClientOptions)")
        expect(client).toContain("hostbased?: Readonly<ClientHostbasedOptions>")
        expect(client).toContain("get elevated(): boolean | undefined")
        expect(client).toContain("delayCompression?: DelayCompressionConfiguration")
        expect(client).toContain("exec(command: string, options?: ClientSessionOptions)")
        expect(client).toContain("get exchangeHash(): Buffer | undefined")
        expect(serverClient).toContain("get exchangeHash(): Buffer | undefined")
        expect(serverClient).toContain("get username(): string | undefined")
        expect(serverClient).toContain("get authenticationMethod(): string | undefined")
        expect(serverClient).not.toContain("credentials: UserAuthRequest")
        expect(client).toContain("get keyExchangeAlgorithm(): string | undefined")
        expect(serverClient).toContain("get keyExchangeAlgorithm(): string | undefined")
        expect(client).toContain(
            "get negotiatedAlgorithms(): Readonly<NegotiatedAlgorithms> | undefined",
        )
        expect(serverClient).toContain(
            "get negotiatedAlgorithms(): Readonly<NegotiatedAlgorithms> | undefined",
        )
        expect(client).not.toContain("clientKexInit?: KexInit")
        expect(client).not.toContain("serverKexInit?: KexInit")
        expect(serverClient).not.toContain("clientKexInit?: KexInit")
        expect(serverClient).not.toContain("serverKexInit?: KexInit")
        expect(client).not.toContain("kexAlgorithms")
        expect(server).not.toContain("kexAlgorithms")
        for (const transcriptState of [
            "clientKexInitPayload",
            "serverKexInitPayload",
            "serverKexDHReply?: KexDHReply",
            "clientKexDHInit?: KexDHInit",
        ]) {
            expect(client).not.toContain(transcriptState)
            expect(serverClient).not.toContain(transcriptState)
        }
        for (const exposedState of [
            "kexAlgorithm?: KexAlgorithm",
            "hostKeyAlgorithm?: HostKeyAlgorithm",
            "clientEncryptionAlgorithm?: typeof EncryptionAlgorithm",
            "serverEncryptionAlgorithm?: typeof EncryptionAlgorithm",
            "clientMacAlgorithm?: typeof MACAlgorithm",
            "serverMacAlgorithm?: typeof MACAlgorithm",
            "clientCompressionAlgorithm?: CompressionAlgorithm",
            "serverCompressionAlgorithm?: CompressionAlgorithm",
            "clientEncryption?: EncryptionAlgorithm",
            "serverEncryption?: EncryptionAlgorithm",
            "clientMac?: MACAlgorithm",
            "serverMac?: MACAlgorithm",
        ]) {
            expect(client).not.toContain(exposedState)
            expect(serverClient).not.toContain(exposedState)
        }
        for (const secret of [
            "ivClientToServer",
            "ivServerToClient",
            "encryptionKeyClientToServer",
            "encryptionKeyServerToClient",
            "integrityKeyClientToServer",
            "integrityKeyServerToClient",
        ]) {
            expect(client).not.toContain(secret)
            expect(serverClient).not.toContain(secret)
        }
        expect(clientChannel).toContain("sendData(data: Buffer | string")
        expect(clientSession).toContain("forwardAgent(): Promise<void>")
        expect(channel).toContain("sendData(data: Buffer): Promise<void>")
        expect(channel).toContain("sendExtendedData(dataType: number, data: Buffer): Promise<void>")
        expect(serverClient).not.toContain("ServerGlobalRequestCallback")
        expect(serverClient).toContain("rekey(): Promise<void>")
        expect(serverClient).toContain("disconnect(error?: DisconnectError): this")
        expect(serverClient).toContain("forwardAgent(): Promise<ForwardedAgentChannel>")
        expect(serverClient).toContain(
            "sendAuthenticationExtensions(extensions: readonly SSHExtension[]): this",
        )
        expect(serverClient).toContain("get clientSupportsAuthenticationExtensionInfo(): boolean")
        expect(serverClient).toContain(
            "get clientElevationPreference(): ElevationRequest | undefined",
        )
        expect(server).toContain("getConnections(): Promise<number>")
        expect(server).toContain("get maxConnections(): number")
        expect(server).toContain("set maxConnections(value: number)")
        expect(server).toContain("get listening(): boolean")
        expect(server).toContain("get connections(): number")
        expect(server).toContain("drop: [info: Readonly<ServerConnectionInfo>]")
        expect(server).toContain("[Symbol.asyncDispose](): Promise<void>")
        expect(server).toContain("delayCompression?: DelayCompressionConfiguration")
        expect(server).toContain("bannerLanguageTag?: string")
        expect(server).toContain("rejection?: ChannelOpenError")
        expect(server).toContain("replyTimeout?: number")
        expect(server).toContain("maxPendingChannelOpens?: number")
        expect(server).toContain("maxChannels?: number")
        expect(server).toContain("injectSocket(socket: ServerTransport): this")
        expect(server).toContain("export interface ServerTransport extends Duplex")
        expect(server).toContain("close(): Promise<void>")
        expect(agentProtocol).toContain("addIdentity(")
        expect(agentProtocol).toContain("removeAllIdentities(): Promise<void>")
        expect(agentProtocol).toContain("queryExtensions(): Promise<readonly string[]>")
        expect(agentProtocol).toContain("opensshSessionBind(")
        expect(agentProtocol).not.toContain("callback")
        expect(streams.match(/close\(\): Promise<void>/gu)).toHaveLength(2)
        expect(sftpClient).toContain("export interface SFTPClientOptions")
        expect(sftpClient).toContain("requestTimeout?: number")
        expect(sftpClient).toContain("readonly requestTimeout: number")
        expect(sftpServer).toContain(
            "status(requestId: number, code: SFTPStatusCode, message?: string, languageTag?: string): Promise<void>",
        )
        for (const response of ["handle", "data", "name", "attributes", "extendedReply"]) {
            expect(sftpServer).toMatch(new RegExp(`${response}\\([^;]+\\): Promise<void>`))
        }
        expect(sftpServer).not.toContain("callback")
        expect(shell).toContain("writeStdout(data: Buffer | string")
        expect(shell).toContain("writeStderr(data: Buffer | string")
        expect(privateKey).toContain(
            "fromPuTTY(data: string | Buffer, passphrase?: string | Buffer): PrivateKey",
        )
        expect(publicKey).toContain("export declare abstract class PublicKeyAlgorithm")
        expect(publicKey).not.toContain("PublicKeyAlgoritm")
        expect(index).not.toContain("PublicKeyAlgoritm")
        expect(knownHosts).toContain("static load(path: string): Promise<KnownHosts>")
        expect(knownHosts).toContain("replaceHostKeys(")
        expect(knownHosts).toContain("): Promise<void>")
        expect(keyRevocationList).toContain("static load(path: string): Promise<KeyRevocationList>")
        expect(keyRevocationList).toContain("isRevoked(key: PublicKey | Buffer): boolean")
        expect(keyRevocationList).toContain("isSignedBy(key: PublicKey | Buffer): boolean")
        expect(securityKeyAttestation).toContain(
            "static load(path: string): Promise<SecurityKeyAttestation>",
        )
        expect(sshSignature).toContain("static sign(")
        expect(sshSignature).toContain("static signWithAgent<Id>(")
        expect(sshSignature).toContain("): Promise<SSHSignature>")
        expect(sshSignature).toContain(
            "verify(message: Buffer, expectedNamespace: string | Buffer)",
        )
        expect(sshSignature).not.toContain("callback")
        expect(allowedSigners).toContain("static load(path: string): Promise<AllowedSigners>")
        expect(allowedSigners).toContain("matchPrincipals(principal: string): readonly string[]")
        expect(allowedSigners).toContain("findPrincipals(")
        expect(allowedSigners).toContain("verify(")
        expect(allowedSigners).not.toContain("callback")
        expect(securityKeyAttestation).toContain("get authenticatorData(): Buffer | undefined")
        expect(agentProtocol).toContain("getPublicKeys(): Promise<[string, PublicKey][]>")
        expect(agentProtocol).toContain("serve(stream: Duplex): Promise<void>")
        expect(agentProtocol).not.toContain("callback")
        expect(cygwinAgent).toContain("getStream(): Promise<Socket>")
        expect(cygwinAgent).not.toContain("callback")
        expect(pageantAgent).toContain("constructor(socketPath?: string)")
        expect(pageantAgent).not.toContain("callback")
        expect(publicKeySubsystemClient).toContain("add(key: PublicKey")
        expect(publicKeySubsystemClient).toContain("remove(key: PublicKey): Promise<void>")
        expect(publicKeySubsystemClient).toContain("list(): Promise<")
        expect(publicKeySubsystemClient).toContain(
            "export interface PublicKeySubsystemClientOptions",
        )
        expect(publicKeySubsystemClient).toContain("requestTimeout?: number")
        expect(publicKeySubsystemClient).toContain("readonly requestTimeout: number")
        expect(publicKeySubsystemClient).toContain("listAttributes(): Promise<")
        expect(publicKeySubsystemClient).toContain("end(): void")
        expect(publicKeySubsystemClient).not.toContain("callback")
        expect(channelOpenFailure).toContain(
            "constructor(reasonCode: number, message: string, languageTag?: string)",
        )
        expect(channelOpenFailure).toContain("readonly reasonCode: number")
        expect(channelOpenFailure).toContain("readonly languageTag: string")
    })

    test("package archive exposes a working ESM API", async () => {
        const directory = await mkdtemp(join(tmpdir(), "modernssh-package-"))
        try {
            await execFileAsync("pnpm", ["pack", "--pack-destination", directory])
            const archive = (await readdir(directory)).find((name) => name.endsWith(".tgz"))
            expect(archive).toBeDefined()
            const consumer = join(directory, "consumer")
            await mkdir(consumer)
            await execFileAsync("pnpm", [
                "add",
                "--ignore-scripts",
                "--dir",
                consumer,
                join(directory, archive!),
            ])
            const { stdout, stderr } = await execFileAsync(
                "node",
                [
                    "--input-type=module",
                    "--eval",
                    `
                    const { once } = await import("node:events")
                    const { mkdtemp, rm } = await import("node:fs/promises")
                    const { tmpdir } = await import("node:os")
                    const { join } = await import("node:path")
                    const { AllowedSigners, ChannelOpenError, ChannelOpenFailureReasonCodes, Client, ClientForwardedStreamLocalChannel, ClientForwardedTCPIPChannel, ClientX11Channel, createSocketAgent, CygwinAgent, CygwinAgentError, DELAY_COMPRESSION_EXTENSION, delayCompressionExtension, discoverPageantAgentSocket, DisconnectError, DisconnectReason, ELEVATION_EXTENSION, EncodedSignature, generateKeyPair, generateKeyPairSync, KeyRevocationList, KnownHosts, MAX_OPENSSH_AGENT_SESSION_BINDINGS, MAX_SSH_AGENT_MESSAGE_LENGTH, NO_FLOW_CONTROL_EXTENSION, OnePasswordAgent, OPENSSH_AGENT_SECURITY_KEY_PROVIDER, OPENSSH_AGENT_SESSION_BIND, PageantAgent, PageantAgentError, parseKey, parseRFC4716PublicKeyFile, PrivateKey, PrivateKeyAgent, PublicKey, PublicKeySubsystemClient, PublicKeySubsystemServer, PublicKeySubsystemStatusCode, SecurityKeyAttestation, serializeRFC4716PublicKey, Server, SessionChannel, SSH_ED25519_SECURITY_KEY_ALGORITHM, SSHAgentConstraintType, SSHAgentExtensionFailureError, SSHAgentMessageType, SSHAgentProtocolClient, SSHAgentProtocolError, SSHAgentProtocolServer, SSHED25519SecurityKeyPrivateKey, SSHED25519SecurityKeyPublicKey, SSHSignature } = await import("@bunkerch/modernssh")
                    const { privateKey, publicKey } = await generateKeyPair("ed25519", {
                        comment: "packed@example.test",
                    })
                    const message = Buffer.from("packed-key-generation")
                    if (!publicKey.verifySignature(message, privateKey.sign(message))) process.exit(2)
                    const detached = SSHSignature.sign(message, privateKey, { namespace: "package" })
                    if (!SSHSignature.parse(detached.toString()).verify(message, "package")) process.exit(49)
                    const allowed = AllowedSigners.parse("packed@example.test " + publicKey.toString() + "\\n")
                    if (allowed.matchPrincipals("packed@example.test")[0] !== "packed@example.test") process.exit(54)
                    if (allowed.findPrincipals(detached)[0] !== "packed@example.test") process.exit(55)
                    if (!allowed.verify(message, detached, { principal: "packed@example.test", namespace: "package" })) process.exit(53)
                    const encrypted = privateKey.toString({ passphrase: "packed-secret", rounds: 1 })
                    const parsed = PrivateKey.fromString(encrypted, "packed-secret")
                    if (!parsed.data.publicKey.equals(publicKey)) process.exit(3)
                    if (!parseKey(publicKey.toString()).equals(publicKey)) process.exit(4)
                    const configured = new Client({ privateKey: encrypted, passphrase: "packed-secret" })
                    if ("options" in configured) process.exit(5)
                    const emptyPasswordClient = new Client({ password: "" })
                    const emptyPasswordDecision = { password: undefined }
                    if (!await emptyPasswordClient.hooker.triggerHookChecked("passwordAuth", { username: "root" }, emptyPasswordDecision) || emptyPasswordDecision.password !== "") process.exit(61)
                    try { new Client({ agentForward: "false" }); process.exit(62) } catch (error) { if (!String(error).includes("agentForward option must be a boolean")) process.exit(63) }
                    try { new Client({ hostVerifier: true }); process.exit(64) } catch (error) { if (!String(error).includes("hostVerifier option must be a function")) process.exit(65) }
                    const invalidSession = new Client({}).exec("true", { agentForward: "false" })
                    if (!(invalidSession instanceof Promise)) process.exit(66)
                    try { await invalidSession; process.exit(67) } catch (error) { if (!String(error).includes("session agentForward option must be a boolean")) process.exit(68) }
                    const invalidForward = new Client({}).forwardOut("source.example", 0, "target.example", -1)
                    if (!(invalidForward instanceof Promise)) process.exit(69)
                    try { await invalidForward; process.exit(70) } catch (error) { if (!String(error).includes("destination port must be between 0 and 65535")) process.exit(71) }
                    try { new Server({ hostKeys: null }); process.exit(72) } catch (error) { if (!String(error).includes("hostKeys option must be an array")) process.exit(73) }
                    try { new Client({ port: 0 }); process.exit(57) } catch (error) { if (!String(error).includes("between 1 and 65535")) process.exit(58) }
                    try { new Server({ greeting: "invalid\\ud800greeting" }); process.exit(59) } catch (error) { if (!String(error).includes("not valid UTF-8 text")) process.exit(60) }
                    const legacy = generateKeyPairSync("dsa")
                    const legacySignature = legacy.privateKey.sign(message)
                    if (!legacy.publicKey.verifySignature(message, legacySignature)) process.exit(6)
                    if (new Client({}).algorithmOffer.serverHostKey.includes("ssh-dss")) process.exit(7)
                    const explicitLegacy = new Client({ algorithms: { serverHostKey: ["ssh-dss"] } })
                    if (explicitLegacy.algorithmOffer.serverHostKey[0] !== "ssh-dss") process.exit(8)
                    const synchronous = generateKeyPairSync("ecdsa", { bits: 256 })
                    if (!synchronous.publicKey.verifySignature(message, synchronous.privateKey.sign(message))) process.exit(9)
                    const rfc4716 = "---- BEGIN SSH" + "2 PUBLIC KEY ----\\n" + publicKey.serialize().toString("base64") + "\\n---- END SSH" + "2 PUBLIC KEY ----\\n"
                    if (!parseKey(rfc4716).equals(publicKey)) process.exit(10)
                    const serializedRFC4716 = serializeRFC4716PublicKey(publicKey, [{ tag: "x-packed", value: "preserve-me" }])
                    const parsedRFC4716 = parseRFC4716PublicKeyFile(serializedRFC4716)
                    if (!parsedRFC4716.publicKey.equals(publicKey) || parsedRFC4716.headers[0]?.value !== "preserve-me") process.exit(53)
                    const ppk = Buffer.from("UHVUVFktVXNlci1LZXktRmlsZS0zOiBzc2gtZWQyNTUxOQpFbmNyeXB0aW9uOiBub25lCkNvbW1lbnQ6IFJGQyA4MDMyIHRlc3QgdmVjdG9yIDEKUHVibGljLUxpbmVzOiAyCkFBQUFDM056YUMxbFpESTFOVEU1QUFBQUlOZGFtQUdDc1FxMzFVdiswOGxrQnpvTzRYTHoycVlqSmE4Q0dtajMKQjFFYQpQcml2YXRlLUxpbmVzOiAxCkFBQUFJSjFoc1ozdi9WcGd1b1JLOUpMc0xNUkVTY1ZwZXpKcEdYQTdyQU1jcm45ZwpQcml2YXRlLU1BQzogOWUxNzE1ZjEwNzM2ZWY1NTdiMDI0OWJkNjAxOWVjYTgyOTBhNjQ4ZDk3YjFmZjc1MmVlNmJlMDhkMDNiNzcxOQo=", "base64")
                    const importedPPK = parseKey(ppk)
                    if (!(importedPPK instanceof PrivateKey)) process.exit(11)
                    if (importedPPK.data.comment !== "RFC 8032 test vector 1") process.exit(12)
                    if (!importedPPK.data.publicKey.verifySignature(Buffer.alloc(0), importedPPK.sign(Buffer.alloc(0)))) process.exit(13)
                    const curve448Client = new Client({ algorithms: { kex: ["curve448-sha512"] } })
                    if (curve448Client.algorithmOffer.kex[0] !== "curve448-sha512") process.exit(14)
                    const knownHosts = KnownHosts.parse("packed.example.test " + publicKey.toString())
                    if (knownHosts.check("packed.example.test", publicKey).status !== "trusted") process.exit(15)
                    const packedKRL = KeyRevocationList.parse(Buffer.from("5353484b524c0a0000000001000000000000000000000000000000000000000000000000000000000000000d6669786564205348412d3235360500000024000000206db5e9b8a1bace1cdd9a7c6adb9e9396acc5073465d9fe8e3a0ef6d9c60d6d4f", "hex"))
                    const packedRevokedKey = PublicKey.parseString("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINdamAGCsQq31Uv+08lkBzoO4XLz2qYjJa8CGmj3B1Ea")
                    if (!packedKRL.isRevoked(packedRevokedKey)) process.exit(39)
                    if (packedKRL.isSignedBy(packedRevokedKey)) process.exit(40)
                    const packedAttestation = SecurityKeyAttestation.parse(Buffer.from("000000117373682d736b2d6174746573742d76303000000004cafebabe00000004112233440000000000000000", "hex"))
                    if (packedAttestation.format !== "ssh-sk-attest-v00" || !packedAttestation.serialize().equals(Buffer.from("000000117373682d736b2d6174746573742d76303000000004cafebabe00000004112233440000000000000000", "hex"))) process.exit(41)
                    if (new Client({}).algorithmOffer.kex[0] !== "mlkem768x25519-sha256") process.exit(16)
                    if (typeof SSHAgentProtocolClient !== "function" || typeof SSHAgentProtocolServer !== "function" || typeof SSHAgentProtocolError !== "function") process.exit(17)
                    if (SSHAgentMessageType.SignResponse !== 14 || MAX_SSH_AGENT_MESSAGE_LENGTH !== 262144) process.exit(18)
                    if (typeof CygwinAgent !== "function" || typeof CygwinAgentError !== "function" || typeof createSocketAgent !== "function") process.exit(19)
                    if (SSHAgentMessageType.ExtensionResponse !== 29 || SSHAgentConstraintType.Extension !== 255 || typeof SSHAgentExtensionFailureError !== "function") process.exit(21)
                    if (OPENSSH_AGENT_SESSION_BIND !== "session-bind@openssh.com" || MAX_OPENSSH_AGENT_SESSION_BINDINGS !== 16) process.exit(22)
                    const securityKey = PublicKey.parse(Buffer.from("0000001a736b2d7373682d65643235353139406f70656e7373682e636f6d00000020d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a000000087373683a74657374", "hex"))
                    const securityKeySignature = EncodedSignature.parse(Buffer.from("0000001a736b2d7373682d65643235353139406f70656e7373682e636f6d00000040f2330a0e0f6b9da42b530f7e14a4bb4db0832754452a0bdb90c002f6c922508ead849b2fb57a5552fcd92d407616d7347dafb9335e1e46a806f01de7bcd2d10f010000002a", "hex"))
                    if (!(securityKey.data.algorithm instanceof SSHED25519SecurityKeyPublicKey)) process.exit(23)
                    if (SSH_ED25519_SECURITY_KEY_ALGORITHM !== "sk-ssh-ed25519@openssh.com") process.exit(24)
                    if (!securityKey.verifySignature(Buffer.from("security-key-message"), securityKeySignature)) process.exit(25)
                    if (!parseKey(Buffer.from(securityKey.toString())).equals(securityKey)) process.exit(56)
                    const securityPrivateKey = new SSHED25519SecurityKeyPrivateKey({ publicKey: securityKey.data.algorithm.data.publicKey, application: "ssh:test", flags: 1, keyHandle: Buffer.from([1]), reserved: Buffer.alloc(0) })
                    if (!securityPrivateKey.getPublicKey().equals(securityKey)) process.exit(26)
                    if (OPENSSH_AGENT_SECURITY_KEY_PROVIDER !== "sk-provider@openssh.com") process.exit(27)
                    try { securityPrivateKey.sign(message); process.exit(28) } catch (error) { if (!String(error).includes("requires an SSH agent")) process.exit(29) }
                    const originalPlatform = process.platform
                    Object.defineProperty(process, "platform", { configurable: true, value: "win32" })
                    const selectedAgent = createSocketAgent("C:/cygwin/tmp/agent.socket")
                    const selectedClient = new Client({ agent: "C:/cygwin/tmp/agent.socket" })
                    const onePasswordAgent = new OnePasswordAgent()
                    Object.defineProperty(process, "platform", { configurable: true, value: originalPlatform })
                    if (!(selectedAgent instanceof CygwinAgent) || "options" in selectedClient) process.exit(20)
                    if (onePasswordAgent.socketPath !== ${JSON.stringify(String.raw`\\.\pipe\openssh-ssh-agent`)}) process.exit(30)
                    if (NO_FLOW_CONTROL_EXTENSION !== "no-flow-control") process.exit(31)
                    if (ELEVATION_EXTENSION !== "elevation") process.exit(32)
                    if (DELAY_COMPRESSION_EXTENSION !== "delay-compression") process.exit(33)
                    if (delayCompressionExtension({ clientToServer: ["none"], serverToClient: ["none"] }).name !== "delay-compression") process.exit(34)
                    if (typeof PageantAgent !== "function" || typeof PageantAgentError !== "function" || typeof discoverPageantAgentSocket !== "function") process.exit(35)
                    const explicitPageant = new PageantAgent("explicit-pageant.sock")
                    if (explicitPageant.socketPath !== "explicit-pageant.sock") process.exit(36)
                    const standaloneMLKEM = new Client({ algorithms: { kex: ["mlkem512-sha256", "mlkem768-sha256", "mlkem1024-sha384"] } })
                    if (standaloneMLKEM.algorithmOffer.kex.join(",") !== "mlkem512-sha256,mlkem768-sha256,mlkem1024-sha384") process.exit(37)
                    if (typeof PublicKeySubsystemClient !== "function" || typeof PublicKeySubsystemServer !== "function" || PublicKeySubsystemStatusCode.Success !== 0) process.exit(38)
                    let rejectRuntime
                    const runtimeFailure = new Promise((_, reject) => { rejectRuntime = reject })
                    let resolveRuntimeDisconnect
                    const runtimeDisconnect = new Promise((resolve) => { resolveRuntimeDisconnect = resolve })
                    const runtimeServer = new Server({ hostKeys: [privateKey], sendAllHostKeys: false, banner: "packed-banner", bannerLanguageTag: "en-US" })
                    runtimeServer.on("error", rejectRuntime)
                    runtimeServer.hooker.hook("noneAuthentication", (_hook, _context, decision) => { decision.allowLogin = true })
                    runtimeServer.hooker.hook("channelOpenRequest", (_hook, channel, decision) => { decision.allowOpen = channel instanceof SessionChannel })
                    runtimeServer.hooker.hook("tcpipForward", (_hook, context, decision) => { decision.allow = context.bindAddress === "127.0.0.1" })
                    runtimeServer.hooker.hook("streamLocalForward", (_hook, _context, decision) => { decision.allow = true })
                    let runtimeConnection
                    runtimeServer.on("connection", (connection) => {
                        runtimeConnection = connection
                        connection.on("error", rejectRuntime)
                        connection.once("disconnect", resolveRuntimeDisconnect)
                        connection.on("channel", (channel) => {
                        if (!(channel instanceof SessionChannel)) return
                        channel.hooker.hook("execRequest", (_hook, context, decision) => { decision.success = context.command === "packed-node-runtime" })
                        channel.hooker.hook("x11Request", (_hook, _context, decision) => { decision.success = true })
                            channel.events.on("exec", (_command, shell) => {
                                void (async () => {
                                    await shell.writeStdout("node-stdout")
                                    await shell.writeStderr("node-stderr")
                                    shell.exit(7).close()
                                })().catch(rejectRuntime)
                            })
                        })
                    })
                    runtimeServer.listen({ host: "127.0.0.1", port: 0 })
                    await Promise.race([once(runtimeServer, "listening"), runtimeFailure])
                    const runtimeAddress = runtimeServer.address()
                    if (!runtimeAddress || typeof runtimeAddress === "string") process.exit(42)
                    const runtimeClient = new Client({ hostname: "127.0.0.1", port: runtimeAddress.port, username: "packed-node", strictVendor: false })
                    const runtimeBanners = []
                    runtimeClient.on("banner", (message, languageTag) => runtimeBanners.push([message, languageTag]))
                    runtimeClient.on("error", rejectRuntime)
                    await Promise.race([runtimeClient.connect(), runtimeFailure])
                    if (JSON.stringify(runtimeBanners) !== JSON.stringify([["packed-banner", "en-US"]])) process.exit(46)
                    const runtimeCommand = await Promise.race([runtimeClient.exec("packed-node-runtime"), runtimeFailure])
                    const runtimeStdout = []
                    const runtimeStderr = []
                    runtimeCommand.on("data", (data) => runtimeStdout.push(data))
                    runtimeCommand.stderr.on("data", (data) => runtimeStderr.push(data))
                    await Promise.race([once(runtimeCommand, "close"), runtimeFailure])
                    if (Buffer.concat(runtimeStdout).toString() !== "node-stdout") process.exit(43)
                    if (Buffer.concat(runtimeStderr).toString() !== "node-stderr") process.exit(44)
                    if (runtimeCommand.exitCode !== 7) process.exit(45)
                    runtimeClient.hooker.hook("tcpConnection", async (_hook, channel, decision) => {
                        await Promise.resolve()
                        if (channel.details.sourceHost === "192.0.2.30") decision.allowOpen = true
                    })
                    const runtimeTCPConnection = once(runtimeClient, "tcp connection")
                    const runtimeForwardedPort = await runtimeClient.forwardIn("127.0.0.1", 0)
                    const runtimeServerTCP = runtimeConnection.forwardOut("127.0.0.1", runtimeForwardedPort, "192.0.2.30", 51238)
                    const [[runtimeTCPDetails, runtimeClientTCP], runtimeServerTCPChannel] = await Promise.all([runtimeTCPConnection, runtimeServerTCP])
                    if (!(runtimeClientTCP instanceof ClientForwardedTCPIPChannel) || runtimeTCPDetails !== runtimeClientTCP.details) process.exit(50)
                    runtimeClientTCP.close()
                    runtimeServerTCPChannel.close()
                    await runtimeClient.unforwardIn("127.0.0.1", runtimeForwardedPort)
                    const runtimeSocketDirectory = await mkdtemp(join(tmpdir(), "modernssh-packed-stream-local-"))
                    const runtimeSocketPath = join(runtimeSocketDirectory, "forwarded.sock")
                    runtimeClient.hooker.hook("streamLocalConnection", async (_hook, channel, decision) => {
                        await Promise.resolve()
                        if (channel.details.socketPath === runtimeSocketPath) decision.allowOpen = true
                    })
                    const runtimeStreamLocalConnection = once(runtimeClient, "unix connection")
                    await runtimeClient.openssh_forwardInStreamLocal(runtimeSocketPath)
                    const runtimeServerStreamLocal = runtimeConnection.openssh_forwardOutStreamLocal(runtimeSocketPath)
                    const [[runtimeStreamLocalDetails, runtimeClientStreamLocal], runtimeServerStreamLocalChannel] = await Promise.all([runtimeStreamLocalConnection, runtimeServerStreamLocal])
                    if (!(runtimeClientStreamLocal instanceof ClientForwardedStreamLocalChannel) || runtimeStreamLocalDetails !== runtimeClientStreamLocal.details) process.exit(51)
                    runtimeClientStreamLocal.close()
                    runtimeServerStreamLocalChannel.close()
                    await runtimeClient.openssh_unforwardInStreamLocal(runtimeSocketPath)
                    await rm(runtimeSocketDirectory, { recursive: true, force: true })
                    const runtimeX11Session = await runtimeClient.openSession()
                    await runtimeX11Session.requestX11()
                    runtimeClient.hooker.hook("x11Connection", async (_hook, channel, decision) => {
                        await Promise.resolve()
                        if (channel.details.originatorAddress === "192.0.2.50") decision.allowOpen = true
                    })
                    const runtimeX11Connection = once(runtimeClient, "x11")
                    const runtimeServerX11 = runtimeConnection.x11("192.0.2.50", 60050)
                    const [[runtimeX11Details, runtimeClientX11], runtimeServerX11Channel] = await Promise.all([runtimeX11Connection, runtimeServerX11])
                    if (!(runtimeClientX11 instanceof ClientX11Channel) || runtimeX11Details !== runtimeClientX11.details) process.exit(52)
                    runtimeClientX11.close()
                    runtimeServerX11Channel.close()
                    runtimeX11Session.close()
                    runtimeServer.hooker.hook("channelOpenRequest", (_hook, _channel, decision) => {
                        decision.allowOpen = false
                        decision.rejection = new ChannelOpenError(0xfe000002, "packed channel policy", "fr")
                    })
                    try {
                        await runtimeClient.openSession()
                        process.exit(48)
                    } catch (error) {
                        if (error.reasonCode !== 0xfe000002 || error.message !== "packed channel policy" || error.languageTag !== "fr") process.exit(49)
                    }
                    runtimeClient.disconnect(new DisconnectError(DisconnectReason.SSH_DISCONNECT_BY_APPLICATION, "packed maintenance", "en-US"))
                    const runtimeDisconnectInfo = await Promise.race([runtimeDisconnect, runtimeFailure])
                    if (JSON.stringify(runtimeDisconnectInfo) !== JSON.stringify({ reasonCode: 11, description: "packed maintenance", languageTag: "en-US" })) process.exit(47)
                    await Promise.race([once(runtimeClient, "close"), runtimeFailure])
                    await runtimeServer.close()
                    process.stdout.write(publicKey.toString())
                `,
                ],
                { cwd: consumer, timeout: 20_000 },
            )
            expect(stdout).toStartWith("ssh-ed25519 ")
            expect(stdout).toEndWith(" packed@example.test")
            expect(stderr).toBe("")
        } finally {
            await rm(directory, { recursive: true, force: true })
        }
    }, 30_000)
})
