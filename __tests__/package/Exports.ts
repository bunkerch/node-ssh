import { execFile } from "node:child_process"
import { mkdir, mkdtemp, readFile, readdir, rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { promisify } from "node:util"
import {
    Agent,
    buildGSSAPIKeyExchangeUserAuthMIC,
    Channel,
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
    PrivateKey,
    PrivateKeyAgent,
    ProtocolVersionExchange,
    PublicKey,
    PublicKeyAlgorithm,
    PublicKeySubsystemClient,
    SecurityKeyAttestation,
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
    SSHAuthenticationMethods,
    TerminalMode,
    TerminalModes,
    type ClientOptions,
    type ClientSessionOptions,
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

        expect(clientOptions.hostname).toBe("example.test")
        expect(sessionOptions.pty).toBe(true)
        expect(serverOptions.sendAllHostKeys).toBe(false)
        expect(connectionInfo.remoteAddress).toBe("127.0.0.1")
        expect(keyExchangeOptions.service).toBe("host")
        expect(agentProtocolOptions.requestTimeout).toBe(250)
        expect(agentProtocolServerOptions.maxMessageLength).toBe(2048)
        expect(agentConstraint.type).toBe("confirm")
        expect(destinationConstraint.type).toBe("openssh-restrict-destination")
        expect(sessionBinding).toBeUndefined()
        expect(cygwinAgentOptions.handshakeTimeout).toBe(500)
        expect(publicKeyAddOptions.overwrite).toBe(true)
        expect(publicKeyServerOptions.attributes?.[0]?.name).toBe("comment")
        expect([
            Agent,
            Channel,
            Client,
            ClientAgentChannel,
            ClientDirectStreamLocalChannel,
            ClientForwardedStreamLocalChannel,
            ClientForwardedTCPIPChannel,
            ClientTCPIPChannel,
            ClientX11Channel,
            DirectTCPIPChannel,
            DirectStreamLocalChannel,
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
            PrivateKey,
            PrivateKeyAgent,
            ProtocolVersionExchange,
            PublicKey,
            PublicKeyAlgorithm,
            SecurityKeyAttestation,
            Server,
            ServerClient,
            SessionChannel,
            Shell,
            SSHAgent,
            SSHHTTPAgent,
            SSHHTTPSAgent,
        ]).toHaveLength(42)
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

        expect(entry.Client).toBeDefined()
        expect(entry.ClientAgentChannel).toBeDefined()
        expect(entry.ClientDirectStreamLocalChannel).toBeDefined()
        expect(entry.ClientForwardedStreamLocalChannel).toBeDefined()
        expect(entry.ClientForwardedTCPIPChannel).toBeDefined()
        expect(entry.ClientTCPIPChannel).toBeDefined()
        expect(entry.ClientX11Channel).toBeDefined()
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
        expect(entry.KnownHosts).toBeFunction()
        expect(entry.parseKeys).toBeFunction()
        expect(entry.DirectTCPIPChannel).toBeDefined()
        expect(entry.DirectStreamLocalChannel).toBeDefined()
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
        const agentProtocol = await readFile("dist/publickey/SSHAgentProtocol.d.ts", "utf8")
        const cygwinAgent = await readFile("dist/publickey/CygwinAgent.d.ts", "utf8")
        const pageantAgent = await readFile("dist/publickey/PageantAgent.d.ts", "utf8")
        const sftpServer = await readFile("dist/sftp/SFTPServer.d.ts", "utf8")
        const publicKeySubsystemClient = await readFile(
            "dist/publickey/PublicKeySubsystemClient.d.ts",
            "utf8",
        )

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
        expect(client).toContain("authenticationMethodsOrder?: readonly SSHAuthenticationMethods[]")
        expect(client).toContain("replyTimeout?: number")
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
        expect(server).toContain("delayCompression?: DelayCompressionConfiguration")
        expect(server).toContain("replyTimeout?: number")
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
                    const { Client, createSocketAgent, CygwinAgent, CygwinAgentError, DELAY_COMPRESSION_EXTENSION, delayCompressionExtension, discoverPageantAgentSocket, ELEVATION_EXTENSION, EncodedSignature, generateKeyPair, generateKeyPairSync, KeyRevocationList, KnownHosts, MAX_OPENSSH_AGENT_SESSION_BINDINGS, MAX_SSH_AGENT_MESSAGE_LENGTH, NO_FLOW_CONTROL_EXTENSION, OnePasswordAgent, OPENSSH_AGENT_SECURITY_KEY_PROVIDER, OPENSSH_AGENT_SESSION_BIND, PageantAgent, PageantAgentError, parseKey, PrivateKey, PrivateKeyAgent, PublicKey, PublicKeySubsystemClient, PublicKeySubsystemServer, PublicKeySubsystemStatusCode, SecurityKeyAttestation, Server, SessionChannel, SSH_ED25519_SECURITY_KEY_ALGORITHM, SSHAgentConstraintType, SSHAgentExtensionFailureError, SSHAgentMessageType, SSHAgentProtocolClient, SSHAgentProtocolError, SSHAgentProtocolServer, SSHED25519SecurityKeyPrivateKey, SSHED25519SecurityKeyPublicKey } = await import("@bunkerch/modernssh")
                    const { privateKey, publicKey } = await generateKeyPair("ed25519", {
                        comment: "packed@example.test",
                    })
                    const message = Buffer.from("packed-key-generation")
                    if (!publicKey.verifySignature(message, privateKey.sign(message))) process.exit(2)
                    const encrypted = privateKey.toString({ passphrase: "packed-secret", rounds: 1 })
                    const parsed = PrivateKey.fromString(encrypted, "packed-secret")
                    if (!parsed.data.publicKey.equals(publicKey)) process.exit(3)
                    if (!parseKey(publicKey.toString()).equals(publicKey)) process.exit(4)
                    const configured = new Client({ privateKey: encrypted, passphrase: "packed-secret" })
                    if ("options" in configured) process.exit(5)
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
                    const runtimeServer = new Server({ hostKeys: [privateKey], sendAllHostKeys: false })
                    runtimeServer.on("error", rejectRuntime)
                    runtimeServer.hooker.hook("noneAuthentication", (_hook, _context, decision) => { decision.allowLogin = true })
                    runtimeServer.hooker.hook("channelOpenRequest", (_hook, channel, decision) => { decision.allowOpen = channel instanceof SessionChannel })
                    runtimeServer.on("connection", (connection) => {
                        connection.on("error", rejectRuntime)
                        connection.on("channel", (channel) => {
                            if (!(channel instanceof SessionChannel)) return
                            channel.hooker.hook("execRequest", (_hook, context, decision) => { decision.success = context.command === "packed-node-runtime" })
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
                    const runtimeClient = new Client({ hostname: "127.0.0.1", port: runtimeAddress.port, username: "packed-node" })
                    runtimeClient.on("error", rejectRuntime)
                    await Promise.race([runtimeClient.connect(), runtimeFailure])
                    const runtimeCommand = await Promise.race([runtimeClient.exec("packed-node-runtime"), runtimeFailure])
                    const runtimeStdout = []
                    const runtimeStderr = []
                    runtimeCommand.on("data", (data) => runtimeStdout.push(data))
                    runtimeCommand.stderr.on("data", (data) => runtimeStderr.push(data))
                    await Promise.race([once(runtimeCommand, "close"), runtimeFailure])
                    if (Buffer.concat(runtimeStdout).toString() !== "node-stdout") process.exit(43)
                    if (Buffer.concat(runtimeStderr).toString() !== "node-stderr") process.exit(44)
                    if (runtimeCommand.exitCode !== 7) process.exit(45)
                    runtimeClient.end()
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
