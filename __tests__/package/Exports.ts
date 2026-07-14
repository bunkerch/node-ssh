import {
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
    decodeSFTPLimits,
    DiskAgent,
    EncodedSignature,
    encodeSFTPPacket,
    flagsToString,
    ForwardedTCPIPChannel,
    ForwardedAgentChannel,
    ForwardedStreamLocalChannel,
    ForwardedX11Channel,
    HTTPAgent,
    HTTPSAgent,
    OnePasswordAgent,
    OPEN_MODE,
    PrivateKey,
    ProtocolVersionExchange,
    PublicKey,
    PublicKeyAlgorithm,
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
    SSHHTTPAgent,
    SSHHTTPSAgent,
    SSHAuthenticationMethods,
    type ClientOptions,
    type ClientSessionOptions,
    type ServerOptions,
} from "../../src/index.js"

describe("package exports", () => {
    test("exposes the supported source API without executing a demo", () => {
        const clientOptions: ClientOptions = { hostname: "example.test" }
        const sessionOptions: ClientSessionOptions = { env: { LANG: "C" }, pty: true }
        const serverOptions: ServerOptions = { sendAllHostKeys: false }

        expect(clientOptions.hostname).toBe("example.test")
        expect(sessionOptions.pty).toBe(true)
        expect(serverOptions.sendAllHostKeys).toBe(false)
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
            HTTPAgent,
            HTTPSAgent,
            OnePasswordAgent,
            PrivateKey,
            ProtocolVersionExchange,
            PublicKey,
            PublicKeyAlgorithm,
            Server,
            ServerClient,
            SessionChannel,
            Shell,
            SSHAgent,
            SSHHTTPAgent,
            SSHHTTPSAgent,
        ]).toHaveLength(31)
        expect(SSHAuthenticationMethods.PublicKey).toBe("publickey")
        expect(SSHAuthenticationMethods.KeyboardInteractive).toBe("keyboard-interactive")
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
        expect(entry.DirectTCPIPChannel).toBeDefined()
        expect(entry.DirectStreamLocalChannel).toBeDefined()
        expect(entry.ForwardedTCPIPChannel).toBeDefined()
        expect(entry.ForwardedAgentChannel).toBeDefined()
        expect(entry.ForwardedStreamLocalChannel).toBeDefined()
        expect(entry.ForwardedX11Channel).toBeDefined()
        expect(entry.Server).toBeDefined()
        expect(entry.PrivateKey).toBeDefined()
        expect(entry.ProtocolVersionExchange).toBeDefined()
        expect(entry.SSHAgent).toBeDefined()
        expect(entry.OnePasswordAgent).toBeDefined()
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
    })
})
