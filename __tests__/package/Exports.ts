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
    ForwardedTCPIPChannel,
    ForwardedAgentChannel,
    ForwardedStreamLocalChannel,
    ForwardedX11Channel,
    OnePasswordAgent,
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
    SFTPWriteStream,
    SSHAgent,
    SSHAuthenticationMethods,
    type ClientOptions,
    type ServerOptions,
} from "../../src/index.js"

describe("package exports", () => {
    test("exposes the supported source API without executing a demo", () => {
        const clientOptions: ClientOptions = { hostname: "example.test" }
        const serverOptions: ServerOptions = { sendAllHostKeys: false }

        expect(clientOptions.hostname).toBe("example.test")
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
        ]).toHaveLength(27)
        expect(SSHAuthenticationMethods.PublicKey).toBe("publickey")
        expect(SSHAuthenticationMethods.KeyboardInteractive).toBe("keyboard-interactive")
        expect(encodeSFTPPacket).toBeFunction()
        expect(decodeSFTPLimits).toBeFunction()
        expect(SFTPPacketParser).toBeFunction()
        expect(SFTPPacketType.Init).toBe(1)
        expect(SFTPClient).toBeFunction()
        expect(SFTPReadStream).toBeFunction()
        expect(SFTPServer).toBeFunction()
        expect(SFTPWriteStream).toBeFunction()
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
        expect(entry.SFTPWriteStream).toBeDefined()
        expect(entry.decodeSFTPLimits).toBeDefined()
    })
})
