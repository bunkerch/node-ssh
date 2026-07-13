import {
    Agent,
    Channel,
    Client,
    ClientAgentChannel,
    ClientDirectStreamLocalChannel,
    ClientForwardedStreamLocalChannel,
    ClientForwardedTCPIPChannel,
    ClientTCPIPChannel,
    DirectTCPIPChannel,
    DirectStreamLocalChannel,
    DiskAgent,
    EncodedSignature,
    ForwardedTCPIPChannel,
    ForwardedAgentChannel,
    ForwardedStreamLocalChannel,
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
            DirectTCPIPChannel,
            DirectStreamLocalChannel,
            DiskAgent,
            EncodedSignature,
            ForwardedTCPIPChannel,
            ForwardedAgentChannel,
            ForwardedStreamLocalChannel,
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
        ]).toHaveLength(25)
        expect(SSHAuthenticationMethods.PublicKey).toBe("publickey")
    })

    test("compiled entry point provides the same side-effect-free API", async () => {
        const entry = await import("../../dist/index.js")

        expect(entry.Client).toBeDefined()
        expect(entry.ClientAgentChannel).toBeDefined()
        expect(entry.ClientDirectStreamLocalChannel).toBeDefined()
        expect(entry.ClientForwardedStreamLocalChannel).toBeDefined()
        expect(entry.ClientForwardedTCPIPChannel).toBeDefined()
        expect(entry.ClientTCPIPChannel).toBeDefined()
        expect(entry.DirectTCPIPChannel).toBeDefined()
        expect(entry.DirectStreamLocalChannel).toBeDefined()
        expect(entry.ForwardedTCPIPChannel).toBeDefined()
        expect(entry.ForwardedAgentChannel).toBeDefined()
        expect(entry.ForwardedStreamLocalChannel).toBeDefined()
        expect(entry.Server).toBeDefined()
        expect(entry.PrivateKey).toBeDefined()
        expect(entry.ProtocolVersionExchange).toBeDefined()
        expect(entry.SSHAgent).toBeDefined()
        expect(entry.OnePasswordAgent).toBeDefined()
    })
})
