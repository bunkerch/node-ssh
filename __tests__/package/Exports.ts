import {
    Agent,
    Channel,
    Client,
    DiskAgent,
    EncodedSignature,
    PrivateKey,
    ProtocolVersionExchange,
    PublicKey,
    PublicKeyAlgorithm,
    Server,
    ServerClient,
    SessionChannel,
    Shell,
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
            DiskAgent,
            EncodedSignature,
            PrivateKey,
            ProtocolVersionExchange,
            PublicKey,
            PublicKeyAlgorithm,
            Server,
            ServerClient,
            SessionChannel,
            Shell,
        ]).toHaveLength(13)
        expect(SSHAuthenticationMethods.PublicKey).toBe("publickey")
    })

    test("compiled entry point provides the same side-effect-free API", async () => {
        const entry = await import("../../dist/index.js")

        expect(entry.Client).toBeDefined()
        expect(entry.Server).toBeDefined()
        expect(entry.PrivateKey).toBeDefined()
        expect(entry.ProtocolVersionExchange).toBeDefined()
    })
})
