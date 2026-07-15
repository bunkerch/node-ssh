import { expect, test } from "bun:test"
import { once } from "node:events"
import type { AddressInfo } from "node:net"
import Client from "../../src/Client.js"
import { SSHAuthenticationMethods } from "../../src/constants.js"
import ProtocolVersionExchange from "../../src/ProtocolVersionExchange.js"
import Server from "../../src/Server.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

test("client and server own configured identifications before connecting", async () => {
    const clientIdentity = new ProtocolVersionExchange("2.0", "client_original")
    const serverIdentity = new ProtocolVersionExchange("2.0", "server_original")
    const server = new Server({
        hostKeys: [await PrivateKey.generate("ssh-ed25519")],
        protocolVersionExchange: serverIdentity,
        sendAllHostKeys: false,
    })
    server.hooker.hook("noneAuthentication", (_hook, _context, decision) => {
        decision.allowLogin = true
    })

    let observedClientIdentity: string | undefined
    server.on("connection", (connection) => {
        connection.on("error", () => undefined)
        connection.on("clientProtocolVersion", (identity) => {
            observedClientIdentity = identity.protocol_software
        })
    })
    server.listen({ host: "127.0.0.1", port: 0 })
    await once(server, "listening")

    const client = new Client({
        hostname: "127.0.0.1",
        port: (server.address() as AddressInfo).port,
        username: "identity-owner",
        protocolVersionExchange: clientIdentity,
        authenticationMethodsOrder: [SSHAuthenticationMethods.None],
    })
    client.hooker.hook("hostKey", (_hook, decision) => {
        decision.allowHostKey = true
    })
    expect(
        () =>
            ((clientIdentity as { protocol_software: string }).protocol_software =
                "client_mutated"),
    ).toThrow(TypeError)
    expect(
        () =>
            ((serverIdentity as { protocol_software: string }).protocol_software =
                "server_mutated"),
    ).toThrow(TypeError)

    try {
        await client.connect()
        expect(observedClientIdentity).toBe("client_original")
        expect(client.serverProtocolVersion?.protocol_software).toBe("server_original")
    } finally {
        client.destroy()
        for (const connection of server.clients) connection.terminate()
        await server.close()
    }
})
