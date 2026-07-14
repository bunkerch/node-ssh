import { once } from "node:events"
import type { AddressInfo } from "node:net"
import Client from "../../src/Client.js"
import { SSHAuthenticationMethods } from "../../src/constants.js"
import Server, { type ServerConnectionInfo } from "../../src/Server.js"
import type ServerClient from "../../src/ServerClient.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

test("server connection events retain immutable transport endpoint metadata", async () => {
    const hostKey = await PrivateKey.generate("ssh-ed25519")
    const server = new Server({ hostKeys: [hostKey], sendAllHostKeys: false })
    server.hooker.hook("noneAuthentication", (_hook, _context, controller) => {
        controller.allowLogin = true
    })
    let peer: ServerClient | undefined
    let connectionInfo: Readonly<ServerConnectionInfo> | undefined
    server.on("connection", (connection, info) => {
        peer = connection
        connectionInfo = info
    })
    server.listen({ host: "127.0.0.1", port: 0 })
    await once(server, "listening")

    const address = server.address() as AddressInfo
    const client = new Client({
        hostname: "127.0.0.1",
        port: address.port,
        username: "connection-info-test",
        authenticationMethodsOrder: [SSHAuthenticationMethods.None],
    })
    client.hooker.hook("hostKey", (_hook, controller) => {
        controller.allowHostKey = true
    })

    try {
        await client.connect()
        expect(connectionInfo).toMatchObject({
            remoteAddress: "127.0.0.1",
            remoteFamily: "IPv4",
            localAddress: "127.0.0.1",
            localFamily: "IPv4",
            localPort: address.port,
        })
        expect(connectionInfo?.remotePort).toBeGreaterThan(0)
        expect(Object.isFrozen(connectionInfo)).toBe(true)

        const snapshot = connectionInfo
        const closed = once(peer!, "close")
        client.end()
        await closed
        expect(connectionInfo).toBe(snapshot)
        expect(connectionInfo?.remoteAddress).toBe("127.0.0.1")
    } finally {
        client.destroy()
        for (const connection of server.clients) connection.terminate()
        await server.close()
    }
}, 15_000)
