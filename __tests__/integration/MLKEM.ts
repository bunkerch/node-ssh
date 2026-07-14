import { AddressInfo } from "node:net"
import { once } from "node:events"

import Client from "../../src/Client.js"
import Server from "../../src/Server.js"
import { SSHAuthenticationMethods } from "../../src/constants.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

describe("registered ML-KEM hybrid key exchange", () => {
    test.each(["mlkem768nistp256-sha256", "mlkem1024nistp384-sha384", "mlkem768x25519-sha256"])(
        "exchanges protected traffic and rekeys with %s",
        async (keyExchange) => {
            const hostKey = await PrivateKey.generate("ssh-ed25519")
            const server = new Server({
                hostKeys: [hostKey],
                sendAllHostKeys: false,
                algorithms: { kex: [keyExchange] },
            })
            const errors: Error[] = []
            server.hooker.hook("noneAuthentication", (_hook, _context, decision) => {
                decision.allowLogin = true
            })
            server.on("connection", (connection) =>
                connection.on("error", (error) => errors.push(error)),
            )
            server.listen({ host: "127.0.0.1", port: 0 })
            await once(server.server, "listening")

            const client = new Client({
                hostname: "127.0.0.1",
                port: (server.server.address() as AddressInfo).port,
                username: "mlkem-user",
                authenticationMethodsOrder: [SSHAuthenticationMethods.None],
                algorithms: { kex: [keyExchange] },
            })
            client.on("error", (error) => errors.push(error))
            client.hooker.hook("hostKey", (_hook, decision) => {
                decision.allowHostKey = true
            })

            try {
                await client.connect()
                await client.rekey()
                await [...server.clients][0]!.rekey()
                expect(errors).toEqual([])
            } finally {
                client.destroy()
                for (const connection of server.clients) connection.terminate()
                await server.close()
            }
        },
        20_000,
    )
})
