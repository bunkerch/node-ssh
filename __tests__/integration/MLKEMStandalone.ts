import { once } from "node:events"
import type { AddressInfo } from "node:net"

import Client from "../../src/Client.js"
import Server from "../../src/Server.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

describe("registered standalone ML-KEM key exchange", () => {
    test.each([
        ["mlkem512-sha256", 32],
        ["mlkem768-sha256", 32],
        ["mlkem1024-sha384", 48],
    ] as const)(
        "exchanges protected traffic and rekeys with %s",
        async (keyExchange, hashBytes) => {
            const server = new Server({
                hostKeys: [PrivateKey.generateSync("ssh-ed25519")],
                sendAllHostKeys: false,
                algorithms: {
                    kex: [keyExchange],
                    serverHostKey: ["ssh-ed25519"],
                    cipher: ["aes128-ctr"],
                    hmac: ["hmac-sha2-256-etm@openssh.com"],
                    compress: ["none"],
                },
            })
            const serverErrors: Error[] = []
            const serverHandshakes: string[] = []
            server.hooker.hook("noneAuthentication", async (_hook, _context, controller) => {
                await Promise.resolve()
                controller.allowLogin = true
            })
            server.hooker.hook("globalRequest", async (_hook, context, controller) => {
                await Promise.resolve()
                if (context.name !== "echo@example.test") return
                controller.success = true
                controller.response = Buffer.from(context.args)
            })
            server.on("connection", (peer) => {
                peer.on("error", (error) => serverErrors.push(error))
                peer.on("handshake", (negotiated) => serverHandshakes.push(negotiated.kex))
            })

            server.listen(0, "127.0.0.1")
            await once(server, "listening")
            const client = new Client({
                hostname: "127.0.0.1",
                port: (server.address() as AddressInfo).port,
                username: "mlkem-test",
                algorithms: {
                    kex: [keyExchange],
                    serverHostKey: ["ssh-ed25519"],
                    cipher: ["aes128-ctr"],
                    hmac: ["hmac-sha2-256-etm@openssh.com"],
                    compress: ["none"],
                },
            })
            const clientErrors: Error[] = []
            const clientHandshakes: string[] = []
            client.on("error", (error) => clientErrors.push(error))
            client.on("handshake", (negotiated) => clientHandshakes.push(negotiated.kex))
            client.hooker.hook("hostKey", async (_hook, decision) => {
                await Promise.resolve()
                decision.allowHostKey = true
            })

            try {
                await client.connect()
                const sessionId = Buffer.from(client.sessionID!)
                const firstExchangeHash = Buffer.from(client.H!)
                expect(firstExchangeHash).toHaveLength(hashBytes)
                expect(
                    await client.globalRequest("echo@example.test", Buffer.from("first")),
                ).toEqual(Buffer.from("first"))

                await client.rekey()
                await [...server.clients][0]!.rekey()
                expect(client.sessionID).toEqual(sessionId)
                expect(client.H).not.toEqual(firstExchangeHash)
                expect(
                    await client.globalRequest("echo@example.test", Buffer.from("second")),
                ).toEqual(Buffer.from("second"))
                expect(clientHandshakes).toEqual([keyExchange, keyExchange, keyExchange])
                expect(serverHandshakes).toEqual([keyExchange, keyExchange, keyExchange])
                expect(clientErrors).toEqual([])
                expect(serverErrors).toEqual([])
            } finally {
                if (client.isConnected) {
                    const closed = once(client, "close")
                    client.end()
                    await closed
                } else {
                    client.destroy()
                }
                await server.close()
            }
        },
        20_000,
    )
})
