import { once } from "node:events"
import type { AddressInfo } from "node:net"

import Client from "../../src/Client.js"
import Server from "../../src/Server.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

describe("ChaCha20-Poly1305 integration", () => {
    test.each(["chacha20-poly1305", "chacha20-poly1305@openssh.com"])(
        "exchanges protected traffic and rekeys with %s",
        async (cipher) => {
            const algorithms = {
                kex: ["curve25519-sha256"],
                serverHostKey: ["ssh-ed25519"],
                cipher: [cipher],
                hmac: ["hmac-sha2-256"],
                compress: ["none"],
            }
            const server = new Server({
                hostKeys: [PrivateKey.generateSync("ssh-ed25519")],
                sendAllHostKeys: false,
                algorithms,
            })
            const serverErrors: Error[] = []
            const serverHandshakes: { cipher: string; mac: string }[] = []
            server.hooker.hook("noneAuthentication", (_hook, _context, decision) => {
                decision.allowLogin = true
            })
            server.hooker.hook("globalRequest", async (_hook, context, decision) => {
                await Promise.resolve()
                if (context.name !== "echo@example.test") return
                decision.success = true
                decision.response = Buffer.from(context.args)
            })
            server.on("connection", (connection) => {
                connection.on("error", (error) => serverErrors.push(error))
                connection.on("handshake", ({ cs }) => {
                    serverHandshakes.push({ cipher: cs.cipher, mac: cs.mac })
                })
            })

            server.listen(0, "127.0.0.1")
            await once(server, "listening")
            const client = new Client({
                hostname: "127.0.0.1",
                port: (server.address() as AddressInfo).port,
                username: "chacha20-poly1305-test",
                algorithms,
            })
            const clientErrors: Error[] = []
            const clientHandshakes: { cipher: string; mac: string }[] = []
            client.on("error", (error) => clientErrors.push(error))
            client.on("handshake", ({ cs }) => {
                clientHandshakes.push({ cipher: cs.cipher, mac: cs.mac })
            })
            client.hooker.hook("hostKey", (_hook, decision) => {
                decision.allowHostKey = true
            })

            try {
                await client.connect()
                expect(
                    await client.globalRequest("echo@example.test", Buffer.from("first")),
                ).toEqual(Buffer.from("first"))
                await client.rekey()
                expect(
                    await client.globalRequest("echo@example.test", Buffer.from("second")),
                ).toEqual(Buffer.from("second"))
                expect(clientHandshakes).toEqual([
                    { cipher, mac: "" },
                    { cipher, mac: "" },
                ])
                expect(serverHandshakes).toEqual(clientHandshakes)
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
    )
})
