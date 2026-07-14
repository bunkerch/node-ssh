import { once } from "node:events"
import type { AddressInfo } from "node:net"

import Client from "../../src/Client.js"
import Server from "../../src/Server.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

describe("RFC 5647 AES-GCM integration", () => {
    test.each(["AEAD_AES_128_GCM", "AEAD_AES_256_GCM"])(
        "exchanges protected traffic and rekeys with %s in both negotiation lists",
        async (algorithm) => {
            const algorithms = {
                kex: ["curve25519-sha256"],
                serverHostKey: ["ssh-ed25519"],
                cipher: [algorithm],
                hmac: [algorithm],
                compress: ["none"],
            }
            const server = new Server({
                hostKeys: [PrivateKey.generateSync("ssh-ed25519")],
                sendAllHostKeys: false,
                algorithms,
            })
            const serverErrors: Error[] = []
            const serverHandshakes: { cipher: string; mac: string }[] = []
            server.hooker.hook("noneAuthentication", (_hook, _context, controller) => {
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
                peer.on("handshake", ({ cs }) => {
                    serverHandshakes.push({ cipher: cs.cipher, mac: cs.mac })
                })
            })

            server.listen(0, "127.0.0.1")
            await once(server, "listening")
            const client = new Client({
                hostname: "127.0.0.1",
                port: (server.address() as AddressInfo).port,
                username: "rfc5647-test",
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
                    { cipher: algorithm, mac: algorithm },
                    { cipher: algorithm, mac: algorithm },
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
