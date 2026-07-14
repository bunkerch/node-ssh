import { once } from "node:events"
import type { AddressInfo } from "node:net"

import Client from "../../src/Client.js"
import Server from "../../src/Server.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

describe("legacy Blowfish-CBC integration", () => {
    test("exchanges protected traffic and rekeys in both peer roles", async () => {
        const algorithms = {
            kex: ["curve25519-sha256"],
            serverHostKey: ["ssh-ed25519"],
            cipher: ["blowfish-cbc"],
            hmac: ["hmac-sha2-256"],
            compress: ["none"],
        }
        const server = new Server({
            hostKeys: [PrivateKey.generateSync("ssh-ed25519")],
            sendAllHostKeys: false,
            algorithms,
        })
        const serverErrors: Error[] = []
        const serverCiphers: string[] = []
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
            peer.on("handshake", ({ cs }) => serverCiphers.push(cs.cipher))
        })

        server.listen(0, "127.0.0.1")
        await once(server, "listening")
        const client = new Client({
            hostname: "127.0.0.1",
            port: (server.address() as AddressInfo).port,
            username: "blowfish-test",
            algorithms,
        })
        const clientErrors: Error[] = []
        const clientCiphers: string[] = []
        client.on("error", (error) => clientErrors.push(error))
        client.on("handshake", ({ cs }) => clientCiphers.push(cs.cipher))
        client.hooker.hook("hostKey", (_hook, controller) => {
            controller.allowHostKey = true
        })

        try {
            await client.connect()
            expect(await client.globalRequest("echo@example.test", Buffer.from("first"))).toEqual(
                Buffer.from("first"),
            )
            await client.rekey()
            expect(await client.globalRequest("echo@example.test", Buffer.from("second"))).toEqual(
                Buffer.from("second"),
            )
            expect(clientCiphers).toEqual(["blowfish-cbc", "blowfish-cbc"])
            expect(serverCiphers).toEqual(clientCiphers)
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
    })
})
