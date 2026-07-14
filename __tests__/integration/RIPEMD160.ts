import { once } from "node:events"
import type { AddressInfo } from "node:net"

import Client from "../../src/Client.js"
import Server from "../../src/Server.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

describe("legacy HMAC-RIPEMD160 integration", () => {
    test("exchanges protected traffic and rekeys in both peer roles", async () => {
        const algorithms = {
            kex: ["curve25519-sha256"],
            serverHostKey: ["ssh-ed25519"],
            cipher: ["aes128-ctr"],
            hmac: ["hmac-ripemd160"],
            compress: ["none"],
        }
        const server = new Server({
            hostKeys: [PrivateKey.generateSync("ssh-ed25519")],
            sendAllHostKeys: false,
            algorithms,
        })
        const serverErrors: Error[] = []
        const serverMACs: string[] = []
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
            peer.on("handshake", ({ cs }) => serverMACs.push(cs.mac))
        })

        server.listen(0, "127.0.0.1")
        await once(server, "listening")
        const client = new Client({
            hostname: "127.0.0.1",
            port: (server.address() as AddressInfo).port,
            username: "ripemd160-test",
            algorithms,
        })
        const clientErrors: Error[] = []
        const clientMACs: string[] = []
        client.on("error", (error) => clientErrors.push(error))
        client.on("handshake", ({ cs }) => clientMACs.push(cs.mac))
        client.hooker.hook("hostKey", (_hook, decision) => {
            decision.allowHostKey = true
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
            expect(clientMACs).toEqual(["hmac-ripemd160", "hmac-ripemd160"])
            expect(serverMACs).toEqual(clientMACs)
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
