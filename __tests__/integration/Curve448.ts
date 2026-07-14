import { once } from "node:events"
import type { AddressInfo } from "node:net"
import Client from "../../src/Client.js"
import Server from "../../src/Server.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

describe("RFC 8731 Curve448 integration", () => {
    test("exchanges protected traffic and rekeys with curve448-sha512 in both roles", async () => {
        const server = new Server({
            hostKeys: [PrivateKey.generateSync("ssh-ed25519")],
            sendAllHostKeys: false,
            algorithms: {
                kex: ["curve448-sha512"],
                serverHostKey: ["ssh-ed25519"],
                cipher: ["aes128-ctr"],
                hmac: ["hmac-sha2-256-etm@openssh.com"],
                compress: ["none"],
            },
        })
        const serverErrors: Error[] = []
        const serverHandshakes: string[] = []
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
            peer.on("handshake", (negotiated) => serverHandshakes.push(negotiated.kex))
        })

        server.listen(0, "127.0.0.1")
        await once(server, "listening")
        const port = (server.address() as AddressInfo).port
        const client = new Client({
            hostname: "127.0.0.1",
            port,
            username: "curve448-test",
            algorithms: {
                kex: ["curve448-sha512"],
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
        client.hooker.hook("hostKey", (_hook, decision) => {
            decision.allowHostKey = true
        })

        try {
            await client.connect()
            const sessionId = Buffer.from(client.sessionID!)
            const firstExchangeHash = Buffer.from(client.exchangeHash!)
            expect(firstExchangeHash).toHaveLength(64)
            expect(await client.globalRequest("echo@example.test", Buffer.from("first"))).toEqual(
                Buffer.from("first"),
            )

            await client.rekey()
            expect(client.sessionID).toEqual(sessionId)
            expect(client.exchangeHash).not.toEqual(firstExchangeHash)
            expect(await client.globalRequest("echo@example.test", Buffer.from("second"))).toEqual(
                Buffer.from("second"),
            )
            expect(clientHandshakes).toEqual(["curve448-sha512", "curve448-sha512"])
            expect(serverHandshakes).toEqual(["curve448-sha512", "curve448-sha512"])
            expect(clientErrors).toEqual([])
            expect(serverErrors).toEqual([])
        } finally {
            const closed = once(client, "close")
            client.end()
            await closed
            await server.close()
        }
    })
})
