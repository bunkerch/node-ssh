import { once } from "node:events"
import type { AddressInfo } from "node:net"

import Client from "../../src/Client.js"
import Server from "../../src/Server.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

const methods = [
    ["RFC 4253", "diffie-hellman-group1-sha1"],
    ["RFC 4253", "diffie-hellman-group14-sha1"],
    ["RFC 8268", "diffie-hellman-group14-sha256"],
    ["RFC 8268", "diffie-hellman-group15-sha512"],
    ["RFC 8268", "diffie-hellman-group16-sha512"],
    ["RFC 8268", "diffie-hellman-group17-sha512"],
    ["RFC 8268", "diffie-hellman-group18-sha512"],
] as const

describe("fixed-group Diffie-Hellman integration", () => {
    test.each(methods)("%s traffic and rekey with %s", async (_, keyExchange) => {
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
        server.hooker.hook("noneAuthentication", (_hook, _context, decision) => {
            decision.allowLogin = true
        })
        server.hooker.hook("globalRequest", (_hook, context, decision) => {
            if (context.name !== "echo@example.test") return
            decision.success = true
            decision.response = Buffer.from(context.args)
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
            username: "fixed-group-test",
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
        client.hooker.hook("hostKey", (_hook, decision) => {
            decision.allowHostKey = true
        })

        try {
            await client.connect()
            const sessionId = Buffer.from(client.sessionID!)
            const firstHash = Buffer.from(client.exchangeHash!)
            expect(await client.globalRequest("echo@example.test", Buffer.from("first"))).toEqual(
                Buffer.from("first"),
            )

            await client.rekey()
            expect(client.sessionID).toEqual(sessionId)
            expect(client.exchangeHash).not.toEqual(firstHash)
            expect(await client.globalRequest("echo@example.test", Buffer.from("second"))).toEqual(
                Buffer.from("second"),
            )
            expect(clientHandshakes).toEqual([keyExchange, keyExchange])
            expect(serverHandshakes).toEqual([keyExchange, keyExchange])
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
