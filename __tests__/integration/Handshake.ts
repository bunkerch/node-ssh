import { AddressInfo } from "node:net"
import Client from "../../src/Client.js"
import Server from "../../src/Server.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

describe("client/server integration", () => {
    test("completes an encrypted handshake and none authentication over fragmented-safe transport", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({ hostKeys: [hostKey], sendAllHostKeys: false })
        const serverErrors: Error[] = []
        server.hooker.hook("noneAuthentication", (_hook, _context, controller) => {
            controller.allowLogin = true
        })
        server.on("connection", (peer) => {
            peer.on("error", (error) => serverErrors.push(error))
        })

        server.listen({ host: "127.0.0.1", port: 0 })
        await new Promise<void>((resolve) => server.server!.once("listening", resolve))

        const address = server.server!.address() as AddressInfo
        const client = new Client({
            hostname: "127.0.0.1",
            port: address.port,
            username: "integration-test",
        })
        const clientErrors: Error[] = []
        client.on("error", (error) => clientErrors.push(error))

        try {
            await client.connect()

            expect(client.hasAuthenticated).toBe(true)
            expect(serverErrors).toEqual([])
            expect(clientErrors).toEqual([])
        } finally {
            for (const peer of server.clients) peer.terminate()
            await new Promise<void>((resolve, reject) => {
                server.server!.close((error) => (error ? reject(error) : resolve()))
            })
        }
    }, 15_000)
})
