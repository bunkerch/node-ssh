import { AddressInfo, createConnection } from "node:net"
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
        server.hooker.hook("tcpipForward", (_hook, context, controller) => {
            controller.allow = context.bindAddress === "127.0.0.1" && context.bindPort === 0
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
        let connectEvents = 0
        client.on("error", (error) => clientErrors.push(error))
        client.on("connect", () => connectEvents++)

        try {
            await client.connect()

            expect(client.hasAuthenticated).toBe(true)
            expect(client.isConnected).toBe(true)
            expect(connectEvents).toBe(1)
            expect(serverErrors).toEqual([])
            expect(clientErrors).toEqual([])

            const forwardedPort = await client.forwardIn("127.0.0.1", 0)
            expect(forwardedPort).toBeGreaterThan(0)
            expect(forwardedPort).toBeLessThanOrEqual(65_535)
            await client.unforwardIn("127.0.0.1", forwardedPort)
            const listenerStillAccepts = await new Promise<boolean>((resolve) => {
                const probe = createConnection({ host: "127.0.0.1", port: forwardedPort })
                probe.once("connect", () => {
                    probe.destroy()
                    resolve(true)
                })
                probe.once("error", () => resolve(false))
            })
            expect(listenerStillAccepts).toBe(false)
        } finally {
            const closed = new Promise<void>((resolve) => client.once("close", resolve))
            expect(client.end()).toBe(client)
            expect(client.end()).toBe(client)
            await closed
            expect(client.isConnected).toBe(false)
            await new Promise<void>((resolve, reject) => {
                server.server!.close((error) => (error ? reject(error) : resolve()))
            })
        }
    }, 15_000)
})
