import { once } from "node:events"
import type { AddressInfo } from "node:net"
import Client from "../../src/Client.js"
import Server from "../../src/Server.js"
import { SSHAuthenticationMethods } from "../../src/constants.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

test("direct TCP inactivity emits timeout without closing the SSH connection", async () => {
    const server = new Server({
        hostKeys: [await PrivateKey.generate("ssh-ed25519")],
        sendAllHostKeys: false,
    })
    server.hooker.hook("noneAuthentication", (_hook, _context, controller) => {
        controller.allowLogin = true
    })
    server.hooker.hook("globalRequest", (_hook, context, controller) => {
        if (context.name !== "after-timeout@example.test") return
        controller.success = true
        controller.response = Buffer.from("still connected")
    })
    server.listen({ host: "127.0.0.1", port: 0 })
    await once(server, "listening")

    const client = new Client({
        hostname: "127.0.0.1",
        port: (server.address() as AddressInfo).port,
        username: "transport-timeout-test",
        authenticationMethodsOrder: [SSHAuthenticationMethods.None],
        timeout: 50,
    })
    client.hooker.hook("hostKey", (_hook, controller) => {
        controller.allowHostKey = true
    })

    try {
        const timeout = once(client, "timeout", { signal: AbortSignal.timeout(2_000) })
        await client.connect()
        expect(await timeout).toEqual([])
        expect(client.isConnected).toBe(true)
        expect(await client.globalRequest("after-timeout@example.test")).toEqual(
            Buffer.from("still connected"),
        )
    } finally {
        client.destroy()
        for (const connection of server.clients) connection.terminate()
        await server.close()
    }
}, 15_000)
