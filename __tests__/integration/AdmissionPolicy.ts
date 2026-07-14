import { once } from "node:events"
import type { AddressInfo } from "node:net"
import Client from "../../src/Client.js"
import { SSHAuthenticationMethods } from "../../src/constants.js"
import Server from "../../src/Server.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

test("a rejected async preconnect policy cannot retain an earlier allow decision", async () => {
    const hostKey = await PrivateKey.generate("ssh-ed25519")
    const server = new Server({
        hostKeys: [hostKey],
        sendAllHostKeys: false,
        algorithms: { kex: ["curve25519-sha256"] },
    })
    const hookErrors: Error[] = []
    let admitted = 0
    server.hooker.on("uncaughtException", (_event, error) => hookErrors.push(error))
    server.hooker.hook("preconnect", (_hook, controller) => {
        controller.allowConnection = true
    })
    server.hooker.hook("preconnect", async () => {
        await Promise.resolve()
        throw new Error("admission backend failed")
    })
    server.hooker.hook("noneAuthentication", (_hook, _context, controller) => {
        controller.allowLogin = true
    })
    server.on("connection", () => {
        admitted++
    })
    server.listen({ host: "127.0.0.1", port: 0 })
    await once(server, "listening")

    const client = new Client({
        hostname: "127.0.0.1",
        port: (server.address() as AddressInfo).port,
        username: "rejected-admission",
        authenticationMethodsOrder: [SSHAuthenticationMethods.None],
        algorithms: { kex: ["curve25519-sha256"] },
    })
    client.hooker.hook("hostKey", (_hook, controller) => {
        controller.allowHostKey = true
    })

    try {
        const settlement = await client.connect().then(
            () => "fulfilled" as const,
            () => "rejected" as const,
        )

        expect(settlement).toBe("rejected")
        expect(admitted).toBe(0)
        expect(hookErrors.map((error) => error.message)).toEqual(["admission backend failed"])
        expect(server.clients.size).toBe(0)
    } finally {
        client.destroy()
        for (const connection of server.clients) connection.terminate()
        await server.close()
    }
}, 15_000)
