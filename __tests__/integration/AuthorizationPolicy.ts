import { once } from "node:events"
import type { AddressInfo } from "node:net"
import Client from "../../src/Client.js"
import { SSHAuthenticationMethods } from "../../src/constants.js"
import Server from "../../src/Server.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

async function listen(server: Server): Promise<number> {
    server.listen({ host: "127.0.0.1", port: 0 })
    await once(server, "listening")
    return (server.address() as AddressInfo).port
}

async function close(server: Server, client: Client): Promise<void> {
    client.destroy()
    for (const connection of server.clients) connection.terminate()
    await server.close()
}

function settlement(connecting: Promise<void>): Promise<"fulfilled" | "rejected"> {
    return connecting.then(
        () => "fulfilled",
        () => "rejected",
    )
}

describe("contained authorization hook failures", () => {
    test("cannot retain an earlier host-key trust decision", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({
            hostKeys: [hostKey],
            sendAllHostKeys: false,
            algorithms: { kex: ["curve25519-sha256"] },
        })
        server.hooker.hook("noneAuthentication", (_hook, _context, controller) => {
            controller.allowLogin = true
        })
        const port = await listen(server)

        const client = new Client({
            hostname: "127.0.0.1",
            port,
            username: "host-policy-failure",
            authenticationMethodsOrder: [SSHAuthenticationMethods.None],
            algorithms: { kex: ["curve25519-sha256"] },
        })
        const hookErrors: Error[] = []
        client.hooker.on("uncaughtException", (_event, error) => hookErrors.push(error))
        client.hooker.hook("hostKey", (_hook, controller) => {
            controller.allowHostKey = true
        })
        client.hooker.hook("hostKey", async () => {
            await Promise.resolve()
            throw new Error("host trust backend failed")
        })

        try {
            expect(await settlement(client.connect())).toBe("rejected")
            expect(hookErrors.map((error) => error.message)).toEqual(["host trust backend failed"])
            expect(client.isConnected).toBe(false)
        } finally {
            await close(server, client)
        }
    }, 15_000)

    test("cannot retain an earlier user-authentication decision", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({
            hostKeys: [hostKey],
            sendAllHostKeys: false,
            algorithms: { kex: ["curve25519-sha256"] },
        })
        const hookErrors: Error[] = []
        server.hooker.on("uncaughtException", (_event, error) => hookErrors.push(error))
        server.hooker.hook("noneAuthentication", (_hook, _context, controller) => {
            controller.allowLogin = true
        })
        server.hooker.hook("noneAuthentication", async () => {
            await Promise.resolve()
            throw new Error("identity backend failed")
        })
        const port = await listen(server)

        const client = new Client({
            hostname: "127.0.0.1",
            port,
            username: "authentication-policy-failure",
            authenticationMethodsOrder: [SSHAuthenticationMethods.None],
            algorithms: { kex: ["curve25519-sha256"] },
        })
        client.hooker.hook("hostKey", (_hook, controller) => {
            controller.allowHostKey = true
        })

        try {
            expect(await settlement(client.connect())).toBe("rejected")
            expect(hookErrors.map((error) => error.message)).toEqual(["identity backend failed"])
            expect(client.isConnected).toBe(false)
        } finally {
            await close(server, client)
        }
    }, 15_000)
})
