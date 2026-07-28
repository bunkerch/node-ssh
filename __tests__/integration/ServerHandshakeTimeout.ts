import { AddressInfo, createConnection } from "node:net"
import Client from "../../src/Client.js"
import { SSHAuthenticationMethods } from "../../src/constants.js"
import Server from "../../src/Server.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

async function listen(server: Server): Promise<number> {
    server.listen({ host: "127.0.0.1", port: 0 })
    await new Promise<void>((resolve) => server.server!.once("listening", resolve))
    return (server.server!.address() as AddressInfo).port
}

async function close(server: Server): Promise<void> {
    for (const connection of server.clients) connection.terminate()
    await new Promise<void>((resolve, reject) => {
        server.server!.close((error) => (error ? reject(error) : resolve()))
    })
}

describe("server SSH handshake deadlines", () => {
    test("closes a silent TCP peer before identification", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({ hostKeys: [hostKey], handshakeTimeout: 35 })
        const port = await listen(server)
        const serverError = new Promise<Error>((resolve) => {
            server.once("connection", (connection) => connection.once("error", resolve))
        })
        const socket = createConnection({ host: "127.0.0.1", port })
        socket.on("error", () => undefined)
        const socketClosed = new Promise<void>((resolve) => socket.once("close", resolve))

        try {
            expect((await serverError).message).toBe("Timed out while waiting for SSH handshake")
            await socketClosed
            expect(server.clients.size).toBe(0)
        } finally {
            socket.destroy()
            await close(server)
        }
    }, 15_000)

    test("hands off to the authentication deadline after accepting the service", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({
            hostKeys: [hostKey],
            sendAllHostKeys: false,
            handshakeTimeout: 35,
            authenticationTimeout: 500,
            algorithms: { kex: ["curve25519-sha256"] },
        })
        server.hooker.hook("noneAuthentication", async (_hook, _context, decision) => {
            await new Promise<void>((resolve) => setTimeout(resolve, 70))
            decision.allowLogin = true
        })
        const port = await listen(server)
        const client = new Client({
            hostname: "127.0.0.1",
            port,
            username: "deadline-handoff",
            authenticationMethodsOrder: [SSHAuthenticationMethods.None],
            algorithms: { kex: ["curve25519-sha256"] },
        })
        client.hooker.hook("hostKey", (_hook, decision) => {
            decision.allowHostKey = true
        })

        try {
            await client.connect()
            expect(client.isConnected).toBe(true)
        } finally {
            client.destroy()
            await close(server)
        }
    }, 15_000)

    test("validates the server handshake deadline", () => {
        expect(() => new Server({ handshakeTimeout: -1 })).toThrow(
            "SSH handshake timeout must be an integer between 0 and 2147483647",
        )
    })
})
