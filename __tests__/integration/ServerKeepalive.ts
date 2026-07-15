import { AddressInfo } from "node:net"
import Client from "../../src/Client.js"
import { SSHAuthenticationMethods } from "../../src/constants.js"
import Packet from "../../src/packet.js"
import RequestFailure from "../../src/packets/RequestFailure.js"
import Server from "../../src/Server.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

class UnresponsiveClient extends Client {
    sendPacket(packet: Packet): number {
        if (this.hasAuthenticated && packet instanceof RequestFailure) return -1
        return super.sendPacket(packet)
    }
}

async function startServer(options: {
    keepaliveInterval: number
    keepaliveCountMax: number
}): Promise<Server> {
    const hostKey = await PrivateKey.generate("ssh-ed25519")
    const server = new Server({
        hostKeys: [hostKey],
        sendAllHostKeys: false,
        replyTimeout: 5,
        ...options,
    })
    server.hooker.hook("noneAuthentication", (_hook, _context, decision) => {
        decision.allowLogin = true
    })
    server.listen({ host: "127.0.0.1", port: 0 })
    await new Promise<void>((resolve) => server.server!.once("listening", resolve))
    return server
}

function createClient<T extends Client>(
    ClientType: new (options: ConstructorParameters<typeof Client>[0]) => T,
    server: Server,
): T {
    const client = new ClientType({
        hostname: "127.0.0.1",
        port: (server.server!.address() as AddressInfo).port,
        username: "server-keepalive",
        authenticationMethodsOrder: [SSHAuthenticationMethods.None],
    })
    client.hooker.hook("hostKey", (_hook, decision) => {
        decision.allowHostKey = true
    })
    return client
}

async function close(server: Server, client: Client): Promise<void> {
    client.destroy()
    for (const connection of server.clients) connection.terminate()
    await new Promise<void>((resolve, reject) => {
        server.server!.close((error) => (error ? reject(error) : resolve()))
    })
}

describe("server SSH keepalives", () => {
    test("treats a failure reply as liveness and keeps probing", async () => {
        const server = await startServer({ keepaliveInterval: 10, keepaliveCountMax: 1 })
        const client = createClient(Client, server)
        let keepalives = 0
        const errors: Error[] = []
        client.on("packet", (metadata) => {
            if (metadata.name === "SSH_MSG_GLOBAL_REQUEST") keepalives++
        })
        server.on("connection", (connection) => {
            connection.on("error", (error) => errors.push(error))
        })

        try {
            await client.connect()
            await new Promise<void>((resolve) => setTimeout(resolve, 55))
            expect(keepalives).toBeGreaterThanOrEqual(2)
            expect(client.isConnected).toBe(true)
            expect(errors).toEqual([])
        } finally {
            await close(server, client)
        }
    }, 15_000)

    test("terminates a peer after the configured unanswered limit", async () => {
        const server = await startServer({ keepaliveInterval: 10, keepaliveCountMax: 1 })
        const client = createClient(UnresponsiveClient, server)
        const timeout = new Promise<Error>((resolve) => {
            server.on("connection", (connection) => {
                connection.on("error", (error) => {
                    if (error.message === "SSH keepalive timeout") resolve(error)
                })
            })
        })

        try {
            await client.connect()
            expect((await timeout).message).toBe("SSH keepalive timeout")
            await new Promise<void>((resolve) => client.once("close", resolve))
            expect(client.isConnected).toBe(false)
        } finally {
            await close(server, client)
        }
    }, 15_000)

    test("validates server keepalive limits", () => {
        expect(() => new Server({ keepaliveInterval: -1 })).toThrow("non-negative")
        expect(() => new Server({ keepaliveCountMax: 1.5 })).toThrow("non-negative integer")
    })
})
