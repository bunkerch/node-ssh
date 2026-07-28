import { once } from "node:events"
import { createServer as createTCPServer, type AddressInfo, type Socket } from "node:net"
import { Duplex } from "node:stream"
import Client from "../../src/Client.js"
import Server from "../../src/Server.js"
import { SSHAuthenticationMethods } from "../../src/constants.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

async function createAuthenticatedServer(): Promise<Server> {
    const hostKey = await PrivateKey.generate("ssh-ed25519")
    const server = new Server({ hostKeys: [hostKey], sendAllHostKeys: false })
    server.hooker.hook("noneAuthentication", (_hook, _context, decision) => {
        decision.allowLogin = true
    })
    server.listen({ host: "127.0.0.1", port: 0 })
    await once(server, "listening")
    return server
}

describe("client lifecycle", () => {
    test("gracefully closes once and remains reusable", async () => {
        const server = await createAuthenticatedServer()
        const client = new Client({
            hostname: "127.0.0.1",
            port: (server.address() as AddressInfo).port,
            username: "lifecycle",
            authenticationMethodsOrder: [SSHAuthenticationMethods.None],
        })
        client.hooker.hook("hostKey", (_hook, decision) => {
            decision.allowHostKey = true
        })
        const observations: string[] = []
        client.on("close", () => observations.push("close"))

        try {
            await client.connect()
            const firstClose = client.close()
            expect(client.close()).toBe(firstClose)
            await firstClose
            expect(observations).toEqual(["close"])
            expect(client.canConnect).toBe(true)
            expect(client.isConnected).toBe(false)

            await client.connect()
            await client[Symbol.asyncDispose]()
            expect(observations).toEqual(["close", "close"])
            expect(client.canConnect).toBe(true)
            await client[Symbol.asyncDispose]()
        } finally {
            client.destroy()
            for (const connection of server.clients) connection.terminate()
            await server.close()
        }
    }, 15_000)

    test("cancels a connection attempt and waits for transport cleanup", async () => {
        const sockets = new Set<Socket>()
        let resolvePeerClose!: () => void
        const peerClose = new Promise<void>((resolve) => {
            resolvePeerClose = resolve
        })
        const server = createTCPServer((socket) => {
            sockets.add(socket)
            socket.on("close", () => {
                sockets.delete(socket)
                resolvePeerClose()
            })
        })
        server.listen(0, "127.0.0.1")
        await once(server, "listening")

        const client = new Client({
            hostname: "127.0.0.1",
            port: (server.address() as AddressInfo).port,
            username: "connecting-lifecycle",
            readyTimeout: 0,
        })
        const connecting = client.connect().then(
            () => undefined,
            (error: unknown) => error as Error,
        )
        await once(server, "connection")

        try {
            await client.close()
            expect((await connecting)?.message).toContain("SSH connection closed or was replaced")
            expect(client.canConnect).toBe(true)
            await peerClose
            expect(sockets.size).toBe(0)
        } finally {
            client.destroy()
            for (const socket of sockets) socket.destroy()
            await new Promise<void>((resolve, reject) => {
                server.close((error) => (error ? reject(error) : resolve()))
            })
        }
    })

    test("reports a transport failure only after close cleanup", async () => {
        class FailingCloseTransport extends Duplex {
            _read(): void {
                void this.readableLength
            }

            _write(
                _chunk: Buffer,
                _encoding: BufferEncoding,
                callback: (error?: Error | null) => void,
            ): void {
                callback()
            }

            _final(callback: (error?: Error | null) => void): void {
                callback(new Error("transport close failed"))
            }
        }

        const client = new Client({
            username: "failing-lifecycle",
            sock: new FailingCloseTransport(),
            readyTimeout: 0,
        })
        const connecting = client.connect().then(
            () => undefined,
            (error: unknown) => error as Error,
        )
        const observations: string[] = []
        client.on("close", () => observations.push("close"))

        await expect(client.close()).rejects.toThrow("transport close failed")
        expect(observations).toEqual(["close"])
        expect(client.canConnect).toBe(true)
        expect(await connecting).toBeInstanceOf(Error)
    })
})
