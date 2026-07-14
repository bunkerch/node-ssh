import { once } from "node:events"
import { createConnection, createServer, type AddressInfo, type Socket } from "node:net"
import Client from "../../src/Client.js"
import Server from "../../src/Server.js"
import type ServerClient from "../../src/ServerClient.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

type Settlement =
    | { status: "fulfilled" }
    | { status: "rejected"; error: Error }
    | { status: "pending" }

async function settlementWithin(
    promise: Promise<unknown>,
    milliseconds: number,
): Promise<Settlement> {
    let timeout: ReturnType<typeof setTimeout> | undefined
    const settled = promise.then<Settlement>(
        () => ({ status: "fulfilled" }),
        (error: Error) => ({ status: "rejected", error }),
    )
    const pending = new Promise<Settlement>((resolve) => {
        timeout = setTimeout(() => resolve({ status: "pending" }), milliseconds)
    })
    try {
        return await Promise.race([settled, pending])
    } finally {
        if (timeout) clearTimeout(timeout)
    }
}

describe("SSH transport EOF", () => {
    test("rejects client setup immediately when an injected transport ends", async () => {
        let peer: Socket | undefined
        const transportServer = createServer({ allowHalfOpen: true }, (socket) => {
            peer = socket
        })
        transportServer.listen({ host: "127.0.0.1", port: 0 })
        await once(transportServer, "listening")

        const socket = createConnection({
            host: "127.0.0.1",
            port: (transportServer.address() as AddressInfo).port,
            allowHalfOpen: true,
        })
        await once(socket, "connect")
        while (!peer) await new Promise<void>((resolve) => setImmediate(resolve))

        const client = new Client({ sock: socket, readyTimeout: 5_000 })
        const ended = once(client, "end")
        const closed = once(client, "close")
        const connecting = client.connect()

        try {
            await new Promise<void>((resolve) => setImmediate(resolve))
            peer.end()
            await ended

            const settlement = await settlementWithin(connecting, 500)
            expect(settlement.status).toBe("rejected")
            if (settlement.status === "rejected") {
                expect(settlement.error.message).toContain("SSH connection closed")
            }
            await closed
        } finally {
            client.destroy()
            await connecting.catch(() => undefined)
            peer.destroy()
            socket.destroy()
            const serverClosed = once(transportServer, "close")
            transportServer.close()
            await serverClosed
        }
    }, 15_000)

    test("closes an injected server connection immediately when its transport ends", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({
            hostKeys: [hostKey],
            handshakeTimeout: 5_000,
        })
        const connection = once(server, "connection")
        let injectedSocket: Socket | undefined
        const transportServer = createServer({ allowHalfOpen: true }, (socket) => {
            // Bun does not currently propagate the server option to accepted sockets.
            socket.allowHalfOpen = true
            injectedSocket = socket
            server.injectSocket(socket)
        })
        transportServer.listen({ host: "127.0.0.1", port: 0 })
        await once(transportServer, "listening")

        const socket = createConnection({
            host: "127.0.0.1",
            port: (transportServer.address() as AddressInfo).port,
            allowHalfOpen: true,
        })
        await once(socket, "connect")
        const [peer] = (await connection) as [ServerClient]
        const ended = once(peer, "end")
        const closed = once(peer, "close")

        try {
            socket.end()
            await ended

            expect(injectedSocket?.allowHalfOpen).toBe(true)
            expect(injectedSocket?.writableEnded).toBe(false)
            expect((await settlementWithin(closed, 500)).status).toBe("fulfilled")
            expect(server.clients.size).toBe(0)
        } finally {
            peer.terminate()
            socket.destroy()
            const serverClosed = once(transportServer, "close")
            transportServer.close()
            await serverClosed
        }
    }, 15_000)
})
