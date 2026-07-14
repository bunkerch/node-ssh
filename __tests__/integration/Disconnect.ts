import { AddressInfo } from "node:net"
import Client from "../../src/Client.js"
import { SSHAuthenticationMethods } from "../../src/constants.js"
import Server from "../../src/Server.js"
import type ServerClient from "../../src/ServerClient.js"
import {
    DisconnectError,
    DisconnectReason,
    PeerDisconnectError,
    type PeerDisconnectInfo,
} from "../../src/packets/Disconnect.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

async function createConnectedPeers(): Promise<{
    server: Server
    peer: ServerClient
    client: Client
}> {
    const hostKey = await PrivateKey.generate("ssh-ed25519")
    const server = new Server({ hostKeys: [hostKey], sendAllHostKeys: false })
    server.hooker.hook("noneAuthentication", (_hook, _context, controller) => {
        controller.allowLogin = true
    })
    let peer: ServerClient | undefined
    server.on("connection", (connection) => {
        peer = connection
    })
    server.listen({ host: "127.0.0.1", port: 0 })
    await new Promise<void>((resolve) => server.server!.once("listening", resolve))

    const client = new Client({
        hostname: "127.0.0.1",
        port: (server.address() as AddressInfo).port,
        username: "disconnect-test",
        authenticationMethodsOrder: [SSHAuthenticationMethods.None],
    })
    client.hooker.hook("hostKey", (_hook, controller) => {
        controller.allowHostKey = true
    })
    await client.connect()
    return { server, peer: peer!, client }
}

async function closePeers(server: Server, client: Client): Promise<void> {
    client.destroy()
    for (const peer of server.clients) peer.terminate()
    await new Promise<void>((resolve) => server.close(() => resolve()))
}

describe("RFC 4253 peer disconnects", () => {
    test("rejects connection setup immediately when the peer disconnects", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({ hostKeys: [hostKey], sendAllHostKeys: false })
        server.on("connection", (peer) => {
            setImmediate(() =>
                peer.disconnect(
                    new DisconnectError(
                        DisconnectReason.SSH_DISCONNECT_SERVICE_NOT_AVAILABLE,
                        "authentication disabled",
                    ),
                ),
            )
        })
        server.listen({ host: "127.0.0.1", port: 0 })
        await new Promise<void>((resolve) => server.server!.once("listening", resolve))
        const client = new Client({
            hostname: "127.0.0.1",
            port: (server.address() as AddressInfo).port,
            username: "disconnect-test",
            readyTimeout: 5_000,
        })
        const started = Date.now()

        try {
            await expect(client.connect()).rejects.toMatchObject({
                name: "PeerDisconnectError",
                reasonCode: DisconnectReason.SSH_DISCONNECT_SERVICE_NOT_AVAILABLE,
                message: "authentication disabled",
            })
            expect(Date.now() - started).toBeLessThan(1_000)
        } finally {
            await closePeers(server, client)
        }
    }, 15_000)

    test("publishes server disconnect metadata and rejects pending client work", async () => {
        const { server, peer, client } = await createConnectedPeers()
        server.hooker.hook("globalRequest", async (_hook, context) => {
            if (context.name === "pending@example.test") await new Promise<never>(() => undefined)
        })
        const disconnect = new Promise<Readonly<PeerDisconnectInfo>>((resolve) => {
            client.once("disconnect", resolve)
        })
        const closed = new Promise<void>((resolve) => client.once("close", resolve))

        try {
            const pending = client.globalRequest("pending@example.test")
            await new Promise<void>((resolve) => setImmediate(resolve))
            peer.disconnect(
                new DisconnectError(DisconnectReason.SSH_DISCONNECT_BY_APPLICATION, "maintenance"),
            )

            const info = await disconnect
            expect(info).toEqual({
                reasonCode: DisconnectReason.SSH_DISCONNECT_BY_APPLICATION,
                description: "maintenance",
                languageTag: "",
            })
            expect(Object.isFrozen(info)).toBe(true)
            await expect(pending).rejects.toBeInstanceOf(PeerDisconnectError)
            await expect(pending).rejects.toMatchObject({
                reasonCode: DisconnectReason.SSH_DISCONNECT_BY_APPLICATION,
                message: "maintenance",
            })
            await closed
            expect(client.peerDisconnect).toBe(info)
        } finally {
            await closePeers(server, client)
        }
    }, 15_000)

    test("publishes a client disconnect to the server before close", async () => {
        const { server, peer, client } = await createConnectedPeers()
        const disconnect = new Promise<Readonly<PeerDisconnectInfo>>((resolve) => {
            peer.once("disconnect", resolve)
        })
        const closed = new Promise<void>((resolve) => peer.once("close", resolve))

        try {
            client.end()
            await expect(disconnect).resolves.toEqual({
                reasonCode: DisconnectReason.SSH_DISCONNECT_BY_APPLICATION,
                description: "",
                languageTag: "",
            })
            await closed
            expect(peer.peerDisconnect?.reasonCode).toBe(
                DisconnectReason.SSH_DISCONNECT_BY_APPLICATION,
            )
        } finally {
            await closePeers(server, client)
        }
    }, 15_000)

    test("gracefully ends a server connection with an application disconnect", async () => {
        const { server, peer, client } = await createConnectedPeers()
        const disconnect = new Promise<Readonly<PeerDisconnectInfo>>((resolve) => {
            client.once("disconnect", resolve)
        })
        const closed = new Promise<void>((resolve) => client.once("close", resolve))

        try {
            expect(peer.end()).toBe(peer)
            await expect(disconnect).resolves.toEqual({
                reasonCode: DisconnectReason.SSH_DISCONNECT_BY_APPLICATION,
                description: "",
                languageTag: "",
            })
            await closed
            expect(client.peerDisconnect?.reasonCode).toBe(
                DisconnectReason.SSH_DISCONNECT_BY_APPLICATION,
            )
        } finally {
            await closePeers(server, client)
        }
    }, 15_000)
})
