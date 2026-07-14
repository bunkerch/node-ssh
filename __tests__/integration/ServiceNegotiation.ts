import { AddressInfo } from "node:net"
import Client from "../../src/Client.js"
import { SSHAuthenticationMethods } from "../../src/constants.js"
import Packet from "../../src/packet.js"
import { DisconnectReason, type PeerDisconnectInfo } from "../../src/packets/Disconnect.js"
import ServiceAccept from "../../src/packets/ServiceAccept.js"
import ServiceRequest from "../../src/packets/ServiceRequest.js"
import Server from "../../src/Server.js"
import type ServerClient from "../../src/ServerClient.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

class UnavailableServiceClient extends Client {
    sendPacket(packet: Packet): number {
        return super.sendPacket(
            packet instanceof ServiceRequest
                ? new ServiceRequest({ service_name: "unavailable@example.test" })
                : packet,
        )
    }
}

async function createServer(): Promise<Server> {
    const hostKey = await PrivateKey.generate("ssh-ed25519")
    const server = new Server({ hostKeys: [hostKey], sendAllHostKeys: false })
    server.hooker.hook("noneAuthentication", (_hook, _context, decision) => {
        decision.allowLogin = true
    })
    server.listen({ host: "127.0.0.1", port: 0 })
    await new Promise<void>((resolve) => server.server!.once("listening", resolve))
    return server
}

function createClient(server: Server): Client {
    const client = new Client({
        hostname: "127.0.0.1",
        port: (server.server!.address() as AddressInfo).port,
        username: "service-test",
        authenticationMethodsOrder: [SSHAuthenticationMethods.None],
    })
    client.hooker.hook("hostKey", (_hook, decision) => {
        decision.allowHostKey = true
    })
    return client
}

async function close(server: Server, ...clients: Client[]): Promise<void> {
    for (const client of clients) client.destroy()
    for (const connection of server.clients) connection.terminate()
    await new Promise<void>((resolve, reject) => {
        server.server!.close((error) => (error ? reject(error) : resolve()))
    })
}

describe("RFC 4253 service negotiation state", () => {
    test("disconnects with service-not-available for an unsupported request", async () => {
        const server = await createServer()
        const client = new UnavailableServiceClient({
            hostname: "127.0.0.1",
            port: (server.server!.address() as AddressInfo).port,
            username: "service-test",
            authenticationMethodsOrder: [SSHAuthenticationMethods.None],
        })
        client.hooker.hook("hostKey", (_hook, decision) => {
            decision.allowHostKey = true
        })
        const disconnected = new Promise<Readonly<PeerDisconnectInfo>>((resolve) => {
            client.once("disconnect", resolve)
        })

        try {
            await expect(client.connect()).rejects.toThrow("unavailable@example.test")
            expect(await disconnected).toEqual({
                reasonCode: DisconnectReason.SSH_DISCONNECT_SERVICE_NOT_AVAILABLE,
                description: "SSH service is not available: unavailable@example.test",
                languageTag: "",
            })
        } finally {
            await close(server, client)
        }
    }, 15_000)

    test("rejects an acceptance for a different service", async () => {
        const server = await createServer()
        let connection!: ServerClient
        const peerDisconnected = new Promise<Readonly<PeerDisconnectInfo>>((resolve) => {
            server.once("connection", (peer) => {
                connection = peer
                peer.once("disconnect", resolve)
                const sendPacket = peer.sendPacket.bind(peer)
                peer.sendPacket = (packet: Packet) =>
                    sendPacket(
                        packet instanceof ServiceAccept
                            ? new ServiceAccept({ service_name: "other@example.test" })
                            : packet,
                    )
            })
        })
        const client = createClient(server)

        try {
            await expect(client.connect()).rejects.toThrow()
            expect(await peerDisconnected).toEqual({
                reasonCode: DisconnectReason.SSH_DISCONNECT_PROTOCOL_ERROR,
                description: "SSH server accepted unexpected service other@example.test",
                languageTag: "",
            })
            expect(connection.peerDisconnect?.reasonCode).toBe(
                DisconnectReason.SSH_DISCONNECT_PROTOCOL_ERROR,
            )
        } finally {
            await close(server, client)
        }
    }, 15_000)

    test("rejects another client service request after authentication", async () => {
        const server = await createServer()
        const client = createClient(server)
        const disconnected = new Promise<Readonly<PeerDisconnectInfo>>((resolve) => {
            client.once("disconnect", resolve)
        })

        try {
            await client.connect()
            client.sendPacket(new ServiceRequest({ service_name: "ssh-userauth" }))
            expect((await disconnected).reasonCode).toBe(
                DisconnectReason.SSH_DISCONNECT_PROTOCOL_ERROR,
            )
        } finally {
            await close(server, client)
        }
    }, 15_000)

    test("rejects a server service acceptance after authentication", async () => {
        const server = await createServer()
        let connection!: ServerClient
        const connectionReady = new Promise<void>((resolve) => {
            server.once("connection", (peer) => {
                connection = peer
                peer.once("connect", resolve)
            })
        })
        const client = createClient(server)
        const peerDisconnected = new Promise<Readonly<PeerDisconnectInfo>>((resolve) => {
            server.on("connection", (peer) => peer.once("disconnect", resolve))
        })

        try {
            await client.connect()
            await connectionReady
            connection.sendPacket(new ServiceAccept({ service_name: "ssh-userauth" }))
            expect((await peerDisconnected).reasonCode).toBe(
                DisconnectReason.SSH_DISCONNECT_PROTOCOL_ERROR,
            )
        } finally {
            await close(server, client)
        }
    }, 15_000)
})
