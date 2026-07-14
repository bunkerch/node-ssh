import { AddressInfo } from "node:net"
import Client from "../../src/Client.js"
import { SSHAuthenticationMethods, SSHServiceNames } from "../../src/constants.js"
import { DisconnectReason, type PeerDisconnectInfo } from "../../src/packets/Disconnect.js"
import GlobalRequest from "../../src/packets/GlobalRequest.js"
import UserAuthBanner from "../../src/packets/UserAuthBanner.js"
import UserAuthRequest, { UnknownAuthMethod } from "../../src/packets/UserAuthRequest.js"
import Server from "../../src/Server.js"
import type ServerClient from "../../src/ServerClient.js"
import PrivateKey from "../../src/utils/PrivateKey.js"
import NewKeys from "../../src/packets/NewKeys.js"
import KexDHInit from "../../src/packets/KexDHInit.js"
import KexInit from "../../src/packets/KexInit.js"

async function listen(server: Server): Promise<number> {
    server.listen({ host: "127.0.0.1", port: 0 })
    await new Promise<void>((resolve) => server.server!.once("listening", resolve))
    return (server.server!.address() as AddressInfo).port
}

function clientFor(port: number): Client {
    const client = new Client({
        hostname: "127.0.0.1",
        port,
        username: "phase-test",
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

function peerDisconnect(peer: Client | ServerClient): Promise<Readonly<PeerDisconnectInfo>> {
    return new Promise((resolve) => peer.once("disconnect", resolve))
}

describe("RFC higher-layer message phases", () => {
    test.each(["client", "server"] as const)(
        "rejects premature NEWKEYS from the %s before fresh keys are derived",
        async (sender) => {
            const hostKey = await PrivateKey.generate("ssh-ed25519")
            const server = new Server({
                hostKeys: [hostKey],
                sendAllHostKeys: false,
                algorithms: { kex: ["curve25519-sha256"] },
            })
            let connection!: ServerClient
            let resolveDisconnect!: (info: Readonly<PeerDisconnectInfo>) => void
            const disconnected = new Promise<Readonly<PeerDisconnectInfo>>((resolve) => {
                resolveDisconnect = resolve
            })
            const client = clientFor(await listen(server))
            client.on("error", () => undefined)
            if (sender === "client") client.once("disconnect", resolveDisconnect)
            const appendPrematureNewKeys = (peer: Client | ServerClient) => {
                const transport = peer as unknown as {
                    sendPacket: (packet: Packet) => number
                }
                const sendPacket = transport.sendPacket.bind(peer)
                transport.sendPacket = (packet) => {
                    if (packet instanceof KexInit) {
                        packet.data.kex_algorithms = packet.data.kex_algorithms.filter(
                            (name) => !name.startsWith("kex-strict-"),
                        )
                    }
                    const sequence = sendPacket(packet)
                    if (packet instanceof KexInit) sendPacket(new NewKeys({}))
                    return sequence
                }
            }
            if (sender === "client") appendPrematureNewKeys(client)
            server.once("connection", (peer) => {
                connection = peer
                peer.on("error", () => undefined)
                if (sender === "server") peer.once("disconnect", resolveDisconnect)
                if (sender === "server") appendPrematureNewKeys(peer)
            })

            try {
                await expect(client.connect()).rejects.toThrow()
                await expect(disconnected).resolves.toMatchObject({
                    reasonCode: DisconnectReason.SSH_DISCONNECT_PROTOCOL_ERROR,
                    description: `SSH ${sender} sent NEWKEYS before fresh inbound keys were ready`,
                })
            } finally {
                await close(server, client)
                expect(connection).toBeDefined()
            }
        },
        15_000,
    )

    test.each([
        ["client", "NEWKEYS"],
        ["server", "NEWKEYS"],
        ["client", "method-specific"],
        ["server", "method-specific"],
    ] as const)(
        "rejects a %s %s packet outside key exchange",
        async (sender, packetKind) => {
            const hostKey = await PrivateKey.generate("ssh-ed25519")
            const server = new Server({ hostKeys: [hostKey], sendAllHostKeys: false })
            server.hooker.hook("noneAuthentication", (_hook, _context, decision) => {
                decision.allowLogin = true
            })
            let connection!: ServerClient
            server.once("connection", (peer) => {
                connection = peer
            })
            const client = clientFor(await listen(server))

            try {
                await client.connect()
                const disconnected = peerDisconnect(sender === "client" ? client : connection)
                const packet =
                    packetKind === "NEWKEYS"
                        ? new NewKeys({})
                        : new KexDHInit({ e: Buffer.alloc(32, 0x42), encoding: "string" })
                if (sender === "client") client.sendPacket(packet)
                else connection.sendPacket(packet)
                await expect(disconnected).resolves.toMatchObject({
                    reasonCode: DisconnectReason.SSH_DISCONNECT_PROTOCOL_ERROR,
                    description: `SSH ${sender} sent a key-exchange message outside key exchange`,
                })
            } finally {
                await close(server, client)
            }
        },
        15_000,
    )

    test.each(["client", "server"] as const)(
        "rejects an authentication message from the %s after login",
        async (sender) => {
            const hostKey = await PrivateKey.generate("ssh-ed25519")
            const server = new Server({ hostKeys: [hostKey], sendAllHostKeys: false })
            server.hooker.hook("noneAuthentication", (_hook, _context, decision) => {
                decision.allowLogin = true
            })
            let connection!: ServerClient
            server.once("connection", (peer) => {
                connection = peer
            })
            const client = clientFor(await listen(server))

            try {
                await client.connect()
                if (sender === "client") {
                    const disconnected = peerDisconnect(client)
                    client.sendPacket(
                        new UserAuthRequest({
                            username: "phase-test",
                            service_name: SSHServiceNames.Connection,
                            method: new UnknownAuthMethod("none", Buffer.alloc(0)),
                        }),
                    )
                    expect((await disconnected).reasonCode).toBe(
                        DisconnectReason.SSH_DISCONNECT_PROTOCOL_ERROR,
                    )
                } else {
                    const disconnected = peerDisconnect(connection)
                    connection.sendPacket(new UserAuthBanner({ message: "late", languageTag: "" }))
                    expect((await disconnected).reasonCode).toBe(
                        DisconnectReason.SSH_DISCONNECT_PROTOCOL_ERROR,
                    )
                }
            } finally {
                await close(server, client)
            }
        },
        15_000,
    )

    test.each(["client", "server"] as const)(
        "rejects a connection-layer message from the %s before login",
        async (sender) => {
            const hostKey = await PrivateKey.generate("ssh-ed25519")
            const server = new Server({ hostKeys: [hostKey], sendAllHostKeys: false })
            let authenticationStarted!: () => void
            const started = new Promise<void>((resolve) => {
                authenticationStarted = resolve
            })
            server.hooker.hook("noneAuthentication", async (_hook, _context, decision, peer) => {
                authenticationStarted()
                if (sender === "server") {
                    peer.sendPacket(
                        new GlobalRequest({
                            request_name: "premature@example.test",
                            want_reply: false,
                            args: Buffer.alloc(0),
                        }),
                    )
                } else {
                    await new Promise<void>((resolve) => setTimeout(resolve, 25))
                }
                decision.allowLogin = true
            })
            let resolveServerDisconnect!: (info: Readonly<PeerDisconnectInfo>) => void
            const serverDisconnected = new Promise<Readonly<PeerDisconnectInfo>>((resolve) => {
                resolveServerDisconnect = resolve
            })
            server.once("connection", (peer) => {
                peer.once("disconnect", resolveServerDisconnect)
            })
            const client = clientFor(await listen(server))
            const disconnected = sender === "client" ? peerDisconnect(client) : serverDisconnected

            try {
                const connecting = client.connect()
                await started
                if (sender === "client") {
                    client.sendPacket(
                        new GlobalRequest({
                            request_name: "premature@example.test",
                            want_reply: false,
                            args: Buffer.alloc(0),
                        }),
                    )
                }
                await expect(connecting).rejects.toThrow()
                expect((await disconnected).reasonCode).toBe(
                    DisconnectReason.SSH_DISCONNECT_PROTOCOL_ERROR,
                )
            } finally {
                await close(server, client)
            }
        },
        15_000,
    )
})
