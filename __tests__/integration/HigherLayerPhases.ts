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
import KexDHGexRequest from "../../src/packets/KexDHGexRequest.js"
import KexDHReply from "../../src/packets/KexDHReply.js"
import RequestSuccess from "../../src/packets/RequestSuccess.js"
import RequestFailure from "../../src/packets/RequestFailure.js"

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
    test.each([
        ["success", "client"],
        ["success", "server"],
        ["failure", "client"],
        ["failure", "server"],
    ] as const)(
        "rejects an unsolicited global-request %s from the %s",
        async (response, sender) => {
            const hostKey = await PrivateKey.generate("ssh-ed25519")
            const server = new Server({ hostKeys: [hostKey], sendAllHostKeys: false })
            server.hooker.hook("noneAuthentication", (_hook, _context, decision) => {
                decision.allowLogin = true
            })
            let connection!: ServerClient
            server.once("connection", (peer) => {
                connection = peer
                peer.on("error", () => undefined)
            })
            const client = clientFor(await listen(server))

            try {
                await client.connect()
                const disconnected = peerDisconnect(sender === "client" ? client : connection)
                const packet =
                    response === "success"
                        ? new RequestSuccess({ args: Buffer.from("unsolicited") })
                        : new RequestFailure({})
                if (sender === "client") client.sendPacket(packet)
                else connection.sendPacket(packet)
                await expect(disconnected).resolves.toMatchObject({
                    reasonCode: DisconnectReason.SSH_DISCONNECT_PROTOCOL_ERROR,
                    description: "Received an unexpected SSH global request response",
                })
            } finally {
                await close(server, client)
            }
        },
        15_000,
    )

    test.each(["client", "server"] as const)(
        "discards one incorrect optimistic KEX guess from the %s",
        async (sender) => {
            const hostKey = await PrivateKey.generate("ssh-ed25519")
            const server = new Server({
                hostKeys: [hostKey],
                sendAllHostKeys: false,
                algorithms: {
                    kex:
                        sender === "server"
                            ? ["ecdh-sha2-nistp256", "curve25519-sha256"]
                            : ["curve25519-sha256"],
                },
            })
            server.hooker.hook("noneAuthentication", (_hook, _context, decision) => {
                decision.allowLogin = true
            })
            const client = new Client({
                hostname: "127.0.0.1",
                port: await listen(server),
                username: "phase-test",
                authenticationMethodsOrder: [SSHAuthenticationMethods.None],
                algorithms: {
                    kex:
                        sender === "client"
                            ? ["ecdh-sha2-nistp256", "curve25519-sha256"]
                            : ["curve25519-sha256"],
                },
            })
            client.hooker.hook("hostKey", (_hook, decision) => {
                decision.allowHostKey = true
            })
            const appendWrongGuess = (peer: Client | ServerClient) => {
                const transport = peer as unknown as {
                    sendPacket: (packet: Packet) => number
                }
                const sendPacket = transport.sendPacket.bind(peer)
                transport.sendPacket = (packet) => {
                    if (!(packet instanceof KexInit)) return sendPacket(packet)
                    packet.data.first_kex_packet_follows = true
                    packet.data.kex_algorithms = packet.data.kex_algorithms.filter(
                        (name) => !name.startsWith("kex-strict-"),
                    )
                    const sequence = sendPacket(packet)
                    sendPacket(
                        sender === "client"
                            ? new KexDHInit({ e: Buffer.alloc(65, 0x41), encoding: "string" })
                            : new KexDHReply({
                                  K_S: Buffer.from("guessed-host-key"),
                                  f: Buffer.alloc(65, 0x42),
                                  H_sig: Buffer.from("guessed-signature"),
                                  encoding: "string",
                              }),
                    )
                    return sequence
                }
            }
            if (sender === "client") appendWrongGuess(client)
            server.once("connection", (peer) => {
                peer.on("error", () => undefined)
                if (sender === "server") appendWrongGuess(peer)
            })

            try {
                await client.connect()
                expect(client.isConnected).toBe(true)
                expect(client.sessionID).toBeDefined()
            } finally {
                await close(server, client)
            }
        },
        15_000,
    )

    test.each([
        ["client", "premature NEWKEYS"],
        ["server", "premature NEWKEYS"],
        ["client", "out-of-order method packet"],
        ["server", "out-of-order method packet"],
    ] as const)(
        "rejects %s %s during key exchange",
        async (sender, violation) => {
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
                    if (packet instanceof KexInit) {
                        sendPacket(
                            violation === "premature NEWKEYS"
                                ? new NewKeys({})
                                : new KexDHGexRequest({
                                      min: 2048,
                                      preferred: 3072,
                                      max: 8192,
                                  }),
                        )
                    }
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
                    description:
                        violation === "premature NEWKEYS"
                            ? `SSH ${sender} sent NEWKEYS before fresh inbound keys were ready`
                            : `SSH ${sender} sent an out-of-order key-exchange message`,
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
        "rejects higher-layer traffic sent by the %s after KEXINIT",
        async (sender) => {
            const hostKey = await PrivateKey.generate("ssh-ed25519")
            const server = new Server({ hostKeys: [hostKey], sendAllHostKeys: false })
            server.hooker.hook("noneAuthentication", (_hook, _context, decision) => {
                decision.allowLogin = true
            })
            let connection!: ServerClient
            server.once("connection", (peer) => {
                connection = peer
                peer.on("error", () => undefined)
            })
            const client = clientFor(await listen(server))
            client.on("error", () => undefined)

            try {
                await client.connect()
                const sendingPeer = sender === "client" ? client : connection
                const transport = sendingPeer as unknown as {
                    sendPacket: (packet: Packet) => number
                    writePacket: (packet: Packet) => number
                }
                const sendPacket = transport.sendPacket.bind(sendingPeer)
                const writePacket = transport.writePacket.bind(sendingPeer)
                transport.sendPacket = (packet) => {
                    const sequence = sendPacket(packet)
                    if (packet instanceof KexInit) {
                        writePacket(
                            new GlobalRequest({
                                request_name: "forbidden@example.test",
                                want_reply: false,
                                args: Buffer.from("after-kexinit"),
                            }),
                        )
                    }
                    return sequence
                }

                const disconnected = peerDisconnect(sendingPeer)
                const rekey = sendingPeer.rekey().catch((error: Error) => error)
                await expect(disconnected).resolves.toMatchObject({
                    reasonCode: DisconnectReason.SSH_DISCONNECT_PROTOCOL_ERROR,
                    description: `SSH ${sender} sent a non-key-exchange message after KEXINIT`,
                })
                expect(await rekey).toBeInstanceOf(Error)
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
