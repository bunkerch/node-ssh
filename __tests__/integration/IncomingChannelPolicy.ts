import { once } from "node:events"
import type { AddressInfo } from "node:net"
import Client from "../../src/Client.js"
import Server from "../../src/Server.js"
import type ServerClient from "../../src/ServerClient.js"
import type ClientForwardedTCPIPChannel from "../../src/channels/ClientForwardedTCPIPChannel.js"
import { SSHAuthenticationMethods } from "../../src/constants.js"
import { ChannelOpenError } from "../../src/packets/ChannelOpenFailure.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

function within<T>(promise: Promise<T>, label: string): Promise<T> {
    return new Promise<T>((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error(`Timed out waiting for ${label}`)), 500)
        timer.unref()
        promise.then(
            (value) => {
                clearTimeout(timer)
                resolve(value)
            },
            (error: unknown) => {
                clearTimeout(timer)
                reject(error as Error)
            },
        )
    })
}

async function createConnectedPeers(): Promise<{
    server: Server
    peer: ServerClient
    client: Client
}> {
    const server = new Server({
        hostKeys: [await PrivateKey.generate("ssh-ed25519")],
        sendAllHostKeys: false,
    })
    server.hooker.hook("noneAuthentication", (_hook, _context, controller) => {
        controller.allowLogin = true
    })
    server.hooker.hook("tcpipForward", (_hook, context, controller) => {
        controller.allow = context.bindAddress === "127.0.0.1"
    })
    let peer: ServerClient | undefined
    server.on("connection", (connection) => {
        peer = connection
    })
    server.listen({ host: "127.0.0.1", port: 0 })
    await once(server, "listening")

    const client = new Client({
        hostname: "127.0.0.1",
        port: (server.address() as AddressInfo).port,
        username: "incoming-channel-policy-test",
        authenticationMethodsOrder: [SSHAuthenticationMethods.None],
    })
    client.hooker.hook("hostKey", (_hook, controller) => {
        controller.allowHostKey = true
    })
    await client.connect()
    return { server, peer: peer!, client }
}

async function closePeers(server: Server, peer: ServerClient, client: Client): Promise<void> {
    client.destroy()
    peer.terminate()
    await server.close()
}

test("awaits client TCP forwarding policy before publishing the accepted channel", async () => {
    const { server, peer, client } = await createConnectedPeers()
    const port = await client.forwardIn("127.0.0.1", 0)
    let releasePolicy!: () => void
    const policyBlocked = new Promise<void>((resolve) => {
        releasePolicy = resolve
    })
    let reportPolicyStarted!: () => void
    const policyStarted = new Promise<void>((resolve) => {
        reportPolicyStarted = resolve
    })
    client.hooker.hook("tcpConnection", async (_hook, channel, controller) => {
        reportPolicyStarted()
        expect(channel.details.sourceHost).toBe("192.0.2.10")
        await policyBlocked
        controller.allowOpen = true
    })
    const observed = once(client, "tcp connection") as Promise<
        [
            details: Readonly<ClientForwardedTCPIPChannel["details"]>,
            channel: ClientForwardedTCPIPChannel,
        ]
    >

    try {
        let serverSettled = false
        const serverChannel = peer
            .forwardOut("127.0.0.1", port, "192.0.2.10", 51_234)
            .finally(() => {
                serverSettled = true
            })
        void serverChannel.catch(() => undefined)
        await within(policyStarted, "TCP forwarding policy")
        expect(serverSettled).toBe(false)

        releasePolicy()
        const [[details, clientChannel], acceptedServerChannel] = await Promise.all([
            observed,
            serverChannel,
        ])
        expect(details).toEqual(clientChannel.details)
        expect(clientChannel.isOpen).toBe(true)
        clientChannel.close()
        acceptedServerChannel.close()
    } finally {
        releasePolicy()
        await closePeers(server, peer, client)
    }
}, 15_000)

test("returns localized TCP policy denial without closing SSH", async () => {
    const { server, peer, client } = await createConnectedPeers()
    const port = await client.forwardIn("127.0.0.1", 0)
    client.hooker.hook("tcpConnection", async (_hook, _channel, controller) => {
        await Promise.resolve()
        controller.rejection = new ChannelOpenError(0xfe00_0002, "source interdite", "fr")
    })

    try {
        await expect(
            peer.forwardOut("127.0.0.1", port, "198.51.100.20", 51_235),
        ).rejects.toMatchObject({
            name: "ChannelOpenError",
            reasonCode: 0xfe00_0002,
            message: "source interdite",
            languageTag: "fr",
        })
        expect(client.isConnected).toBe(true)
    } finally {
        await closePeers(server, peer, client)
    }
}, 15_000)

test("contains a rejected TCP policy and discards an earlier approval", async () => {
    const { server, peer, client } = await createConnectedPeers()
    const port = await client.forwardIn("127.0.0.1", 0)
    const policyErrors: Error[] = []
    client.hooker.on("uncaughtException", (_event, error) => policyErrors.push(error))
    client.hooker.hook("tcpConnection", (_hook, _channel, controller) => {
        controller.allowOpen = true
        controller.rejection = new ChannelOpenError(0xfe00_0003, "stale approval", "en")
    })
    client.hooker.hook("tcpConnection", async () => {
        await Promise.resolve()
        throw new Error("TCP policy backend failed")
    })

    try {
        await expect(
            peer.forwardOut("127.0.0.1", port, "198.51.100.21", 51_236),
        ).rejects.toMatchObject({
            reasonCode: 1,
            message: "Remote forwarding connection was rejected",
            languageTag: "",
        })
        expect(policyErrors.map((error) => error.message)).toEqual(["TCP policy backend failed"])
        expect(client.isConnected).toBe(true)
    } finally {
        await closePeers(server, peer, client)
    }
}, 15_000)

test("discards a TCP policy decision completed after transport teardown", async () => {
    const { server, peer, client } = await createConnectedPeers()
    const port = await client.forwardIn("127.0.0.1", 0)
    let releasePolicy!: () => void
    const policyBlocked = new Promise<void>((resolve) => {
        releasePolicy = resolve
    })
    let reportPolicyStarted!: () => void
    const policyStarted = new Promise<void>((resolve) => {
        reportPolicyStarted = resolve
    })
    let proposedChannel: ClientForwardedTCPIPChannel | undefined
    let published = false
    client.on("tcp connection", () => {
        published = true
    })
    client.hooker.hook("tcpConnection", async (_hook, channel, controller) => {
        proposedChannel = channel
        reportPolicyStarted()
        await policyBlocked
        controller.allowOpen = true
    })

    try {
        const serverChannel = peer.forwardOut("127.0.0.1", port, "198.51.100.22", 51_237)
        void serverChannel.catch(() => undefined)
        await within(policyStarted, "blocked TCP forwarding policy")
        const closed = once(client, "close")
        client.destroy()
        await closed
        releasePolicy()

        await expect(serverChannel).rejects.toThrow("SSH connection closed")
        expect(proposedChannel?.destroyed).toBe(true)
        expect(published).toBe(false)
    } finally {
        releasePolicy()
        await closePeers(server, peer, client)
    }
}, 15_000)
