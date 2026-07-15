import { once } from "node:events"
import { mkdtemp, rm } from "node:fs/promises"
import type { AddressInfo } from "node:net"
import { tmpdir } from "node:os"
import { join } from "node:path"
import Client from "../../src/Client.js"
import Server from "../../src/Server.js"
import type ServerClient from "../../src/ServerClient.js"
import type ClientForwardedStreamLocalChannel from "../../src/channels/ClientForwardedStreamLocalChannel.js"
import type ClientForwardedTCPIPChannel from "../../src/channels/ClientForwardedTCPIPChannel.js"
import type ClientX11Channel from "../../src/channels/ClientX11Channel.js"
import SessionChannel from "../../src/channels/SessionChannel.js"
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

async function createConnectedPeers(maxChannels?: number): Promise<{
    server: Server
    peer: ServerClient
    client: Client
}> {
    const server = new Server({
        hostKeys: [await PrivateKey.generate("ssh-ed25519")],
        sendAllHostKeys: false,
        ...(maxChannels === undefined ? {} : { maxChannels }),
    })
    server.hooker.hook("noneAuthentication", (_hook, _context, controller) => {
        controller.allowLogin = true
    })
    server.hooker.hook("tcpipForward", (_hook, context, controller) => {
        controller.allow = context.bindAddress === "127.0.0.1"
    })
    server.hooker.hook("streamLocalForward", (_hook, _context, controller) => {
        controller.allow = true
    })
    server.hooker.hook("channelOpenRequest", (_hook, channel, controller) => {
        controller.allowOpen = channel instanceof SessionChannel
    })
    let peer: ServerClient | undefined
    server.on("connection", (connection) => {
        peer = connection
        connection.on("channel", (channel) => {
            if (!(channel instanceof SessionChannel)) return
            channel.hooker.hook("x11Request", (_hook, _request, controller) => {
                controller.success = true
            })
        })
    })
    server.listen({ host: "127.0.0.1", port: 0 })
    await once(server, "listening")

    const client = new Client({
        hostname: "127.0.0.1",
        port: (server.address() as AddressInfo).port,
        username: "incoming-channel-policy-test",
        authenticationMethodsOrder: [SSHAuthenticationMethods.None],
        strictVendor: false,
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

test("awaits client X11 policy before publishing the accepted channel", async () => {
    const { server, peer, client } = await createConnectedPeers()
    const session = await client.openSession()
    await session.requestX11()
    let releasePolicy!: () => void
    const policyBlocked = new Promise<void>((resolve) => {
        releasePolicy = resolve
    })
    let reportPolicyStarted!: () => void
    const policyStarted = new Promise<void>((resolve) => {
        reportPolicyStarted = resolve
    })
    client.hooker.hook("x11Connection", async (_hook, channel, controller) => {
        reportPolicyStarted()
        expect(channel.details).toEqual({
            originatorAddress: "192.0.2.40",
            originatorPort: 60_040,
        })
        await policyBlocked
        controller.allowOpen = true
    })
    const observed = once(client, "x11") as Promise<
        [details: Readonly<ClientX11Channel["details"]>, channel: ClientX11Channel]
    >

    try {
        let serverSettled = false
        const serverChannel = peer.x11("192.0.2.40", 60_040).finally(() => {
            serverSettled = true
        })
        void serverChannel.catch(() => undefined)
        await within(policyStarted, "X11 forwarding policy")
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
        session.close()
    } finally {
        releasePolicy()
        await closePeers(server, peer, client)
    }
}, 15_000)

test("preserves single X11 authorization across local validation failure", async () => {
    const { server, peer, client } = await createConnectedPeers()
    const session = await client.openSession()
    await session.requestX11({ single: true })
    client.hooker.hook("x11Connection", (_hook, _channel, controller) => {
        controller.allowOpen = true
    })

    try {
        await expect(peer.x11("\ud800", 60_040)).rejects.toThrow("not valid UTF-8")
        const channel = await peer.x11("192.0.2.40", 60_040)
        channel.close()
        await expect(peer.x11("192.0.2.41", 60_041)).rejects.toThrow(
            "has not authorized X11 forwarding",
        )
        session.close()
    } finally {
        await closePeers(server, peer, client)
    }
}, 15_000)

test("preserves single X11 authorization across local channel exhaustion", async () => {
    const { server, peer, client } = await createConnectedPeers(2)
    const session = await client.openSession()
    await session.requestX11({ single: true })
    const occupyingSession = await client.openSession()
    client.hooker.hook("x11Connection", (_hook, _channel, controller) => {
        controller.allowOpen = true
    })

    try {
        await expect(peer.x11("192.0.2.42", 60_042)).rejects.toThrow("simultaneous channel limit")
        occupyingSession.close()
        await within(
            (async () => {
                while (peer.channels.size > 1) {
                    await new Promise<void>((resolve) => setImmediate(resolve))
                }
            })(),
            "the occupying server channel to close",
        )
        const channel = await peer.x11("192.0.2.42", 60_042)
        channel.close()
        session.close()
    } finally {
        occupyingSession.close()
        await closePeers(server, peer, client)
    }
}, 15_000)

test("awaits client stream-local forwarding policy before publishing the channel", async () => {
    const directory = await mkdtemp(join(tmpdir(), "modernssh-incoming-policy-"))
    const socketPath = join(directory, "forwarded.sock")
    const { server, peer, client } = await createConnectedPeers()
    let releasePolicy!: () => void
    const policyBlocked = new Promise<void>((resolve) => {
        releasePolicy = resolve
    })
    let reportPolicyStarted!: () => void
    const policyStarted = new Promise<void>((resolve) => {
        reportPolicyStarted = resolve
    })
    client.hooker.hook("streamLocalConnection", async (_hook, channel, controller) => {
        reportPolicyStarted()
        expect(channel.details.socketPath).toBe(socketPath)
        await policyBlocked
        controller.allowOpen = true
    })
    const observed = once(client, "unix connection") as Promise<
        [
            details: Readonly<ClientForwardedStreamLocalChannel["details"]>,
            channel: ClientForwardedStreamLocalChannel,
        ]
    >

    try {
        await client.openssh_forwardInStreamLocal(socketPath)
        let serverSettled = false
        const serverChannel = peer.openssh_forwardOutStreamLocal(socketPath).finally(() => {
            serverSettled = true
        })
        void serverChannel.catch(() => undefined)
        await within(policyStarted, "stream-local forwarding policy")
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
        await rm(directory, { recursive: true, force: true })
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

test("returns localized stream-local policy denial without closing SSH", async () => {
    const directory = await mkdtemp(join(tmpdir(), "modernssh-incoming-policy-denial-"))
    const socketPath = join(directory, "forwarded.sock")
    const { server, peer, client } = await createConnectedPeers()
    client.hooker.hook("streamLocalConnection", async (_hook, _channel, controller) => {
        await Promise.resolve()
        controller.rejection = new ChannelOpenError(0xfe00_0004, "chemin interdit", "fr")
    })

    try {
        await client.openssh_forwardInStreamLocal(socketPath)
        await expect(peer.openssh_forwardOutStreamLocal(socketPath)).rejects.toMatchObject({
            name: "ChannelOpenError",
            reasonCode: 0xfe00_0004,
            message: "chemin interdit",
            languageTag: "fr",
        })
        expect(client.isConnected).toBe(true)
    } finally {
        await closePeers(server, peer, client)
        await rm(directory, { recursive: true, force: true })
    }
}, 15_000)

test("does not confirm a stream-local channel destroyed during admission policy", async () => {
    const directory = await mkdtemp(join(tmpdir(), "modernssh-incoming-policy-destroyed-"))
    const socketPath = join(directory, "forwarded.sock")
    const { server, peer, client } = await createConnectedPeers()
    let published = false
    client.on("unix connection", () => {
        published = true
    })
    client.hooker.hook("streamLocalConnection", async (_hook, channel) => {
        await Promise.resolve()
        channel.destroy()
    })
    client.hooker.hook("streamLocalConnection", (_hook, _channel, controller) => {
        controller.allowOpen = true
    })

    try {
        await client.openssh_forwardInStreamLocal(socketPath)
        await expect(peer.openssh_forwardOutStreamLocal(socketPath)).rejects.toMatchObject({
            reasonCode: 1,
            message: "Remote stream-local forwarding connection was rejected",
        })
        expect(published).toBe(false)
        expect(client.isConnected).toBe(true)
    } finally {
        await closePeers(server, peer, client)
        await rm(directory, { recursive: true, force: true })
    }
}, 15_000)

test("returns localized X11 policy denial without closing SSH", async () => {
    const { server, peer, client } = await createConnectedPeers()
    const session = await client.openSession()
    await session.requestX11()
    client.hooker.hook("x11Connection", async (_hook, _channel, controller) => {
        await Promise.resolve()
        controller.rejection = new ChannelOpenError(0xfe00_0005, "affichage interdit", "fr")
    })

    try {
        await expect(peer.x11("198.51.100.40", 60_041)).rejects.toMatchObject({
            name: "ChannelOpenError",
            reasonCode: 0xfe00_0005,
            message: "affichage interdit",
            languageTag: "fr",
        })
        expect(client.isConnected).toBe(true)
        session.close()
    } finally {
        await closePeers(server, peer, client)
    }
}, 15_000)

test("does not confirm an X11 channel destroyed during admission policy", async () => {
    const { server, peer, client } = await createConnectedPeers()
    const session = await client.openSession()
    await session.requestX11()
    let published = false
    client.on("x11", () => {
        published = true
    })
    client.hooker.hook("x11Connection", async (_hook, channel) => {
        await Promise.resolve()
        channel.destroy()
    })
    client.hooker.hook("x11Connection", (_hook, _channel, controller) => {
        controller.allowOpen = true
    })

    try {
        await expect(peer.x11("198.51.100.42", 60_043)).rejects.toMatchObject({
            reasonCode: 1,
            message: "X11 forwarding connection was rejected",
        })
        expect(published).toBe(false)
        expect(client.isConnected).toBe(true)
        session.close()
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

test("does not confirm a TCP channel destroyed during admission policy", async () => {
    const { server, peer, client } = await createConnectedPeers()
    const port = await client.forwardIn("127.0.0.1", 0)
    let published = false
    client.on("tcp connection", () => {
        published = true
    })
    client.hooker.hook("tcpConnection", async (_hook, channel) => {
        await Promise.resolve()
        channel.destroy()
    })
    client.hooker.hook("tcpConnection", (_hook, _channel, controller) => {
        controller.allowOpen = true
    })

    try {
        await expect(
            peer.forwardOut("127.0.0.1", port, "198.51.100.23", 51_238),
        ).rejects.toMatchObject({
            reasonCode: 1,
            message: "Remote forwarding connection was rejected",
        })
        expect(published).toBe(false)
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

test("discards a stream-local policy decision completed after transport teardown", async () => {
    const directory = await mkdtemp(join(tmpdir(), "modernssh-incoming-policy-teardown-"))
    const socketPath = join(directory, "forwarded.sock")
    const { server, peer, client } = await createConnectedPeers()
    let releasePolicy!: () => void
    const policyBlocked = new Promise<void>((resolve) => {
        releasePolicy = resolve
    })
    let reportPolicyStarted!: () => void
    const policyStarted = new Promise<void>((resolve) => {
        reportPolicyStarted = resolve
    })
    let proposedChannel: ClientForwardedStreamLocalChannel | undefined
    let published = false
    client.on("unix connection", () => {
        published = true
    })
    client.hooker.hook("streamLocalConnection", async (_hook, channel, controller) => {
        proposedChannel = channel
        reportPolicyStarted()
        await policyBlocked
        controller.allowOpen = true
    })

    try {
        await client.openssh_forwardInStreamLocal(socketPath)
        const serverChannel = peer.openssh_forwardOutStreamLocal(socketPath)
        void serverChannel.catch(() => undefined)
        await within(policyStarted, "blocked stream-local forwarding policy")
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
        await rm(directory, { recursive: true, force: true })
    }
}, 15_000)

test("discards an X11 policy decision completed after transport teardown", async () => {
    const { server, peer, client } = await createConnectedPeers()
    const session = await client.openSession()
    await session.requestX11()
    let releasePolicy!: () => void
    const policyBlocked = new Promise<void>((resolve) => {
        releasePolicy = resolve
    })
    let reportPolicyStarted!: () => void
    const policyStarted = new Promise<void>((resolve) => {
        reportPolicyStarted = resolve
    })
    let proposedChannel: ClientX11Channel | undefined
    let published = false
    client.on("x11", () => {
        published = true
    })
    client.hooker.hook("x11Connection", async (_hook, channel, controller) => {
        proposedChannel = channel
        reportPolicyStarted()
        await policyBlocked
        controller.allowOpen = true
    })

    try {
        const serverChannel = peer.x11("198.51.100.41", 60_042)
        void serverChannel.catch(() => undefined)
        await within(policyStarted, "blocked X11 forwarding policy")
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
