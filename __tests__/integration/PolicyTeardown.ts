import { expect, test } from "bun:test"
import { once } from "node:events"
import type { AddressInfo } from "node:net"
import Client from "../../src/Client.js"
import Server from "../../src/Server.js"
import type ServerClient from "../../src/ServerClient.js"
import SessionChannel from "../../src/channels/SessionChannel.js"
import { SSHAuthenticationMethods } from "../../src/constants.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

test("server aborts a pending channel candidate when its connection closes", async () => {
    const server = new Server({
        hostKeys: [await PrivateKey.generate("ssh-ed25519")],
        sendAllHostKeys: false,
    })
    server.hooker.hook("noneAuthentication", (_hook, _context, controller) => {
        controller.allowLogin = true
    })

    let release!: () => void
    const policy = new Promise<void>((resolve) => {
        release = resolve
    })
    let startedResolve!: () => void
    const started = new Promise<void>((resolve) => {
        startedResolve = resolve
    })
    let finishedResolve!: () => void
    const finished = new Promise<void>((resolve) => {
        finishedResolve = resolve
    })
    let candidate: SessionChannel | undefined
    server.hooker.hook("channelOpenRequest", async (_hook, channel, controller) => {
        if (!(channel instanceof SessionChannel)) return
        candidate = channel
        startedResolve()
        await policy
        controller.allowOpen = true
        finishedResolve()
    })

    let peer: ServerClient | undefined
    let channelEvents = 0
    server.on("connection", (connection) => {
        peer = connection
        connection.on("channel", () => {
            channelEvents++
        })
    })
    server.listen({ host: "127.0.0.1", port: 0 })
    await once(server, "listening")

    const client = new Client({
        hostname: "127.0.0.1",
        port: (server.address() as AddressInfo).port,
        username: "policy-teardown-test",
        authenticationMethodsOrder: [SSHAuthenticationMethods.None],
    })
    client.hooker.hook("hostKey", (_hook, controller) => {
        controller.allowHostKey = true
    })

    try {
        await client.connect()
        const openResult = client.openSession().then(
            () => "unexpected success",
            (error: Error) => error.message,
        )
        await started

        const clientClosed = once(client, "close")
        const peerClosed = once(peer!, "close")
        client.destroy()
        await Promise.all([clientClosed, peerClosed])
        expect(await openResult).not.toBe("unexpected success")
        expect(candidate?.isOpen).toBe(false)

        release()
        await finished
        await new Promise<void>((resolve) => setImmediate(resolve))
        expect(channelEvents).toBe(0)
        expect(peer!.channels.size).toBe(0)
    } finally {
        release()
        client.destroy()
        peer?.terminate()
        await server.close()
    }
})

test("server rolls back a channel whose confirmation cannot be encoded", async () => {
    const server = new Server({
        hostKeys: [await PrivateKey.generate("ssh-ed25519")],
        sendAllHostKeys: false,
    })
    server.hooker.hook("noneAuthentication", (_hook, _context, controller) => {
        controller.allowLogin = true
    })

    let candidate: SessionChannel | undefined
    server.hooker.hook("channelOpenRequest", (_hook, channel, controller) => {
        if (!(channel instanceof SessionChannel)) return
        candidate = channel
        channel.local_initial_window_size = -1
        controller.allowOpen = true
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
        username: "confirmation-rollback-test",
        authenticationMethodsOrder: [SSHAuthenticationMethods.None],
    })
    client.hooker.hook("hostKey", (_hook, controller) => {
        controller.allowHostKey = true
    })

    try {
        await client.connect()
        await expect(client.openSession()).rejects.toMatchObject({ reasonCode: 2 })
        expect(candidate?.isOpen).toBe(false)
        expect(peer?.channels.size).toBe(0)
        expect(peer?.isConnected).toBe(true)
    } finally {
        client.destroy()
        peer?.terminate()
        await server.close()
    }
})

test("server never sends channel failure after publishing confirmation", async () => {
    const server = new Server({
        hostKeys: [await PrivateKey.generate("ssh-ed25519")],
        sendAllHostKeys: false,
    })
    server.hooker.hook("noneAuthentication", (_hook, _context, controller) => {
        controller.allowLogin = true
    })
    server.hooker.hook("channelOpenRequest", (_hook, channel, controller) => {
        controller.allowOpen = channel instanceof SessionChannel
    })

    const peerErrors: Error[] = []
    let peer: ServerClient | undefined
    server.on("connection", (connection) => {
        peer = connection
        connection.on("error", (error) => peerErrors.push(error))
        connection.on("channel", () => {
            throw new Error("channel observer failed")
        })
    })
    server.listen({ host: "127.0.0.1", port: 0 })
    await once(server, "listening")

    const client = new Client({
        hostname: "127.0.0.1",
        port: (server.address() as AddressInfo).port,
        username: "confirmation-publication-test",
        authenticationMethodsOrder: [SSHAuthenticationMethods.None],
    })
    client.hooker.hook("hostKey", (_hook, controller) => {
        controller.allowHostKey = true
    })
    client.on("error", () => undefined)
    const receivedPackets: string[] = []
    client.on("packet", ({ name }) => {
        if (name !== undefined) receivedPackets.push(name)
    })

    try {
        await client.connect()
        const closed = new Promise<void>((resolve) => client.once("close", resolve))
        await client.openSession().catch(() => undefined)
        await closed

        expect(
            receivedPackets.filter((name) => name === "SSH_MSG_CHANNEL_OPEN_CONFIRMATION"),
        ).toHaveLength(1)
        expect(receivedPackets).not.toContain("SSH_MSG_CHANNEL_OPEN_FAILURE")
        expect(peerErrors.map((error) => error.message)).toEqual(["channel observer failed"])
    } finally {
        client.destroy()
        peer?.terminate()
        await server.close()
    }
})

test("server never sends channel failure after publishing request success", async () => {
    const server = new Server({
        hostKeys: [await PrivateKey.generate("ssh-ed25519")],
        sendAllHostKeys: false,
    })
    server.hooker.hook("noneAuthentication", (_hook, _context, controller) => {
        controller.allowLogin = true
    })
    server.hooker.hook("channelOpenRequest", (_hook, channel, controller) => {
        controller.allowOpen = channel instanceof SessionChannel
    })

    const peerErrors: Error[] = []
    let peer: ServerClient | undefined
    server.on("connection", (connection) => {
        peer = connection
        connection.on("error", (error) => peerErrors.push(error))
        connection.on("channel", (channel) => {
            if (!(channel instanceof SessionChannel)) return
            channel.hooker.hook("execRequest", (_hook, _context, controller) => {
                controller.success = true
            })
            channel.events.on("exec", () => {
                throw new Error("exec observer failed")
            })
        })
    })
    server.listen({ host: "127.0.0.1", port: 0 })
    await once(server, "listening")

    const client = new Client({
        hostname: "127.0.0.1",
        port: (server.address() as AddressInfo).port,
        username: "request-publication-test",
        authenticationMethodsOrder: [SSHAuthenticationMethods.None],
    })
    client.hooker.hook("hostKey", (_hook, controller) => {
        controller.allowHostKey = true
    })
    client.on("error", () => undefined)
    const receivedPackets: string[] = []
    client.on("packet", ({ name }) => {
        if (name !== undefined) receivedPackets.push(name)
    })

    try {
        await client.connect()
        const channel = await client.openSession()
        const closed = new Promise<void>((resolve) => client.once("close", resolve))
        await channel.exec("true").catch(() => undefined)
        await closed

        expect(receivedPackets.filter((name) => name === "SSH_MSG_CHANNEL_SUCCESS")).toHaveLength(1)
        expect(receivedPackets).not.toContain("SSH_MSG_CHANNEL_FAILURE")
        expect(peerErrors.map((error) => error.message)).toEqual(["exec observer failed"])
    } finally {
        client.destroy()
        peer?.terminate()
        await server.close()
    }
})

test("server routes one-way session observer failures to connection errors", async () => {
    const server = new Server({
        hostKeys: [await PrivateKey.generate("ssh-ed25519")],
        sendAllHostKeys: false,
    })
    server.hooker.hook("noneAuthentication", (_hook, _context, controller) => {
        controller.allowLogin = true
    })
    server.hooker.hook("channelOpenRequest", (_hook, channel, controller) => {
        controller.allowOpen = channel instanceof SessionChannel
    })

    const peerErrors: Error[] = []
    let observerRanResolve!: () => void
    const observerRan = new Promise<void>((resolve) => {
        observerRanResolve = resolve
    })
    let peer: ServerClient | undefined
    server.on("connection", (connection) => {
        peer = connection
        connection.on("error", (error) => peerErrors.push(error))
        connection.on("channel", (channel) => {
            if (!(channel instanceof SessionChannel)) return
            channel.hooker.hook("execRequest", (_hook, _context, controller) => {
                controller.success = true
            })
            channel.events.on("windowChange", () => {
                observerRanResolve()
                throw new Error("window observer failed")
            })
        })
    })
    server.listen({ host: "127.0.0.1", port: 0 })
    await once(server, "listening")

    const client = new Client({
        hostname: "127.0.0.1",
        port: (server.address() as AddressInfo).port,
        username: "one-way-observer-test",
        authenticationMethodsOrder: [SSHAuthenticationMethods.None],
    })
    client.hooker.hook("hostKey", (_hook, controller) => {
        controller.allowHostKey = true
    })
    client.on("error", () => undefined)
    const receivedPackets: string[] = []
    client.on("packet", ({ name }) => {
        if (name !== undefined) receivedPackets.push(name)
    })

    try {
        await client.connect()
        const channel = await client.openSession()
        await channel.exec("true")
        const repliesBefore = receivedPackets.filter(
            (name) => name === "SSH_MSG_CHANNEL_SUCCESS" || name === "SSH_MSG_CHANNEL_FAILURE",
        ).length

        await channel.setWindow({ columns: 120, rows: 40 })
        await observerRan
        await new Promise<void>((resolve) => setImmediate(resolve))

        expect(peerErrors.map((error) => error.message)).toEqual(["window observer failed"])
        expect(peer?.isConnected).toBe(false)
        expect(
            receivedPackets.filter(
                (name) => name === "SSH_MSG_CHANNEL_SUCCESS" || name === "SSH_MSG_CHANNEL_FAILURE",
            ),
        ).toHaveLength(repliesBefore)
    } finally {
        client.destroy()
        peer?.terminate()
        await server.close()
    }
})
