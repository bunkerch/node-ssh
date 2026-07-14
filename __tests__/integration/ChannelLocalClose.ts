import { expect, test } from "bun:test"
import { once } from "node:events"
import { createConnection, type AddressInfo, type Socket } from "node:net"
import { DEFAULT_SERVER_CHANNEL_WINDOW_SIZE } from "../../src/Channel.js"
import Client from "../../src/Client.js"
import Server from "../../src/Server.js"
import type ServerClient from "../../src/ServerClient.js"
import { DEFAULT_CHANNEL_WINDOW_SIZE } from "../../src/channels/ClientChannel.js"
import SessionChannel from "../../src/channels/SessionChannel.js"
import { SSHAuthenticationMethods } from "../../src/constants.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

function within<T>(promise: Promise<T>, label: string): Promise<T> {
    return new Promise<T>((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error(`Timed out waiting for ${label}`)), 250)
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

test("locally closing a channel rejects a flow-control-blocked write", async () => {
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

    let peer: ServerClient | undefined
    server.on("connection", (connection) => {
        peer = connection
    })
    server.listen({ host: "127.0.0.1", port: 0 })
    await once(server, "listening")

    const transport = createConnection({
        host: "127.0.0.1",
        port: (server.address() as AddressInfo).port,
    })
    await once(transport, "connect")
    const client = new Client({
        sock: transport,
        username: "local-channel-close-test",
        authenticationMethodsOrder: [SSHAuthenticationMethods.None],
    })
    client.hooker.hook("hostKey", (_hook, controller) => {
        controller.allowHostKey = true
    })

    try {
        await client.connect()
        const channel = await client.openSession()
        transport.pause()
        const pendingWrite = channel
            .sendData(Buffer.alloc(DEFAULT_SERVER_CHANNEL_WINDOW_SIZE + 1))
            .then(
                () => undefined,
                (error: Error) => error,
            )
        await new Promise<void>((resolve) => setImmediate(resolve))

        channel.close()
        const error = await within(pendingWrite, "locally closed channel write")

        expect(error).toBeInstanceOf(Error)
        expect(error?.message).toContain("closed during write")
        expect(channel.isOpen).toBe(false)
    } finally {
        transport.resume()
        client.destroy()
        peer?.terminate()
        await server.close()
    }
})

test("a server channel rejects a blocked write when it closes locally", async () => {
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

    let peer: ServerClient | undefined
    let serverChannel: SessionChannel | undefined
    let serverTransport: Socket | undefined
    server.server.on("connection", (socket) => {
        serverTransport = socket
    })
    server.on("connection", (connection) => {
        peer = connection
        connection.on("channel", (channel) => {
            if (channel instanceof SessionChannel) serverChannel = channel
        })
    })
    server.listen({ host: "127.0.0.1", port: 0 })
    await once(server, "listening")

    const client = new Client({
        hostname: "127.0.0.1",
        port: (server.address() as AddressInfo).port,
        username: "server-channel-close-test",
        authenticationMethodsOrder: [SSHAuthenticationMethods.None],
    })
    client.hooker.hook("hostKey", (_hook, controller) => {
        controller.allowHostKey = true
    })

    try {
        await client.connect()
        await client.openSession()
        serverTransport!.pause()
        const pendingWrite = serverChannel!
            .sendData(Buffer.alloc(DEFAULT_CHANNEL_WINDOW_SIZE + 1))
            .then(
                () => undefined,
                (error: Error) => error,
            )
        await new Promise<void>((resolve) => setImmediate(resolve))

        serverChannel!.close()
        const error = await within(pendingWrite, "locally closed server channel write")

        expect(error).toBeInstanceOf(Error)
        expect(error?.message).toContain("closed during write")
        expect(serverChannel!.isOpen).toBe(false)
    } finally {
        serverTransport?.resume()
        client.destroy()
        peer?.terminate()
        await server.close()
    }
})
