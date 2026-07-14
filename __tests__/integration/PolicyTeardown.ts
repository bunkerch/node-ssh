import { expect, test } from "bun:test"
import { once } from "node:events"
import type { AddressInfo } from "node:net"
import Client from "../../src/Client.js"
import Server from "../../src/Server.js"
import type ServerClient from "../../src/ServerClient.js"
import SessionChannel from "../../src/channels/SessionChannel.js"
import { SSHAuthenticationMethods } from "../../src/constants.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

test("server discards a channel-open decision after connection close", async () => {
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
    server.hooker.hook("channelOpenRequest", async (_hook, channel, controller) => {
        if (!(channel instanceof SessionChannel)) return
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
