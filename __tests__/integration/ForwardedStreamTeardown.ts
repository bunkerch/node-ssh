import { expect, test } from "bun:test"
import { once } from "node:events"
import type { AddressInfo } from "node:net"
import Client from "../../src/Client.js"
import Server from "../../src/Server.js"
import type ServerClient from "../../src/ServerClient.js"
import type ClientForwardedTCPIPChannel from "../../src/channels/ClientForwardedTCPIPChannel.js"
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

test("destroying a server forwarding stream closes its SSH channel", async () => {
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
        username: "forwarded-stream-teardown-test",
        authenticationMethodsOrder: [SSHAuthenticationMethods.None],
    })
    client.hooker.hook("hostKey", (_hook, controller) => {
        controller.allowHostKey = true
    })

    try {
        await client.connect()
        const forwardedPort = await client.forwardIn("127.0.0.1", 0)
        client.hooker.hook("tcpConnection", (_hook, _channel, controller) => {
            controller.allowOpen = true
        })
        let clientChannel: ClientForwardedTCPIPChannel | undefined
        client.once("tcp connection", (_details, channel) => {
            clientChannel = channel
        })
        const serverChannel = await peer!.forwardOut(
            "127.0.0.1",
            forwardedPort,
            "192.0.2.50",
            51_234,
        )
        expect(clientChannel).toBeDefined()
        const clientClosed = once(clientChannel!, "close")

        serverChannel.stream.destroy()
        await within(clientClosed, "client forwarding channel close")

        expect(clientChannel!.destroyed).toBe(true)
        expect(client.isConnected).toBe(true)
    } finally {
        client.destroy()
        peer?.terminate()
        await server.close()
    }
})
