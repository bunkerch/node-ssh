import { expect, test } from "bun:test"
import { once } from "node:events"
import type { AddressInfo } from "node:net"
import Client from "../../src/Client.js"
import Server from "../../src/Server.js"
import type ServerClient from "../../src/ServerClient.js"
import SessionChannel from "../../src/channels/SessionChannel.js"
import type Shell from "../../src/channels/Session/Shell.js"
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

test("destroying a server shell closes its SSH channel", async () => {
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
    let serverShell: Shell | undefined
    server.on("connection", (connection) => {
        peer = connection
        connection.on("channel", (channel) => {
            if (!(channel instanceof SessionChannel)) return
            channel.hooker.hook("execRequest", (_hook, _context, controller) => {
                controller.success = true
            })
            channel.events.on("exec", (_command, shell) => {
                serverShell = shell
            })
        })
    })
    server.listen({ host: "127.0.0.1", port: 0 })
    await once(server, "listening")

    const client = new Client({
        hostname: "127.0.0.1",
        port: (server.address() as AddressInfo).port,
        username: "shell-teardown-test",
        authenticationMethodsOrder: [SSHAuthenticationMethods.None],
    })
    client.hooker.hook("hostKey", (_hook, controller) => {
        controller.allowHostKey = true
    })

    try {
        await client.connect()
        const channel = await client.exec("destroy-shell")
        const closed = once(channel, "close")

        serverShell!.destroy()
        await within(closed, "client channel close")

        expect(channel.destroyed).toBe(true)
        expect(client.isConnected).toBe(true)
    } finally {
        client.destroy()
        peer?.terminate()
        await server.close()
    }
})
