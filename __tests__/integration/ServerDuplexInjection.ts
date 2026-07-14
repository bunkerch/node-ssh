import { expect, test } from "bun:test"
import { once } from "node:events"
import type { AddressInfo } from "node:net"
import { PassThrough } from "node:stream"
import Client from "../../src/Client.js"
import Server from "../../src/Server.js"
import type ServerClient from "../../src/ServerClient.js"
import DirectTCPIPChannel from "../../src/channels/DirectTCPIPChannel.js"
import { SSHAuthenticationMethods } from "../../src/constants.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

function allowNoneAuthentication(server: Server): void {
    server.hooker.hook("noneAuthentication", (_hook, _context, controller) => {
        controller.allowLogin = true
    })
}

function trustHost(client: Client): void {
    client.hooker.hook("hostKey", (_hook, controller) => {
        controller.allowHostKey = true
    })
}

test("rejects a server transport that has already closed", async () => {
    const server = new Server({
        hostKeys: [await PrivateKey.generate("ssh-ed25519")],
        sendAllHostKeys: false,
    })
    server.hooker.hook("preconnect", () => undefined)
    const transport = new PassThrough()
    transport.destroy()
    await once(transport, "close")

    expect(() => server.injectSocket(transport)).toThrow(
        "SSH server transport must be open, readable, and writable",
    )
})

test("rejects a client transport that has already ended", async () => {
    const transport = new PassThrough({ autoDestroy: false })
    transport.resume()
    const ended = once(transport, "end")
    const finished = once(transport, "finish")
    transport.end()
    await Promise.all([ended, finished])
    expect(transport.destroyed).toBe(false)

    const client = new Client({ sock: transport, readyTimeout: 20 })
    client.on("error", () => undefined)
    await expect(client.connect()).rejects.toThrow(
        "The supplied SSH transport must be open, readable, and writable",
    )
    expect(client.canConnect).toBe(true)
    transport.destroy()
})

test("injects an SSH channel as a server transport", async () => {
    const outerServer = new Server({
        hostKeys: [await PrivateKey.generate("ssh-ed25519")],
        sendAllHostKeys: false,
    })
    const innerServer = new Server({
        hostKeys: [await PrivateKey.generate("ssh-ed25519")],
        sendAllHostKeys: false,
    })
    allowNoneAuthentication(outerServer)
    allowNoneAuthentication(innerServer)
    outerServer.hooker.hook("channelOpenRequest", (_hook, channel, controller) => {
        controller.allowOpen = channel instanceof DirectTCPIPChannel
    })

    let outerPeer: ServerClient | undefined
    let innerPeer: ServerClient | undefined
    outerServer.on("connection", (connection) => {
        outerPeer = connection
        connection.on("error", () => undefined)
        connection.on("channel", (channel) => {
            if (channel instanceof DirectTCPIPChannel) innerServer.injectSocket(channel.stream)
        })
    })
    innerServer.on("connection", (connection) => {
        innerPeer = connection
        connection.on("error", () => undefined)
    })

    outerServer.listen({ host: "127.0.0.1", port: 0 })
    await once(outerServer, "listening")
    const outerClient = new Client({
        hostname: "127.0.0.1",
        port: (outerServer.address() as AddressInfo).port,
        username: "outer",
        authenticationMethodsOrder: [SSHAuthenticationMethods.None],
    })
    trustHost(outerClient)
    let innerClient: Client | undefined

    try {
        await outerClient.connect()
        const tunnel = await outerClient.forwardOut("nested.example", 22, "127.0.0.1", 42_424)
        innerClient = new Client({
            sock: tunnel,
            username: "inner",
            authenticationMethodsOrder: [SSHAuthenticationMethods.None],
        })
        trustHost(innerClient)

        await innerClient.connect()

        expect(innerPeer?.setNoDelay(false)).toBe(innerPeer)
    } finally {
        innerClient?.destroy()
        outerClient.destroy()
        innerPeer?.terminate()
        outerPeer?.terminate()
        await outerServer.close()
    }
})
