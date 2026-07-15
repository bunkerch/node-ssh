import { once } from "node:events"
import type { AddressInfo } from "node:net"
import Client from "../../src/Client.js"
import { SSHAuthenticationMethods } from "../../src/constants.js"
import Server from "../../src/Server.js"
import type ServerClient from "../../src/ServerClient.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

async function connectedPeers(): Promise<{
    client: Client
    peer: ServerClient
    server: Server
}> {
    const server = new Server({
        hostKeys: [await PrivateKey.generate("ssh-ed25519")],
        sendAllHostKeys: false,
    })
    server.hooker.hook("noneAuthentication", (_hook, _context, controller) => {
        controller.allowLogin = true
    })
    server.hooker.hook("channelOpenRequest", (_hook, _channel, controller) => {
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
        username: "packet-operation-test",
        authenticationMethodsOrder: [SSHAuthenticationMethods.None],
    })
    client.hooker.hook("hostKey", (_hook, controller) => {
        controller.allowHostKey = true
    })
    await client.connect()

    return { client, peer: peer!, server }
}

async function closePeers(client: Client, peer: ServerClient, server: Server): Promise<void> {
    client.destroy()
    peer.terminate()
    await server.close()
}

describe("asynchronous packet operation containment", () => {
    test("reports a rejected channel-open operation and closes the connection", async () => {
        const { client, peer, server } = await connectedPeers()
        const failure = new Error("channel-open queue failed")
        const reported = once(peer, "error")
        peer.queue.obtainLock = () => Promise.reject(failure)

        try {
            const opening = expect(client.openSession()).rejects.toThrow("SSH connection closed")
            const [error] = await reported

            expect(error).toBe(failure)
            await opening
        } finally {
            await closePeers(client, peer, server)
        }
    })

    test("reports a rejected channel-request operation and closes the connection", async () => {
        const { client, peer, server } = await connectedPeers()
        const channel = await client.openSession()
        const failure = new Error("channel-request queue failed")
        const reported = once(peer, "error")
        peer.queue.obtainLock = () => Promise.reject(failure)

        try {
            const request = expect(channel.exec("true")).rejects.toThrow("SSH connection closed")
            const [error] = await reported

            expect(error).toBe(failure)
            await request
        } finally {
            await closePeers(client, peer, server)
        }
    })
})
