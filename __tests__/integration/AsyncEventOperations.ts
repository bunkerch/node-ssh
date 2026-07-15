import { once } from "node:events"
import type { AddressInfo } from "node:net"
import Client from "../../src/Client.js"
import { SSHAuthenticationMethods } from "../../src/constants.js"
import Server from "../../src/Server.js"
import type ServerClient from "../../src/ServerClient.js"
import GlobalRequest from "../../src/packets/GlobalRequest.js"
import { ActionQueue, ActionQueueCapacityError } from "../../src/utils/ActionQueue.js"
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

    test("closes on a one-way request backlog beyond the bounded action queue", async () => {
        const { client, peer, server } = await connectedPeers()
        peer.queue = new ActionQueue(1)
        let releaseRequest!: () => void
        const requestReleased = new Promise<void>((resolve) => {
            releaseRequest = resolve
        })
        let reportRequest!: () => void
        const requestStarted = new Promise<void>((resolve) => {
            reportRequest = resolve
        })
        server.hooker.hook("globalRequest", async () => {
            reportRequest()
            await requestReleased
        })
        const reported = once(peer, "error")
        const clientClosed = once(client, "close")

        try {
            client.sendPacket(
                new GlobalRequest({
                    request_name: "held@example.test",
                    want_reply: false,
                    args: Buffer.alloc(0),
                }),
            )
            await requestStarted
            for (const name of ["waiting@example.test", "overflow@example.test"]) {
                client.sendPacket(
                    new GlobalRequest({
                        request_name: name,
                        want_reply: false,
                        args: Buffer.alloc(0),
                    }),
                )
            }

            const [error] = await reported
            expect(error).toBeInstanceOf(ActionQueueCapacityError)
            expect(error.message).toBe("SSH action queue exceeds 1 waiting operations")
            await clientClosed
        } finally {
            releaseRequest()
            await closePeers(client, peer, server)
        }
    })

    test("discards an old async request decision after reconnecting the same client", async () => {
        const { client, peer, server } = await connectedPeers()
        let releaseOldRequest!: () => void
        const oldRequestReleased = new Promise<void>((resolve) => {
            releaseOldRequest = resolve
        })
        let reportOldRequest!: () => void
        const oldRequestStarted = new Promise<void>((resolve) => {
            reportOldRequest = resolve
        })
        client.hooker.hook("globalRequest", async (_hook, context, controller) => {
            if (context.name !== "old@example.test") return
            reportOldRequest()
            await oldRequestReleased
            controller.success = true
        })
        server.hooker.hook("globalRequest", (_hook, context, controller) => {
            if (context.name !== "new@example.test") return
            controller.success = true
            controller.response = Buffer.from("new connection")
        })

        try {
            const oldRequest = peer.globalRequest("old@example.test").then(
                () => undefined,
                (error: unknown) => error,
            )
            await oldRequestStarted
            const closed = once(client, "close")
            client.destroy()
            await closed
            expect(await oldRequest).toBeInstanceOf(Error)

            await client.connect()
            releaseOldRequest()
            await new Promise<void>((resolve) => setImmediate(resolve))
            expect(client.isConnected).toBe(true)
            await expect(client.globalRequest("new@example.test")).resolves.toEqual(
                Buffer.from("new connection"),
            )
        } finally {
            releaseOldRequest()
            await closePeers(client, peer, server)
        }
    }, 15_000)
})
