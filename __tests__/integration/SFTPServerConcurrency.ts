import { once } from "node:events"
import type { AddressInfo } from "node:net"
import { setTimeout as delay } from "node:timers/promises"
import Client from "../../src/Client.js"
import SessionChannel from "../../src/channels/SessionChannel.js"
import { SSHAuthenticationMethods } from "../../src/constants.js"
import Server from "../../src/Server.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

test("an SFTP server completes a later pipelined request while an earlier hook waits", async () => {
    const server = new Server({
        hostKeys: [await PrivateKey.generate("ssh-ed25519")],
        sendAllHostKeys: false,
        algorithms: { kex: ["curve25519-sha256"] },
    })
    server.hooker.hook("noneAuthentication", (_hook, _context, controller) => {
        controller.allowLogin = true
    })
    server.hooker.hook("channelOpenRequest", (_hook, channel, controller) => {
        controller.allowOpen = channel instanceof SessionChannel
    })

    let releaseSlow!: () => void
    const slowReleased = new Promise<void>((resolve) => {
        releaseSlow = resolve
    })
    let reportSlow!: () => void
    const slowStarted = new Promise<void>((resolve) => {
        reportSlow = resolve
    })
    let slowStarts = 0
    server.on("connection", (connection) => {
        connection.on("channel", (channel) => {
            if (!(channel instanceof SessionChannel)) return
            channel.hooker.hook("subsystemRequest", (_hook, context, controller) => {
                if (context.subsystem !== "sftp") return
                controller.success = true
                controller.sftp = { maxConcurrentRequests: 2 }
            })
            channel.events.on("sftp", (sftp) => {
                sftp.hooker.hook("STAT", async (_hook, request) => {
                    if (request.path.equals(Buffer.from("slow"))) {
                        slowStarts++
                        reportSlow()
                        await slowReleased
                    }
                    await sftp.attributes(request.requestId, {
                        size: request.path.equals(Buffer.from("slow")) ? 1n : 2n,
                    })
                })
            })
        })
    })

    server.listen({ host: "127.0.0.1", port: 0 })
    await once(server, "listening")
    const client = new Client({
        hostname: "127.0.0.1",
        port: (server.address() as AddressInfo).port,
        username: "sftp-concurrency",
        authenticationMethodsOrder: [SSHAuthenticationMethods.None],
        algorithms: { kex: ["curve25519-sha256"] },
    })
    client.hooker.hook("hostKey", (_hook, controller) => {
        controller.allowHostKey = true
    })

    try {
        await client.connect()
        const sftp = await client.sftp()
        const slow = sftp.stat("slow")
        await slowStarted
        const fast = sftp.stat("fast")
        const fastResult = await Promise.race([
            fast,
            delay(500).then(() => {
                throw new Error("Later SFTP request remained blocked behind an earlier hook")
            }),
        ])

        expect(fastResult.size).toBe(2n)
        const sameResource = sftp.stat("slow")
        const laterIndependent = await sftp.stat("later-independent")
        expect(laterIndependent.size).toBe(2n)
        expect(slowStarts).toBe(1)
        releaseSlow()
        expect((await slow).size).toBe(1n)
        expect((await sameResource).size).toBe(1n)
        expect(slowStarts).toBe(2)
        sftp.end()
    } finally {
        releaseSlow()
        client.destroy()
        for (const connection of server.clients) connection.terminate()
        await server.close()
    }
}, 15_000)
