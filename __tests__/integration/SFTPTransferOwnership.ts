import { once } from "node:events"
import { mkdtemp, rm } from "node:fs/promises"
import type { AddressInfo } from "node:net"
import { tmpdir } from "node:os"
import { join } from "node:path"
import Client from "../../src/Client.js"
import SessionChannel from "../../src/channels/SessionChannel.js"
import { SSHAuthenticationMethods } from "../../src/constants.js"
import Server from "../../src/Server.js"
import { SFTPStatusCode } from "../../src/sftp/constants.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

test("SFTP fastGet owns its remote path across stat and open requests", async () => {
    const directory = await mkdtemp(join(tmpdir(), "modernssh-fast-get-ownership-"))
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

    let releaseStat!: () => void
    const statReleased = new Promise<void>((resolve) => {
        releaseStat = resolve
    })
    let reportStat!: () => void
    const statReceived = new Promise<void>((resolve) => {
        reportStat = resolve
    })
    const receivedPaths: Buffer[] = []
    server.on("connection", (connection) => {
        connection.on("channel", (channel) => {
            if (!(channel instanceof SessionChannel)) return
            channel.hooker.hook("subsystemRequest", (_hook, context, controller) => {
                if (context.subsystem !== "sftp") return
                controller.success = true
                controller.sftp = {}
            })
            channel.events.on("sftp", (sftp) => {
                sftp.hooker.hook("STAT", async (_hook, request) => {
                    receivedPaths.push(Buffer.from(request.path))
                    reportStat()
                    await statReleased
                    sftp.attributes(request.requestId, { size: 0n })
                })
                sftp.hooker.hook("OPEN", async (_hook, request) => {
                    receivedPaths.push(Buffer.from(request.filename))
                    sftp.handle(request.requestId, Buffer.from("file-handle"))
                })
                sftp.hooker.hook("CLOSE", async (_hook, request) => {
                    sftp.status(request.requestId, SFTPStatusCode.Ok)
                })
            })
        })
    })

    server.listen({ host: "127.0.0.1", port: 0 })
    await once(server, "listening")
    const client = new Client({
        hostname: "127.0.0.1",
        port: (server.address() as AddressInfo).port,
        username: "sftp-fast-get-ownership",
        authenticationMethodsOrder: [SSHAuthenticationMethods.None],
        algorithms: { kex: ["curve25519-sha256"] },
    })
    client.hooker.hook("hostKey", (_hook, controller) => {
        controller.allowHostKey = true
    })

    try {
        await client.connect()
        const sftp = await client.sftp()
        const remotePath = Buffer.from("original-path")
        const transfer = sftp.fastGet(remotePath, join(directory, "download"))

        await statReceived
        remotePath.fill(0x78)
        releaseStat()
        await transfer

        expect(receivedPaths).toEqual([Buffer.from("original-path"), Buffer.from("original-path")])
        sftp.end()
    } finally {
        releaseStat()
        client.destroy()
        for (const connection of server.clients) connection.terminate()
        await server.close()
        await rm(directory, { recursive: true, force: true })
    }
}, 15_000)
