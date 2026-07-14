import { once } from "node:events"
import type { AddressInfo } from "node:net"
import Client from "../../src/Client.js"
import SessionChannel from "../../src/channels/SessionChannel.js"
import { SSHAuthenticationMethods } from "../../src/constants.js"
import Server from "../../src/Server.js"
import { SFTPStatusCode } from "../../src/sftp/constants.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

test("SFTP writes own handle and data buffers across acknowledged chunks", async () => {
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

    let releaseFirstWrite!: () => void
    const firstWriteReleased = new Promise<void>((resolve) => {
        releaseFirstWrite = resolve
    })
    let reportFirstWrite!: () => void
    const firstWriteReceived = new Promise<void>((resolve) => {
        reportFirstWrite = resolve
    })
    const received: { handle: Buffer; offset: bigint; data: Buffer }[] = []
    server.on("connection", (connection) => {
        connection.on("channel", (channel) => {
            if (!(channel instanceof SessionChannel)) return
            channel.hooker.hook("subsystemRequest", (_hook, context, controller) => {
                if (context.subsystem !== "sftp") return
                controller.success = true
                controller.sftp = {}
            })
            channel.events.on("sftp", (sftp) => {
                sftp.hooker.hook("WRITE", async (_hook, request) => {
                    received.push({
                        handle: Buffer.from(request.handle),
                        offset: request.offset,
                        data: Buffer.from(request.data),
                    })
                    if (received.length === 1) {
                        reportFirstWrite()
                        await firstWriteReleased
                    }
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
        username: "sftp-write-ownership",
        authenticationMethodsOrder: [SSHAuthenticationMethods.None],
        algorithms: { kex: ["curve25519-sha256"] },
    })
    client.hooker.hook("hostKey", (_hook, controller) => {
        controller.allowHostKey = true
    })

    try {
        await client.connect()
        const sftp = await client.sftp()
        sftp.maxWriteLength = 3
        const handle = Buffer.from("handle")
        const data = Buffer.from("abcdef")
        const writing = sftp.write(handle, data, 7n)

        await firstWriteReceived
        handle.fill(0x78)
        data.fill(0x7a)
        releaseFirstWrite()
        await writing

        expect(received).toEqual([
            { handle: Buffer.from("handle"), offset: 7n, data: Buffer.from("abc") },
            { handle: Buffer.from("handle"), offset: 10n, data: Buffer.from("def") },
        ])
        sftp.end()
    } finally {
        releaseFirstWrite()
        client.destroy()
        for (const connection of server.clients) connection.terminate()
        await server.close()
    }
}, 15_000)

test("SFTP writeFile owns buffer data while opening the remote file", async () => {
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

    let releaseOpen!: () => void
    const openReleased = new Promise<void>((resolve) => {
        releaseOpen = resolve
    })
    let reportOpen!: () => void
    const openReceived = new Promise<void>((resolve) => {
        reportOpen = resolve
    })
    let receivedData: Buffer | undefined
    server.on("connection", (connection) => {
        connection.on("channel", (channel) => {
            if (!(channel instanceof SessionChannel)) return
            channel.hooker.hook("subsystemRequest", (_hook, context, controller) => {
                if (context.subsystem !== "sftp") return
                controller.success = true
                controller.sftp = {}
            })
            channel.events.on("sftp", (sftp) => {
                sftp.hooker.hook("OPEN", async (_hook, request) => {
                    reportOpen()
                    await openReleased
                    sftp.handle(request.requestId, Buffer.from("file-handle"))
                })
                sftp.hooker.hook("WRITE", async (_hook, request) => {
                    receivedData = Buffer.from(request.data)
                    sftp.status(request.requestId, SFTPStatusCode.Ok)
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
        username: "sftp-write-file-ownership",
        authenticationMethodsOrder: [SSHAuthenticationMethods.None],
        algorithms: { kex: ["curve25519-sha256"] },
    })
    client.hooker.hook("hostKey", (_hook, controller) => {
        controller.allowHostKey = true
    })

    try {
        await client.connect()
        const sftp = await client.sftp()
        const data = Buffer.from("original contents")
        const writing = sftp.writeFile("remote-file", data)

        await openReceived
        data.fill(0x78)
        releaseOpen()
        await writing

        expect(receivedData).toEqual(Buffer.from("original contents"))
        sftp.end()
    } finally {
        releaseOpen()
        client.destroy()
        for (const connection of server.clients) connection.terminate()
        await server.close()
    }
}, 15_000)
