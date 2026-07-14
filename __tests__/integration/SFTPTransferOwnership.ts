import { once } from "node:events"
import { mkdtemp, rm, writeFile } from "node:fs/promises"
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

test("SFTP fastGet owns transfer options before awaiting stat", async () => {
    const directory = await mkdtemp(join(tmpdir(), "modernssh-fast-get-options-"))
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
    const source = Buffer.from("abcdef")
    const reads: { offset: bigint; length: number }[] = []
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
                    reportStat()
                    await statReleased
                    sftp.attributes(request.requestId, { size: BigInt(source.length) })
                })
                sftp.hooker.hook("OPEN", async (_hook, request) => {
                    sftp.handle(request.requestId, Buffer.from("file-handle"))
                })
                sftp.hooker.hook("READ", async (_hook, request) => {
                    reads.push({ offset: request.offset, length: request.length })
                    const offset = Number(request.offset)
                    sftp.data(request.requestId, source.subarray(offset, offset + request.length))
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
        username: "sftp-fast-get-options",
        authenticationMethodsOrder: [SSHAuthenticationMethods.None],
        algorithms: { kex: ["curve25519-sha256"] },
    })
    client.hooker.hook("hostKey", (_hook, controller) => {
        controller.allowHostKey = true
    })

    const progress: string[] = []
    const options = {
        chunkSize: 3,
        concurrency: 1,
        step(transferred: number, chunk: number, total: number) {
            progress.push(`original:${transferred}:${chunk}:${total}`)
        },
    }

    try {
        await client.connect()
        const sftp = await client.sftp()
        const transfer = sftp.fastGet("remote-file", join(directory, "download"), options)
        await statReceived
        options.chunkSize = 2
        options.concurrency = 2
        options.step = (transferred, chunk, total) => {
            progress.push(`mutated:${transferred}:${chunk}:${total}`)
        }
        releaseStat()
        await transfer

        expect({ reads, progress }).toEqual({
            reads: [
                { offset: 0n, length: 3 },
                { offset: 3n, length: 3 },
            ],
            progress: ["original:3:3:6", "original:6:3:6"],
        })
        sftp.end()
    } finally {
        releaseStat()
        client.destroy()
        for (const connection of server.clients) connection.terminate()
        await server.close()
        await rm(directory, { recursive: true, force: true })
    }
}, 15_000)

test("SFTP fastPut owns its remote path and mode before opening the local file", async () => {
    const directory = await mkdtemp(join(tmpdir(), "modernssh-fast-put-ownership-"))
    const localPath = join(directory, "upload")
    await writeFile(localPath, Buffer.alloc(0))
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

    let receivedOpen: { path: Buffer; permissions: number | undefined } | undefined
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
                    receivedOpen = {
                        path: Buffer.from(request.filename),
                        permissions: request.attributes.permissions,
                    }
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
        username: "sftp-fast-put-ownership",
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
        const options = { mode: 0o640 }
        const transfer = sftp.fastPut(localPath, remotePath, options)
        remotePath.fill(0x78)
        options.mode = 0o777
        await transfer

        expect(receivedOpen).toEqual({
            path: Buffer.from("original-path"),
            permissions: 0o640,
        })
        sftp.end()
    } finally {
        client.destroy()
        for (const connection of server.clients) connection.terminate()
        await server.close()
        await rm(directory, { recursive: true, force: true })
    }
}, 15_000)
