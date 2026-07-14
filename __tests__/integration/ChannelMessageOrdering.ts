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

test("client closes while an incoming request hook is pending", async () => {
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
        username: "channel-order-test",
        authenticationMethodsOrder: [SSHAuthenticationMethods.None],
    })
    client.hooker.hook("hostKey", (_hook, controller) => {
        controller.allowHostKey = true
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

    try {
        await client.connect()
        const channel = await client.openSession()
        channel.hooker.hook("request", async (_hook, context, controller) => {
            if (context.type !== "ordered@example.test") return
            startedResolve()
            await policy
            controller.success = true
            finishedResolve()
        })
        await channel.exec("ordered-close")

        const requestResult = serverShell!.channel
            .request("ordered@example.test", Buffer.from("before-close"))
            .then(
                () => "unexpected success",
                (error: Error) => error.message,
            )
        await started
        const clientData = once(channel, "data")
        await serverShell!.writeStdout(Buffer.from("while-policy"))
        expect((await clientData)[0]).toEqual(Buffer.from("while-policy"))

        const closed = once(channel, "close")
        serverShell!.close()
        await closed
        expect(channel.destroyed).toBe(true)
        expect(await requestResult).toBe(
            `SSH channel ${serverShell!.channel.localId} closed during request`,
        )

        release()
        await finished
        await new Promise<void>((resolve) => setImmediate(resolve))
        expect(client.isConnected).toBe(true)
    } finally {
        release()
        client.destroy()
        peer?.terminate()
        await server.close()
    }
})

test("server discards a session hook decision after channel close", async () => {
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

    let peer: ServerClient | undefined
    let serverSession: SessionChannel | undefined
    let execEvents = 0
    server.on("connection", (connection) => {
        peer = connection
        connection.on("channel", (channel) => {
            if (!(channel instanceof SessionChannel)) return
            serverSession = channel
            channel.hooker.hook("execRequest", async (_hook, _context, controller) => {
                startedResolve()
                await policy
                controller.success = true
                finishedResolve()
            })
            channel.events.on("exec", () => {
                execEvents++
            })
        })
    })
    server.listen({ host: "127.0.0.1", port: 0 })
    await once(server, "listening")

    const client = new Client({
        hostname: "127.0.0.1",
        port: (server.address() as AddressInfo).port,
        username: "channel-order-test",
        authenticationMethodsOrder: [SSHAuthenticationMethods.None],
    })
    client.hooker.hook("hostKey", (_hook, controller) => {
        controller.allowHostKey = true
    })

    try {
        await client.connect()
        const channel = await client.openSession()
        const execResult = channel.exec("late-exec").then(
            () => "unexpected success",
            (error: Error) => error.message,
        )
        await started

        const closed = once(channel, "close")
        channel.close()
        await closed
        expect(serverSession!.isOpen).toBe(false)
        expect(await execResult).toBe(`SSH channel ${channel.localId} closed during request`)

        release()
        await finished
        await new Promise<void>((resolve) => setImmediate(resolve))
        expect(serverSession!.shell).toBeUndefined()
        expect(execEvents).toBe(0)
        expect(client.isConnected).toBe(true)
    } finally {
        release()
        client.destroy()
        peer?.terminate()
        await server.close()
    }
})
