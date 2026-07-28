import { once } from "node:events"
import type { AddressInfo } from "node:net"
import Client from "../../src/Client.js"
import SessionChannel from "../../src/channels/SessionChannel.js"
import { SSHAuthenticationMethods } from "../../src/constants.js"
import Server from "../../src/Server.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

function neverSettles<T>(): Promise<T> {
    return new Promise<T>(() => undefined)
}

describe("RFC 4819 request deadlines", () => {
    test("closes only the timed-out subsystem channel and keeps SSH usable", async () => {
        const server = new Server({
            hostKeys: [await PrivateKey.generate("ssh-ed25519")],
            sendAllHostKeys: false,
        })
        server.hooker.hook("noneAuthentication", (_hook, _context, decision) => {
            decision.allowLogin = true
        })
        server.hooker.hook("channelOpenRequest", (_hook, channel, decision) => {
            decision.allowOpen = channel instanceof SessionChannel
        })
        server.on("connection", (connection) => {
            connection.on("channel", (channel) => {
                if (!(channel instanceof SessionChannel)) return
                channel.hooker.hook("subsystemRequest", (_hook, context, decision) => {
                    if (context.subsystem !== "publickey") return
                    decision.success = true
                    decision.publicKey = {}
                })
                channel.events.on("publicKey", (subsystem) => {
                    subsystem.hooker.hook("list", async () => neverSettles())
                })
            })
        })
        server.listen({ host: "127.0.0.1", port: 0 })
        await once(server, "listening")

        const client = new Client({
            hostname: "127.0.0.1",
            port: (server.address() as AddressInfo).port,
            username: "public-key-subsystem-timeout-test",
            authenticationMethodsOrder: [SSHAuthenticationMethods.None],
            replyTimeout: 2_345,
        })
        client.hooker.hook("hostKey", (_hook, decision) => {
            decision.allowHostKey = true
        })

        try {
            await client.connect()
            const options = { requestTimeout: 40 }
            const opening = client.publicKeySubsystem(options)
            options.requestTimeout = 9_999
            const subsystem = await opening
            expect(subsystem.requestTimeout).toBe(40)
            await expect(subsystem.list()).rejects.toThrow(
                "Timed out waiting for public-key subsystem request reply",
            )

            expect(subsystem.channel.destroyed).toBe(true)
            expect(client.isConnected).toBe(true)
            const replacement = await client.publicKeySubsystem()
            expect(replacement.requestTimeout).toBe(2_345)
            const replacementClosed = once(replacement.channel, "close")
            replacement.end()
            await replacementClosed
            expect(client.isConnected).toBe(true)
        } finally {
            client.destroy()
            await server.close()
        }
    })

    test("server request timeout closes only the public-key subsystem channel", async () => {
        const server = new Server({
            hostKeys: [await PrivateKey.generate("ssh-ed25519")],
            sendAllHostKeys: false,
        })
        server.hooker.hook("noneAuthentication", (_hook, _context, decision) => {
            decision.allowLogin = true
        })
        server.hooker.hook("channelOpenRequest", (_hook, channel, decision) => {
            decision.allowOpen = channel instanceof SessionChannel
        })
        let timeoutResolve!: (error: Error) => void
        const timedOut = new Promise<Error>((resolve) => {
            timeoutResolve = resolve
        })
        server.on("connection", (connection) => {
            connection.on("channel", (channel) => {
                if (!(channel instanceof SessionChannel)) return
                channel.hooker.hook("subsystemRequest", (_hook, context, decision) => {
                    if (context.subsystem !== "publickey") return
                    decision.success = true
                    decision.publicKey = { requestTimeout: 40 }
                })
                channel.events.on("publicKey", (subsystem) => {
                    subsystem.on("error", timeoutResolve)
                    subsystem.hooker.hook("list", async () => neverSettles())
                })
            })
        })
        server.listen({ host: "127.0.0.1", port: 0 })
        await once(server, "listening")

        const client = new Client({
            hostname: "127.0.0.1",
            port: (server.address() as AddressInfo).port,
            username: "public-key-server-timeout-test",
            authenticationMethodsOrder: [SSHAuthenticationMethods.None],
        })
        client.hooker.hook("hostKey", (_hook, decision) => {
            decision.allowHostKey = true
        })

        try {
            await client.connect()
            const subsystem = await client.publicKeySubsystem({ requestTimeout: 1_000 })
            await expect(subsystem.list()).rejects.toBeInstanceOf(Error)
            expect((await timedOut).message).toBe(
                "Timed out waiting for public-key subsystem server list",
            )

            expect(subsystem.channel.destroyed).toBe(true)
            expect(client.isConnected).toBe(true)
            const replacement = await client.publicKeySubsystem()
            const replacementClosed = once(replacement.channel, "close")
            replacement.end()
            await replacementClosed
            expect(client.isConnected).toBe(true)
        } finally {
            client.destroy()
            await server.close()
        }
    })
})
