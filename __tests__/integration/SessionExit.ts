import { once } from "node:events"
import type { AddressInfo } from "node:net"
import Client from "../../src/Client.js"
import Server from "../../src/Server.js"
import type ServerClient from "../../src/ServerClient.js"
import SessionChannel from "../../src/channels/SessionChannel.js"
import { SSHAuthenticationMethods } from "../../src/constants.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

test("server sends one complete RFC 4254 exit-signal result", async () => {
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
    let duplicateError: Error | undefined
    server.on("connection", (connection) => {
        peer = connection
        connection.on("channel", (channel) => {
            if (!(channel instanceof SessionChannel)) return
            channel.hooker.hook("execRequest", (_hook, _context, controller) => {
                controller.success = true
            })
            channel.events.on("exec", (_command, shell) => {
                shell.exit("TERM", true, "terminated by policy", "en-US")
                try {
                    shell.exit(0)
                } catch (error) {
                    duplicateError = error as Error
                }
                shell.close()
            })
        })
    })
    server.listen({ host: "127.0.0.1", port: 0 })
    await once(server, "listening")

    const client = new Client({
        hostname: "127.0.0.1",
        port: (server.address() as AddressInfo).port,
        username: "session-exit-test",
        authenticationMethodsOrder: [SSHAuthenticationMethods.None],
    })
    client.hooker.hook("hostKey", (_hook, controller) => {
        controller.allowHostKey = true
    })

    try {
        await client.connect()
        const channel = await client.openSession()
        const exit = once(channel, "exit")
        const close = once(channel, "close")
        await channel.exec("terminate")

        expect(await exit).toEqual([null, "SIGTERM", true, "terminated by policy", "en-US"])
        await close
        expect(channel.exitCode).toBeNull()
        expect(channel.exitSignal).toBe("SIGTERM")
        expect(channel.exitCoreDumped).toBe(true)
        expect(channel.exitErrorMessage).toBe("terminated by policy")
        expect(channel.exitLanguageTag).toBe("en-US")
        expect(duplicateError?.message).toBe("SSH session exit result has already been sent")
        expect(client.isConnected).toBe(true)
    } finally {
        client.destroy()
        peer?.terminate()
        await server.close()
    }
}, 15_000)
