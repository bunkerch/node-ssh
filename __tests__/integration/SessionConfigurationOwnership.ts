import { once } from "node:events"
import type { AddressInfo } from "node:net"
import Client, { type ClientSessionOptions } from "../../src/Client.js"
import SessionChannel from "../../src/channels/SessionChannel.js"
import { SSHAuthenticationMethods } from "../../src/constants.js"
import Server from "../../src/Server.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

describe("client session configuration ownership", () => {
    test("exec owns its environment when the operation starts", async () => {
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

        let receivedRole: string | undefined
        server.on("connection", (connection) => {
            connection.on("channel", (channel) => {
                if (!(channel instanceof SessionChannel)) return
                channel.hooker.hook("envRequest", (_hook, context, controller) => {
                    receivedRole = context.value
                    controller.success = true
                })
                channel.hooker.hook("execRequest", (_hook, _context, controller) => {
                    controller.success = true
                })
            })
        })

        server.listen({ host: "127.0.0.1", port: 0 })
        await once(server, "listening")
        const client = new Client({
            hostname: "127.0.0.1",
            port: (server.address() as AddressInfo).port,
            username: "session-ownership",
            authenticationMethodsOrder: [SSHAuthenticationMethods.None],
            algorithms: { kex: ["curve25519-sha256"] },
        })
        client.hooker.hook("hostKey", (_hook, controller) => {
            controller.allowHostKey = true
        })

        try {
            await client.connect()
            const options: ClientSessionOptions = { env: { ROLE: "original" } }
            const opening = client.exec("true", options)
            options.env!.ROLE = "mutated"

            const channel = await opening
            expect(receivedRole).toBe("original")
            channel.close()
        } finally {
            client.destroy()
            for (const connection of server.clients) connection.terminate()
            await server.close()
        }
    }, 15_000)
})
