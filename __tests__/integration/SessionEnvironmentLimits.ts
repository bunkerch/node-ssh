import { describe, expect, test } from "bun:test"
import { once } from "node:events"
import type { AddressInfo } from "node:net"
import Client from "../../src/Client.js"
import SessionChannel from "../../src/channels/SessionChannel.js"
import { SSHAuthenticationMethods } from "../../src/constants.js"
import Server from "../../src/Server.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

describe("server session environment limits", () => {
    test("bounds retained variables and UTF-8 bytes before application policy", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({
            hostKeys: [hostKey],
            sendAllHostKeys: false,
            algorithms: { kex: ["curve25519-sha256"] },
            maxSessionEnvironmentVariables: 2,
            maxSessionEnvironmentBytes: 12,
        })
        server.hooker.hook("noneAuthentication", (_hook, _context, controller) => {
            controller.allowLogin = true
        })
        server.hooker.hook("channelOpenRequest", (_hook, channel, controller) => {
            controller.allowOpen = channel instanceof SessionChannel
        })

        const policyValues: [string, string][] = []
        let serverSession: SessionChannel | undefined
        server.on("connection", (connection) => {
            connection.on("channel", (channel) => {
                if (!(channel instanceof SessionChannel)) return
                serverSession = channel
                channel.hooker.hook("envRequest", (_hook, context, controller) => {
                    policyValues.push([context.key, context.value])
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
            username: "bounded-environment",
            authenticationMethodsOrder: [SSHAuthenticationMethods.None],
            algorithms: { kex: ["curve25519-sha256"] },
        })
        client.hooker.hook("hostKey", (_hook, controller) => {
            controller.allowHostKey = true
        })

        try {
            await client.connect()
            const session = await client.openSession()
            await session.setEnv("A", "12")
            ;(serverSession!.env as Map<string, string>).set("INJECTED", "not retained")
            await session.setEnv("BB", "345")

            await expect(session.setEnv("C", "x")).rejects.toThrow("failed")
            await session.setEnv("A", "éé")
            await expect(session.setEnv("BB", "1234567890")).rejects.toThrow("failed")

            await session.setEnv("D", "ignored", false)
            await session.exec("true")

            expect(serverSession?.env).toEqual(
                new Map([
                    ["A", "éé"],
                    ["BB", "345"],
                ]),
            )
            expect(policyValues).toEqual([
                ["A", "12"],
                ["BB", "345"],
                ["A", "éé"],
            ])
        } finally {
            client.destroy()
            for (const connection of server.clients) connection.terminate()
            await server.close()
        }
    }, 15_000)
})
