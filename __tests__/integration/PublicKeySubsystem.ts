import { describe, expect, test } from "bun:test"
import { once } from "node:events"
import type { AddressInfo } from "node:net"
import Client from "../../src/Client.js"
import Server from "../../src/Server.js"
import SessionChannel from "../../src/channels/SessionChannel.js"
import { SSHAuthenticationMethods } from "../../src/constants.js"
import type { PublicKeySubsystemAddAttribute } from "../../src/publickey/PublicKeySubsystemCodec.js"
import PrivateKey from "../../src/utils/PrivateKey.js"
import PublicKey from "../../src/utils/PublicKey.js"

const RFC_8709_KEY = Buffer.from(
    "0000000b7373682d6564323535313900000020" +
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "hex",
)

describe("RFC 4819 public-key subsystem integration", () => {
    test("adds, lists, and removes keys across transport rekey", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({ hostKeys: [hostKey], sendAllHostKeys: false })
        const keys = new Map<
            string,
            { key: PublicKey; attributes: readonly PublicKeySubsystemAddAttribute[] }
        >()
        const errors: Error[] = []
        server.hooker.hook("noneAuthentication", (_hook, _context, controller) => {
            controller.allowLogin = true
        })
        server.hooker.hook("channelOpenRequest", (_hook, channel, controller) => {
            controller.allowOpen = channel instanceof SessionChannel
        })
        server.on("connection", (connection) => {
            connection.on("error", (error) => errors.push(error))
            connection.on("channel", (channel) => {
                if (!(channel instanceof SessionChannel)) return
                channel.hooker.hook("subsystemRequest", (_hook, context, controller) => {
                    if (context.subsystem !== "publickey") return
                    controller.success = true
                    controller.publicKey = {
                        attributes: [{ name: "comment", compulsory: false }],
                    }
                })
                channel.events.on("publicKey", (subsystem) => {
                    subsystem.hooker.hook("add", async (_hook, context, controller) => {
                        await Promise.resolve()
                        keys.set(context.key.hash("sha256"), {
                            key: context.key,
                            attributes: context.attributes,
                        })
                        controller.success = true
                    })
                    subsystem.hooker.hook("remove", async (_hook, context, controller) => {
                        await Promise.resolve()
                        controller.success = keys.delete(context.key.hash("sha256"))
                    })
                    subsystem.hooker.hook("list", async (_hook, controller) => {
                        await Promise.resolve()
                        controller.keys = [...keys.values()]
                        controller.success = true
                    })
                })
            })
        })
        server.listen({ host: "127.0.0.1", port: 0 })
        await once(server.server!, "listening")

        const client = new Client({
            hostname: "127.0.0.1",
            port: (server.address() as AddressInfo).port,
            username: "key-manager",
            authenticationMethodsOrder: [SSHAuthenticationMethods.None],
        })
        client.on("error", (error) => errors.push(error))
        client.hooker.hook("hostKey", (_hook, controller) => {
            controller.allowHostKey = true
        })

        try {
            await client.connect()
            const subsystem = await client.publicKeySubsystem()
            expect(await subsystem.listAttributes()).toEqual([
                { name: "comment", compulsory: false },
            ])

            const managedKey = PublicKey.parse(RFC_8709_KEY)
            await subsystem.add(managedKey, {
                attributes: [{ name: "comment", value: "workstation", critical: true }],
            })
            await client.rekey()
            const listed = await subsystem.list()
            expect(listed).toHaveLength(1)
            expect(listed[0]!.key.equals(managedKey)).toBe(true)
            expect(listed[0]!.attributes).toEqual([
                { name: "comment", value: Buffer.from("workstation") },
            ])

            await subsystem.remove(managedKey)
            expect(await subsystem.list()).toEqual([])
            expect(errors).toEqual([])
        } finally {
            client.destroy()
            for (const connection of server.clients) connection.terminate()
            await server.close()
        }
    }, 15_000)
})
