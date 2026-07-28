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

describe("RFC 4819 and RFC 7076 public-key subsystem integration", () => {
    test("manages namespaced keys and certificates across transport rekey", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({ hostKeys: [hostKey], sendAllHostKeys: false })
        const keys = new Map<
            string,
            { key: PublicKey; attributes: readonly PublicKeySubsystemAddAttribute[] }
        >()
        const certificates = new Map<
            string,
            { format: string; certificate: Buffer; namespace: string }
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
                        expect(context.namespace).toBe("ssh")
                        keys.set(context.key.hash("sha256"), {
                            key: context.key,
                            attributes: context.attributes,
                        })
                        controller.success = true
                    })
                    subsystem.hooker.hook("remove", async (_hook, context, controller) => {
                        await Promise.resolve()
                        expect(context.namespace).toBe("ssh")
                        controller.success = keys.delete(context.key.hash("sha256"))
                    })
                    subsystem.hooker.hook("list", async (_hook, controller, context) => {
                        await Promise.resolve()
                        expect(context.namespace).toBe("ssh")
                        controller.keys = [...keys.values()]
                        controller.success = true
                    })
                    subsystem.hooker.hook("addCertificate", async (_hook, context, controller) => {
                        await Promise.resolve()
                        certificates.set(
                            `${context.namespace}:${context.format}:${context.certificate.toString("hex")}`,
                            {
                                format: context.format,
                                certificate: Buffer.from(context.certificate),
                                namespace: context.namespace,
                            },
                        )
                        controller.success = true
                    })
                    subsystem.hooker.hook(
                        "removeCertificate",
                        async (_hook, context, controller) => {
                            await Promise.resolve()
                            controller.success = certificates.delete(
                                `${context.namespace}:${context.format}:${context.certificate.toString("hex")}`,
                            )
                        },
                    )
                    subsystem.hooker.hook("listCertificates", async (_hook, controller) => {
                        await Promise.resolve()
                        controller.certificates = [...certificates.values()]
                        controller.success = true
                    })
                    subsystem.hooker.hook("listNamespaces", async (_hook, controller) => {
                        await Promise.resolve()
                        controller.namespaces = ["ssh", "ssl"]
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
                { name: "namespace", compulsory: false },
            ])

            const managedKey = PublicKey.parse(RFC_8709_KEY)
            await subsystem.add(managedKey, {
                namespace: "ssh",
                attributes: [{ name: "comment", value: "workstation", critical: true }],
            })
            await client.rekey()
            const listed = await subsystem.list({ namespace: "ssh" })
            expect(listed).toHaveLength(1)
            expect(listed[0]!.key.equals(managedKey)).toBe(true)
            expect(listed[0]!.attributes).toEqual([
                { name: "namespace", value: Buffer.from("ssh") },
                { name: "comment", value: Buffer.from("workstation") },
            ])

            await subsystem.remove(managedKey, { namespace: "ssh" })
            expect(await subsystem.list({ namespace: "ssh" })).toEqual([])

            const certificate = Buffer.from([1, 2, 3, 4])
            await subsystem.addCertificate("X509", certificate, {
                namespace: "ssh",
                overwrite: false,
            })
            expect(await subsystem.listCertificates()).toEqual([
                {
                    format: "X509",
                    certificate,
                    namespace: "ssh",
                    attributes: [{ name: "namespace", value: Buffer.from("ssh") }],
                },
            ])
            expect(await subsystem.listNamespaces()).toEqual(["ssh", "ssl"])
            await subsystem.removeCertificate("X509", certificate, { namespace: "ssh" })
            expect(await subsystem.listCertificates()).toEqual([])
            expect(errors).toEqual([])
        } finally {
            client.destroy()
            for (const connection of server.clients) connection.terminate()
            await server.close()
        }
    }, 15_000)
})
