import { once } from "node:events"
import type { AddressInfo } from "node:net"

import Client from "../../src/Client.js"
import { SSHAuthenticationMethods } from "../../src/constants.js"
import { delayCompressionExtension } from "../../src/DelayCompression.js"
import NewCompress from "../../src/packets/NewCompress.js"
import Server from "../../src/Server.js"
import type ServerClient from "../../src/ServerClient.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

describe("RFC 8308 delay-compression integration", () => {
    test("activates each direction at its trigger and exchanges compressed traffic", async () => {
        const server = new Server({
            hostKeys: [await PrivateKey.generate("ssh-ed25519")],
            sendAllHostKeys: false,
            algorithms: { compress: ["none"] },
            delayCompression: true,
        })
        let peer: ServerClient | undefined
        let newCompressPackets = 0
        server.hooker.hook("noneAuthentication", (_hook, _context, decision) => {
            decision.allowLogin = true
        })
        server.hooker.hook("elevation", (_hook, _context, decision) => {
            decision.elevated = false
        })
        server.hooker.hook("globalRequest", (_hook, context, decision) => {
            if (context.name !== "compressed@example.com") return
            decision.success = true
            decision.response = Buffer.from(context.args)
        })
        server.on("connection", (connection) => {
            peer = connection
            connection.on("error", () => undefined)
            connection.on("packet", (packet) => {
                if (packet instanceof NewCompress) newCompressPackets++
            })
        })
        server.listen({ host: "127.0.0.1", port: 0 })
        await once(server.server, "listening")

        const client = new Client({
            hostname: "127.0.0.1",
            port: (server.address() as AddressInfo).port,
            username: "delay-compression-user",
            authenticationMethodsOrder: [SSHAuthenticationMethods.None],
            algorithms: { compress: ["none"] },
            delayCompression: true,
            elevation: "default",
        })
        client.on("error", () => undefined)
        client.hooker.hook("hostKey", (_hook, decision) => {
            decision.allowHostKey = true
        })
        const elevation = once(client, "elevation")

        try {
            await client.connect()
            expect(await elevation).toEqual([false])
            const payload = Buffer.from("compressed request payload ".repeat(512))
            expect(await client.globalRequest("compressed@example.com", payload)).toEqual(payload)
            expect(newCompressPackets).toBe(1)
            expect(client.negotiatedAlgorithms?.cs.compress).toBe("zlib")
            expect(client.negotiatedAlgorithms?.sc.compress).toBe("zlib")
            expect(peer?.negotiatedAlgorithms?.cs.compress).toBe("zlib")
            expect(peer?.negotiatedAlgorithms?.sc.compress).toBe("zlib")

            await client.rekey()
            expect(client.negotiatedAlgorithms?.cs.compress).toBe("none")
            expect(client.negotiatedAlgorithms?.sc.compress).toBe("none")
            expect(await client.globalRequest("compressed@example.com", payload)).toEqual(payload)
        } finally {
            client.destroy()
            for (const connection of server.clients) connection.terminate()
            await server.close()
        }
    }, 15_000)

    test.each([
        [true, false],
        [false, true],
    ] as const)(
        "requires bilateral advertisement with client=%s and server=%s",
        async (clientDelayCompression, serverDelayCompression) => {
            const server = new Server({
                hostKeys: [await PrivateKey.generate("ssh-ed25519")],
                sendAllHostKeys: false,
                algorithms: { compress: ["none"] },
                delayCompression: serverDelayCompression,
            })
            let peer: ServerClient | undefined
            let newCompressPackets = 0
            server.hooker.hook("noneAuthentication", (_hook, _context, decision) => {
                decision.allowLogin = true
            })
            server.on("connection", (connection) => {
                peer = connection
                connection.on("error", () => undefined)
                connection.on("packet", (packet) => {
                    if (packet instanceof NewCompress) newCompressPackets++
                })
            })
            server.listen({ host: "127.0.0.1", port: 0 })
            await once(server.server, "listening")

            const client = new Client({
                hostname: "127.0.0.1",
                port: (server.address() as AddressInfo).port,
                username: "bilateral-delay-compression-user",
                authenticationMethodsOrder: [SSHAuthenticationMethods.None],
                algorithms: { compress: ["none"] },
                delayCompression: clientDelayCompression,
            })
            client.on("error", () => undefined)
            client.hooker.hook("hostKey", (_hook, decision) => {
                decision.allowHostKey = true
            })

            try {
                await client.connect()
                expect(newCompressPackets).toBe(0)
                expect(client.negotiatedAlgorithms?.cs.compress).toBe("none")
                expect(client.negotiatedAlgorithms?.sc.compress).toBe("none")
                expect(peer?.negotiatedAlgorithms?.cs.compress).toBe("none")
                expect(peer?.negotiatedAlgorithms?.sc.compress).toBe("none")
            } finally {
                client.destroy()
                for (const connection of server.clients) connection.terminate()
                await server.close()
            }
        },
        15_000,
    )

    test("blocks locally initiated rekey until each role sends its compression trigger", async () => {
        const server = new Server({
            hostKeys: [await PrivateKey.generate("ssh-ed25519")],
            sendAllHostKeys: false,
            algorithms: { compress: ["none"] },
            delayCompression: true,
        })
        let serverRekeyError: Error | undefined
        server.hooker.hook("noneAuthentication", async (_hook, _context, decision, connection) => {
            serverRekeyError = await connection.rekey().catch((error: Error) => error)
            decision.allowLogin = true
        })
        server.on("connection", (connection) => connection.on("error", () => undefined))
        server.listen({ host: "127.0.0.1", port: 0 })
        await once(server.server, "listening")

        const client = new Client({
            hostname: "127.0.0.1",
            port: (server.address() as AddressInfo).port,
            username: "delay-compression-rekey-user",
            authenticationMethodsOrder: [SSHAuthenticationMethods.None],
            algorithms: { compress: ["none"] },
            delayCompression: true,
        })
        let clientRekeyError: Error | undefined
        client.on("error", () => undefined)
        client.hooker.hook("hostKey", (_hook, decision) => {
            decision.allowHostKey = true
        })
        client.hooker.hook("authenticationMethod", async () => {
            clientRekeyError = await client.rekey().catch((error: Error) => error)
        })

        try {
            await client.connect()
            expect(clientRekeyError?.message).toContain("delay-compression is resolved")
            expect(serverRekeyError?.message).toContain("delay-compression is resolved")
            await client.rekey()
        } finally {
            client.destroy()
            for (const connection of server.clients) connection.terminate()
            await server.close()
        }
    }, 15_000)

    test("bounds client messages sent without the required NEWCOMPRESS trigger", async () => {
        const offers = { clientToServer: ["none"] as const, serverToClient: ["none"] as const }
        const server = new Server({
            hostKeys: [await PrivateKey.generate("ssh-ed25519")],
            sendAllHostKeys: false,
            algorithms: { compress: ["none"] },
            delayCompression: offers,
        })
        let peer: ServerClient | undefined
        server.hooker.hook("noneAuthentication", (_hook, _context, decision) => {
            decision.allowLogin = true
        })
        server.on("connection", (connection) => {
            peer = connection
        })
        server.listen({ host: "127.0.0.1", port: 0 })
        await once(server.server, "listening")

        const client = new Client({
            hostname: "127.0.0.1",
            port: (server.address() as AddressInfo).port,
            username: "missing-newcompress-user",
            authenticationMethodsOrder: [SSHAuthenticationMethods.None],
            algorithms: { compress: ["none"] },
            delayCompression: offers,
        })
        client.on("error", () => undefined)
        client.hooker.hook("hostKey", (_hook, decision) => {
            decision.allowHostKey = true
        })
        const sendPacket = client.sendPacket.bind(client)
        client.sendPacket = (packet) => (packet instanceof NewCompress ? 0 : sendPacket(packet))

        try {
            await client.connect()
            const error = once(peer!, "error")
            for (let index = 0; index < 33; index++) client.sendIgnore(Buffer.from([index]))
            expect((await error)[0].message).toContain("did not send NEWCOMPRESS")
        } finally {
            client.destroy()
            for (const connection of server.clients) connection.terminate()
            await server.close()
        }
    }, 15_000)

    test.each(["client", "server"] as const)(
        "rejects an unexpected NEWCOMPRESS sent by the %s",
        async (sender) => {
            const server = new Server({
                hostKeys: [await PrivateKey.generate("ssh-ed25519")],
                sendAllHostKeys: false,
                algorithms: { compress: ["none"] },
                delayCompression: true,
            })
            let peer: ServerClient | undefined
            server.hooker.hook("noneAuthentication", (_hook, _context, decision) => {
                decision.allowLogin = true
            })
            server.on("connection", (connection) => {
                peer = connection
                connection.on("error", () => undefined)
            })
            server.listen({ host: "127.0.0.1", port: 0 })
            await once(server.server, "listening")

            const client = new Client({
                hostname: "127.0.0.1",
                port: (server.address() as AddressInfo).port,
                username: "unexpected-newcompress-user",
                authenticationMethodsOrder: [SSHAuthenticationMethods.None],
                algorithms: { compress: ["none"] },
                delayCompression: true,
            })
            client.on("error", () => undefined)
            client.hooker.hook("hostKey", (_hook, decision) => {
                decision.allowHostKey = true
            })

            try {
                await client.connect()
                if (sender === "client") {
                    const error = once(peer!, "error")
                    client.sendPacket(new NewCompress())
                    expect((await error)[0].message).toContain("NEWCOMPRESS")
                } else {
                    const disconnect = once(peer!, "disconnect")
                    peer!.sendPacket(new NewCompress())
                    expect((await disconnect)[0].description).toContain("NEWCOMPRESS")
                }
            } finally {
                client.destroy()
                for (const connection of server.clients) connection.terminate()
                await server.close()
            }
        },
        15_000,
    )

    test("accepts a server offer delayed until authentication policy", async () => {
        const offers = {
            clientToServer: ["zlib", "none"] as const,
            serverToClient: ["zlib", "none"] as const,
        }
        const server = new Server({
            hostKeys: [await PrivateKey.generate("ssh-ed25519")],
            sendAllHostKeys: false,
            algorithms: { compress: ["none"] },
        })
        let peer: ServerClient | undefined
        let newCompressPackets = 0
        let hookError: Error | undefined
        let resolveNewCompress!: () => void
        const newCompressReceived = new Promise<void>((resolve) => {
            resolveNewCompress = resolve
        })
        server.hooker.on("uncaughtException", (_event, error) => {
            hookError = error
        })
        server.hooker.hook("noneAuthentication", (_hook, _context, decision, connection) => {
            connection.sendAuthenticationExtensions([delayCompressionExtension(offers)])
            decision.allowLogin = true
        })
        server.on("connection", (connection) => {
            peer = connection
            connection.on("error", () => undefined)
            connection.on("packet", (packet) => {
                if (packet instanceof NewCompress) {
                    newCompressPackets++
                    resolveNewCompress()
                }
            })
        })
        server.listen({ host: "127.0.0.1", port: 0 })
        await once(server.server, "listening")

        const client = new Client({
            hostname: "127.0.0.1",
            port: (server.address() as AddressInfo).port,
            username: "late-delay-compression-user",
            authenticationMethodsOrder: [SSHAuthenticationMethods.None],
            algorithms: { compress: ["none"] },
            delayCompression: true,
        })
        client.on("error", () => undefined)
        client.hooker.hook("hostKey", (_hook, decision) => {
            decision.allowHostKey = true
        })

        try {
            await client.connect()
            await newCompressReceived
            expect(hookError).toBeUndefined()
            expect(newCompressPackets).toBe(1)
            expect(client.negotiatedAlgorithms?.cs.compress).toBe("zlib")
            expect(client.negotiatedAlgorithms?.sc.compress).toBe("zlib")
            expect(peer?.negotiatedAlgorithms?.cs.compress).toBe("zlib")
            expect(peer?.negotiatedAlgorithms?.sc.compress).toBe("zlib")
        } finally {
            client.destroy()
            for (const connection of server.clients) connection.terminate()
            await server.close()
        }
    }, 15_000)

    test("disconnects with key-exchange failure when a direction has no mutual algorithm", async () => {
        const server = new Server({
            hostKeys: [await PrivateKey.generate("ssh-ed25519")],
            sendAllHostKeys: false,
            algorithms: { compress: ["none"] },
            delayCompression: {
                clientToServer: ["none"],
                serverToClient: ["none"],
            },
        })
        let resolveServerError!: (error: Error) => void
        const serverError = new Promise<Error>((resolve) => {
            resolveServerError = resolve
        })
        server.on("connection", (connection) => {
            connection.on("error", resolveServerError)
        })
        server.listen({ host: "127.0.0.1", port: 0 })
        await once(server.server, "listening")

        const client = new Client({
            hostname: "127.0.0.1",
            port: (server.address() as AddressInfo).port,
            username: "non-mutual-delay-compression-user",
            authenticationMethodsOrder: [SSHAuthenticationMethods.None],
            algorithms: { compress: ["none"] },
            delayCompression: {
                clientToServer: ["zlib"],
                serverToClient: ["zlib"],
            },
        })
        client.on("error", () => undefined)
        client.hooker.hook("hostKey", (_hook, decision) => {
            decision.allowHostKey = true
        })

        try {
            await expect(client.connect()).rejects.toThrow()
            expect(await serverError).toMatchObject({
                reason_code: 3,
                message: "No mutual SSH delay-compression algorithm",
            })
        } finally {
            client.destroy()
            for (const connection of server.clients) connection.terminate()
            await server.close()
        }
    }, 15_000)
})
