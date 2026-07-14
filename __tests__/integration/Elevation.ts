import { once } from "node:events"
import type { AddressInfo } from "node:net"

import Client from "../../src/Client.js"
import { SSHAuthenticationMethods } from "../../src/constants.js"
import GlobalRequest from "../../src/packets/GlobalRequest.js"
import Server from "../../src/Server.js"
import type ServerClient from "../../src/ServerClient.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

describe("RFC 8308 elevation integration", () => {
    test("awaits server elevation policy and reports the result after authentication", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({ hostKeys: [hostKey], sendAllHostKeys: false })
        let peer: ServerClient | undefined
        let releasePolicy!: () => void
        let policyStarted!: () => void
        const policyGate = new Promise<void>((resolve) => {
            releasePolicy = resolve
        })
        const policyStart = new Promise<void>((resolve) => {
            policyStarted = resolve
        })

        server.hooker.hook("noneAuthentication", (_hook, _context, decision) => {
            decision.allowLogin = true
        })
        server.hooker.hook("elevation", async (_hook, context, decision) => {
            expect(context).toEqual({ preference: "elevated", username: "elevation-user" })
            policyStarted()
            await policyGate
            decision.elevated = true
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
            username: "elevation-user",
            authenticationMethodsOrder: [SSHAuthenticationMethods.None],
            elevation: "elevated",
        })
        client.on("error", () => undefined)
        client.hooker.hook("hostKey", (_hook, decision) => {
            decision.allowHostKey = true
        })
        const elevationResult = once(client, "elevation")
        const connected = client.connect()

        try {
            await policyStart
            expect(client.hasAuthenticated).toBe(false)
            releasePolicy()
            await connected
            expect(await elevationResult).toEqual([true])
            expect(client.elevated).toBe(true)
            expect(peer?.clientElevationPreference).toBe("elevated")
        } finally {
            releasePolicy()
            client.destroy()
            for (const connection of server.clients) connection.terminate()
            await server.close()
        }
    }, 15_000)

    test("preserves a false elevation result instead of treating it as absent", async () => {
        const server = new Server({
            hostKeys: [await PrivateKey.generate("ssh-ed25519")],
            sendAllHostKeys: false,
        })
        server.hooker.hook("noneAuthentication", (_hook, _context, decision) => {
            decision.allowLogin = true
        })
        server.hooker.hook("elevation", (_hook, context, decision) => {
            expect(context.preference).toBe("default")
            decision.elevated = false
        })
        server.on("connection", (connection) => connection.on("error", () => undefined))
        server.listen({ host: "127.0.0.1", port: 0 })
        await once(server.server, "listening")

        const client = new Client({
            hostname: "127.0.0.1",
            port: (server.address() as AddressInfo).port,
            username: "default-elevation-user",
            authenticationMethodsOrder: [SSHAuthenticationMethods.None],
            elevation: "default",
        })
        client.on("error", () => undefined)
        client.hooker.hook("hostKey", (_hook, decision) => {
            decision.allowHostKey = true
        })
        const elevationResult = once(client, "elevation")

        try {
            await client.connect()
            expect(await elevationResult).toEqual([false])
            expect(client.elevated).toBe(false)
        } finally {
            client.destroy()
            for (const connection of server.clients) connection.terminate()
            await server.close()
        }
    }, 15_000)

    test("uses default policy without reporting a result when the client omits the extension", async () => {
        const server = new Server({
            hostKeys: [await PrivateKey.generate("ssh-ed25519")],
            sendAllHostKeys: false,
        })
        let elevationPolicies = 0
        server.hooker.hook("noneAuthentication", (_hook, _context, decision) => {
            decision.allowLogin = true
        })
        server.hooker.hook("elevation", (_hook, context, decision) => {
            elevationPolicies++
            expect(context.preference).toBe("default")
            decision.elevated = true
        })
        server.on("connection", (connection) => connection.on("error", () => undefined))
        server.listen({ host: "127.0.0.1", port: 0 })
        await once(server.server, "listening")

        const client = new Client({
            hostname: "127.0.0.1",
            port: (server.address() as AddressInfo).port,
            username: "no-elevation-extension-user",
            authenticationMethodsOrder: [SSHAuthenticationMethods.None],
        })
        client.on("error", () => undefined)
        client.hooker.hook("hostKey", (_hook, decision) => {
            decision.allowHostKey = true
        })

        try {
            await client.connect()
            expect(elevationPolicies).toBe(1)
            expect(client.elevated).toBeUndefined()
        } finally {
            client.destroy()
            for (const connection of server.clients) connection.terminate()
            await server.close()
        }
    }, 15_000)

    test("rejects a malformed elevation result", async () => {
        const server = new Server({
            hostKeys: [await PrivateKey.generate("ssh-ed25519")],
            sendAllHostKeys: false,
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
            username: "malformed-elevation-user",
            authenticationMethodsOrder: [SSHAuthenticationMethods.None],
            elevation: "default",
        })
        client.hooker.hook("hostKey", (_hook, decision) => {
            decision.allowHostKey = true
        })

        try {
            await client.connect()
            const error = once(client, "error")
            peer!.sendPacket(
                new GlobalRequest({
                    request_name: "elevation",
                    want_reply: false,
                    args: Buffer.alloc(0),
                }),
            )
            expect((await error)[0].message).toContain("one-way request containing one boolean")
        } finally {
            client.destroy()
            for (const connection of server.clients) connection.terminate()
            await server.close()
        }
    }, 15_000)
})
