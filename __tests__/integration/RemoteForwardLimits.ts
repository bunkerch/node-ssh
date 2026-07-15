import { describe, expect, test } from "bun:test"
import { once } from "node:events"
import { mkdtemp, rm } from "node:fs/promises"
import type { AddressInfo } from "node:net"
import { tmpdir } from "node:os"
import { join } from "node:path"
import Client from "../../src/Client.js"
import { SSHAuthenticationMethods } from "../../src/constants.js"
import Server from "../../src/Server.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

describe("server remote forwarding limits", () => {
    test("shares capacity across TCP and stream-local listeners and recovers it on cancellation", async () => {
        const directory = await mkdtemp(join(tmpdir(), "modernssh-forward-limit-"))
        const socketPath = join(directory, "forward.sock")
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({
            hostKeys: [hostKey],
            sendAllHostKeys: false,
            ident: "OpenSSH_9.9",
            algorithms: { kex: ["curve25519-sha256"] },
            maxRemoteForwardings: 1,
        })
        server.hooker.hook("noneAuthentication", (_hook, _context, controller) => {
            controller.allowLogin = true
        })
        let tcpPolicyCalls = 0
        let streamLocalPolicyCalls = 0
        server.hooker.hook("tcpipForward", (_hook, _context, controller) => {
            tcpPolicyCalls++
            controller.allow = true
        })
        server.hooker.hook("streamLocalForward", (_hook, _context, controller) => {
            streamLocalPolicyCalls++
            controller.allow = true
        })

        server.listen({ host: "127.0.0.1", port: 0 })
        await once(server, "listening")
        const client = new Client({
            hostname: "127.0.0.1",
            port: (server.address() as AddressInfo).port,
            username: "bounded-forwarding",
            authenticationMethodsOrder: [SSHAuthenticationMethods.None],
            algorithms: { kex: ["curve25519-sha256"] },
        })
        client.hooker.hook("hostKey", (_hook, controller) => {
            controller.allowHostKey = true
        })

        try {
            await client.connect()
            const firstPort = await client.forwardIn("127.0.0.1", 0)
            await expect(client.forwardIn("127.0.0.1", 0)).rejects.toThrow("failed")

            await client.unforwardIn("127.0.0.1", firstPort)
            await client.openssh_forwardInStreamLocal(socketPath)
            await expect(client.forwardIn("127.0.0.1", 0)).rejects.toThrow("failed")

            await client.openssh_unforwardInStreamLocal(socketPath)
            const finalPort = await client.forwardIn("127.0.0.1", 0)
            await client.unforwardIn("127.0.0.1", finalPort)

            expect(tcpPolicyCalls).toBe(2)
            expect(streamLocalPolicyCalls).toBe(1)
        } finally {
            client.destroy()
            for (const connection of server.clients) connection.terminate()
            await server.close()
            await rm(directory, { recursive: true, force: true })
        }
    }, 15_000)
})
