import type { AddressInfo } from "node:net"
import Client from "../../src/Client.js"
import Server from "../../src/Server.js"
import { SSHAuthenticationMethods } from "../../src/constants.js"
import { default_algorithm_names, host_key_algorithms } from "../../src/algorithms.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

describe("RFC 8709 Ed448 host keys", () => {
    test("is supported through explicit negotiation but excluded from defaults", () => {
        expect(host_key_algorithms.has("ssh-ed448")).toBe(true)
        expect(default_algorithm_names.serverHostKey).not.toContain("ssh-ed448")
    })

    test("authenticates a library peer with an Ed448 host signature", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed448")
        const server = new Server({
            hostKeys: [hostKey],
            sendAllHostKeys: false,
            algorithms: { serverHostKey: ["ssh-ed448"] },
        })
        server.hooker.hook("noneAuthentication", async (_hook, _context, decision) => {
            decision.allowLogin = true
        })
        server.listen({ host: "127.0.0.1", port: 0 })
        await new Promise<void>((resolve) => server.server!.once("listening", resolve))

        const client = new Client({
            hostname: "127.0.0.1",
            port: (server.server!.address() as AddressInfo).port,
            algorithms: { serverHostKey: ["ssh-ed448"] },
            authenticationMethodsOrder: [SSHAuthenticationMethods.None],
        })
        client.hooker.hook("hostKey", async (_hook, decision, key) => {
            decision.allowHostKey = key.equals(hostKey.data.publicKey)
        })
        let negotiatedHostKey: string | undefined
        client.on("handshake", (algorithms) => {
            negotiatedHostKey = algorithms.srvHostKey
        })
        try {
            await client.connect()
            expect(negotiatedHostKey).toBe("ssh-ed448")
            expect(client.isConnected).toBe(true)
        } finally {
            client.destroy()
            for (const peer of server.clients) peer.terminate()
            await new Promise<void>((resolve, reject) => {
                server.server!.close((error) => (error ? reject(error) : resolve()))
            })
        }
    })
})
