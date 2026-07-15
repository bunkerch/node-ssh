import { AddressInfo } from "node:net"
import Client from "../../src/Client.js"
import { SSHAuthenticationMethods } from "../../src/constants.js"
import Server from "../../src/Server.js"
import TunnelChannel from "../../src/channels/TunnelChannel.js"
import { TunnelAddressFamily, TunnelMode } from "../../src/channels/Tunnel.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

const ipv4 = Buffer.from("450000140000000040110000c0000201c6336402", "hex")

describe("packet tunnel integration", () => {
    test("awaits tunnel policy and preserves an IP datagram in both directions", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({ hostKeys: [hostKey], sendAllHostKeys: false })
        server.hooker.hook("noneAuthentication", (_hook, _context, controller) => {
            controller.allowLogin = true
        })
        let policyFinished = false
        server.hooker.hook("channelOpenRequest", async (_hook, channel, controller) => {
            await new Promise<void>((resolve) => setImmediate(resolve))
            policyFinished = true
            controller.allowOpen = channel instanceof TunnelChannel
        })
        const received = new Promise<Buffer>((resolve, reject) => {
            server.on("connection", (peer) => {
                peer.on("channel", (channel) => {
                    if (!(channel instanceof TunnelChannel)) return
                    channel.events.once("packet", ({ family, data }) => {
                        expect(family).toBe(TunnelAddressFamily.IPv4)
                        void channel.sendIPv4(data).then(() => resolve(data), reject)
                    })
                })
            })
        })

        server.listen({ host: "127.0.0.1", port: 0 })
        await new Promise<void>((resolve) => server.server!.once("listening", resolve))
        const client = new Client({
            hostname: "127.0.0.1",
            port: (server.address() as AddressInfo).port,
            username: "tunnel-test",
            strictVendor: false,
            authenticationMethodsOrder: [SSHAuthenticationMethods.None],
        })
        client.hooker.hook("hostKey", (_hook, controller) => {
            controller.allowHostKey = true
        })

        try {
            await client.connect()
            const tunnel = await client.openTunnel(TunnelMode.PointToPoint, 7)
            expect(policyFinished).toBe(true)
            expect(tunnel.unit).toBe(7)
            const echoed = new Promise<Buffer>((resolve) => {
                tunnel.events.once("packet", ({ data }) => resolve(data))
            })
            await tunnel.sendIPv4(ipv4)
            await expect(received).resolves.toEqual(ipv4)
            await expect(echoed).resolves.toEqual(ipv4)
            tunnel.destroy()
        } finally {
            client.destroy()
            for (const peer of server.clients) peer.terminate()
            await server.close()
        }
    }, 15_000)
})
