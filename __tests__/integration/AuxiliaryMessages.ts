import { AddressInfo } from "node:net"
import Client from "../../src/Client.js"
import { SSHAuthenticationMethods } from "../../src/constants.js"
import Server from "../../src/Server.js"
import type ServerClient from "../../src/ServerClient.js"
import type { ProtocolDebugMessage } from "../../src/packets/Debug.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

async function createConnectedPeers(): Promise<{
    server: Server
    peer: ServerClient
    client: Client
}> {
    const hostKey = await PrivateKey.generate("ssh-ed25519")
    const server = new Server({ hostKeys: [hostKey], sendAllHostKeys: false })
    server.hooker.hook("noneAuthentication", async (_hook, _context, controller) => {
        controller.allowLogin = true
    })
    let peer: ServerClient | undefined
    server.on("connection", (connection) => {
        peer = connection
    })
    server.listen({ host: "127.0.0.1", port: 0 })
    await new Promise<void>((resolve) => server.server!.once("listening", resolve))

    const client = new Client({
        hostname: "127.0.0.1",
        port: (server.address() as AddressInfo).port,
        username: "auxiliary-message-test",
        authenticationMethodsOrder: [SSHAuthenticationMethods.None],
    })
    client.hooker.hook("hostKey", async (_hook, controller) => {
        controller.allowHostKey = true
    })
    await client.connect()
    return { server, peer: peer!, client }
}

async function closePeers(server: Server, client: Client): Promise<void> {
    client.destroy()
    for (const peer of server.clients) peer.terminate()
    await new Promise<void>((resolve) => server.close(() => resolve()))
}

function nextDebug(emitter: Client | ServerClient): Promise<Readonly<ProtocolDebugMessage>> {
    return new Promise((resolve) => emitter.once("protocolDebug", resolve))
}

describe("RFC 4253 auxiliary transport messages", () => {
    test("exposes immutable debug metadata in both directions", async () => {
        const { server, peer, client } = await createConnectedPeers()
        try {
            const atServer = nextDebug(peer)
            client.sendDebug("client diagnostic", true, "en-GB")
            const serverInfo = await atServer
            expect(serverInfo).toEqual({
                alwaysDisplay: true,
                message: "client diagnostic",
                languageTag: "en-GB",
            })
            expect(Object.isFrozen(serverInfo)).toBe(true)

            const atClient = nextDebug(client)
            peer.sendDebug("diagnostic côté serveur", false, "fr")
            const clientInfo = await atClient
            expect(clientInfo).toEqual({
                alwaysDisplay: false,
                message: "diagnostic côté serveur",
                languageTag: "fr",
            })
            expect(Object.isFrozen(clientInfo)).toBe(true)

            client.sendIgnore(Buffer.from("client padding"))
            peer.sendIgnore(Buffer.from("server padding"))
        } finally {
            await closePeers(server, client)
        }
    }, 15_000)

    test("queues debug output behind rekeys initiated by either role", async () => {
        const { server, peer, client } = await createConnectedPeers()
        try {
            const atServer = nextDebug(peer)
            const clientRekey = client.rekey()
            client.sendDebug("after client NEWKEYS")
            await clientRekey
            await expect(atServer).resolves.toMatchObject({ message: "after client NEWKEYS" })

            const atClient = nextDebug(client)
            const serverRekey = peer.rekey()
            peer.sendDebug("after server NEWKEYS")
            await serverRekey
            await expect(atClient).resolves.toMatchObject({ message: "after server NEWKEYS" })
        } finally {
            await closePeers(server, client)
        }
    }, 15_000)
})
