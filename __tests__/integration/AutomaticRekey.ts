import { once } from "node:events"
import { AddressInfo } from "node:net"
import Client, { type ClientOptions } from "../../src/Client.js"
import { SSHAuthenticationMethods } from "../../src/constants.js"
import Server, { type ServerOptions } from "../../src/Server.js"
import type ServerClient from "../../src/ServerClient.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

const algorithms = {
    kex: ["curve25519-sha256"],
    serverHostKey: ["ssh-ed25519"],
    cipher: ["aes128-ctr"],
    hmac: ["hmac-sha2-256-etm@openssh.com"],
    compress: ["none"],
} as const

async function connectPeers(
    serverOptions: Pick<ServerOptions, "rekeyBytes" | "rekeyInterval">,
    clientOptions: Pick<ClientOptions, "rekeyBytes" | "rekeyInterval">,
): Promise<{ server: Server; peer: ServerClient; client: Client }> {
    const hostKey = await PrivateKey.generate("ssh-ed25519")
    const server = new Server({
        hostKeys: [hostKey],
        sendAllHostKeys: false,
        algorithms,
        ...serverOptions,
    })
    server.hooker.hook("noneAuthentication", (_hook, _context, controller) => {
        controller.allowLogin = true
    })
    server.listen({ host: "127.0.0.1", port: 0 })
    await once(server, "listening")

    const connection = once(server, "connection")
    const client = new Client({
        hostname: "127.0.0.1",
        port: (server.address() as AddressInfo).port,
        username: "automatic-rekey-test",
        authenticationMethodsOrder: [SSHAuthenticationMethods.None],
        algorithms,
        ...clientOptions,
    })
    client.hooker.hook("hostKey", (_hook, controller) => {
        controller.allowHostKey = true
    })
    await client.connect()
    const [peer] = await connection
    return { server, peer, client }
}

async function closePeers(server: Server, client: Client): Promise<void> {
    client.destroy()
    for (const peer of server.clients) peer.terminate()
    await server.close()
}

describe("RFC 4253 automatic key re-exchange", () => {
    test("client initiates after either protected direction reaches the byte limit", async () => {
        const { server, peer, client } = await connectPeers(
            { rekeyBytes: 0, rekeyInterval: 0 },
            { rekeyBytes: 8_000, rekeyInterval: 0 },
        )
        try {
            const clientRekey = once(client, "rekey", { signal: AbortSignal.timeout(2_000) })
            const serverRekey = once(peer, "rekey", { signal: AbortSignal.timeout(2_000) })

            client.sendIgnore(Buffer.alloc(12_000, 0x5a))

            await Promise.all([clientRekey, serverRekey])
            expect(client.isConnected).toBe(true)
            expect(peer.isConnected).toBe(true)

            const clientInboundRekey = once(client, "rekey", {
                signal: AbortSignal.timeout(2_000),
            })
            const serverAcceptedRekey = once(peer, "rekey", {
                signal: AbortSignal.timeout(2_000),
            })
            peer.sendIgnore(Buffer.alloc(12_000, 0xa5))

            await Promise.all([clientInboundRekey, serverAcceptedRekey])
            expect(client.isConnected).toBe(true)
            expect(peer.isConnected).toBe(true)
        } finally {
            await closePeers(server, client)
        }
    }, 15_000)

    test("server initiates when the key age reaches its time limit", async () => {
        const { server, peer, client } = await connectPeers(
            { rekeyBytes: 0, rekeyInterval: 150 },
            { rekeyBytes: 0, rekeyInterval: 0 },
        )
        try {
            await Promise.all([
                once(client, "rekey", { signal: AbortSignal.timeout(2_000) }),
                once(peer, "rekey", { signal: AbortSignal.timeout(2_000) }),
            ])
            expect(client.isConnected).toBe(true)
            expect(peer.isConnected).toBe(true)
        } finally {
            await closePeers(server, client)
        }
    }, 15_000)

    test("does not report an old peer-initiated rekey failure on a reconnected transport", async () => {
        const server = new Server({
            hostKeys: [await PrivateKey.generate("ssh-ed25519")],
            sendAllHostKeys: false,
            algorithms,
            rekeyBytes: 0,
            rekeyInterval: 0,
        })
        server.hooker.hook("noneAuthentication", (_hook, _context, controller) => {
            controller.allowLogin = true
        })
        const peers: ServerClient[] = []
        server.on("connection", (peer) => {
            peers.push(peer)
            peer.on("error", () => undefined)
        })
        server.listen({ host: "127.0.0.1", port: 0 })
        await once(server, "listening")

        let releaseOldDecision!: () => void
        const oldDecisionReleased = new Promise<void>((resolve) => {
            releaseOldDecision = resolve
        })
        let reportOldDecision!: () => void
        const oldDecisionStarted = new Promise<void>((resolve) => {
            reportOldDecision = resolve
        })
        let hostKeyDecisions = 0
        const client = new Client({
            hostname: "127.0.0.1",
            port: (server.address() as AddressInfo).port,
            username: "peer-rekey-reconnect",
            authenticationMethodsOrder: [SSHAuthenticationMethods.None],
            algorithms,
            rekeyBytes: 0,
            rekeyInterval: 0,
        })
        client.on("error", () => undefined)
        client.hooker.hook("hostKey", async (_hook, controller) => {
            hostKeyDecisions++
            if (hostKeyDecisions === 2) {
                reportOldDecision()
                await oldDecisionReleased
            }
            controller.allowHostKey = true
        })

        try {
            await client.connect()
            const oldRekey = peers[0].rekey().then(
                () => undefined,
                (error: unknown) => error,
            )
            await oldDecisionStarted

            const oldTransportClosed = once(client, "close")
            client.destroy()
            await oldTransportClosed
            expect(await oldRekey).toBeInstanceOf(Error)

            await client.connect()
            expect(hostKeyDecisions).toBe(3)
            expect(client.isConnected).toBe(true)

            releaseOldDecision()
            await new Promise<void>((resolve) => setImmediate(resolve))
            expect(client.isConnected).toBe(true)
        } finally {
            releaseOldDecision()
            await closePeers(server, client)
        }
    }, 15_000)

    test("validates byte and timer limits for both peer roles", () => {
        expect(() => new Client({ rekeyBytes: -1 })).toThrow("non-negative safe integer")
        expect(() => new Client({ rekeyBytes: 1.5 })).toThrow("non-negative safe integer")
        expect(() => new Client({ rekeyInterval: -1 })).toThrow("between 0")
        expect(() => new Client({ rekeyInterval: 2_147_483_648 })).toThrow("between 0")

        expect(() => new Server({ rekeyBytes: Number.MAX_SAFE_INTEGER + 1 })).toThrow(
            "non-negative safe integer",
        )
        expect(() => new Server({ rekeyInterval: 1.5 })).toThrow("between 0")
    })
})
