import { once } from "node:events"
import net, { type AddressInfo } from "node:net"
import { Duplex, PassThrough } from "node:stream"

import Client from "../../src/Client.js"
import Server from "../../src/Server.js"
import { SSHAuthenticationMethods } from "../../src/constants.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

function createTransportPair(): readonly [Duplex, Duplex] {
    const clientToServer = new PassThrough()
    const serverToClient = new PassThrough()
    return [
        Duplex.from({ readable: serverToClient, writable: clientToServer }),
        Duplex.from({ readable: clientToServer, writable: serverToClient }),
    ]
}

test("pauses the readable transport while host-key policy is awaited", async () => {
    const server = new Server({
        hostKeys: [await PrivateKey.generate("ssh-ed25519")],
        sendAllHostKeys: false,
        algorithms: { kex: ["curve25519-sha256"] },
    })
    server.hooker.hook("noneAuthentication", (_hook, _context, decision) => {
        decision.allowLogin = true
    })
    server.listen({ host: "127.0.0.1", port: 0 })
    await once(server, "listening")

    const transport = net.connect({
        host: "127.0.0.1",
        port: (server.address() as AddressInfo).port,
    })
    await once(transport, "connect")
    const client = new Client({
        hostname: "127.0.0.1",
        username: "inbound-backpressure-test",
        sock: transport,
        authenticationMethodsOrder: [SSHAuthenticationMethods.None],
        algorithms: { kex: ["curve25519-sha256"] },
    })
    let releasePolicy!: () => void
    const policyReleased = new Promise<void>((resolve) => {
        releasePolicy = resolve
    })
    let reportPolicyStarted!: () => void
    const policyStarted = new Promise<void>((resolve) => {
        reportPolicyStarted = resolve
    })
    client.hooker.hook("hostKey", async (_hook, decision) => {
        reportPolicyStarted()
        await policyReleased
        decision.allowHostKey = true
    })

    try {
        const connected = client.connect()
        await policyStarted
        expect(transport.isPaused()).toBe(true)
        releasePolicy()
        await connected
        expect(transport.isPaused()).toBe(false)
    } finally {
        releasePolicy()
        client.destroy()
        for (const connection of server.clients) connection.terminate()
        await server.close()
    }
})

test("pauses an injected server transport while a key-exchange packet is handled", async () => {
    const server = new Server({
        hostKeys: [await PrivateKey.generate("ssh-ed25519")],
        sendAllHostKeys: false,
        algorithms: { kex: ["curve25519-sha256"] },
    })
    server.hooker.hook("noneAuthentication", (_hook, _context, decision) => {
        decision.allowLogin = true
    })
    const [clientTransport, serverTransport] = createTransportPair()
    clientTransport.on("error", () => undefined)
    serverTransport.on("error", () => undefined)
    let pausedWhileHandlingExchange: boolean | undefined
    server.on("connection", (connection) => {
        connection.on("error", () => undefined)
        connection.on("clientKexDHInit", () => {
            pausedWhileHandlingExchange = serverTransport.isPaused()
        })
    })
    server.injectSocket(serverTransport)

    const client = new Client({
        hostname: "injected.test",
        username: "inbound-backpressure-test",
        sock: clientTransport,
        authenticationMethodsOrder: [SSHAuthenticationMethods.None],
        algorithms: { kex: ["curve25519-sha256"] },
    })
    client.on("error", () => undefined)
    client.hooker.hook("hostKey", (_hook, decision) => {
        decision.allowHostKey = true
    })

    try {
        await client.connect()
        expect(pausedWhileHandlingExchange).toBe(true)
        expect(serverTransport.isPaused()).toBe(false)
    } finally {
        client.destroy()
        for (const connection of server.clients) connection.terminate()
        await server.close()
    }
})
