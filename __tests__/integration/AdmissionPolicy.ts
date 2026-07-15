import { once } from "node:events"
import { createConnection, type AddressInfo } from "node:net"
import Client from "../../src/Client.js"
import { SSHAuthenticationMethods } from "../../src/constants.js"
import Server from "../../src/Server.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

function neverSettles<T>(): Promise<T> {
    return new Promise<T>(() => undefined)
}

test("a rejected async preconnect policy cannot retain an earlier allow decision", async () => {
    const hostKey = await PrivateKey.generate("ssh-ed25519")
    const server = new Server({
        hostKeys: [hostKey],
        sendAllHostKeys: false,
        algorithms: { kex: ["curve25519-sha256"] },
    })
    const hookErrors: Error[] = []
    let admitted = 0
    server.hooker.on("uncaughtException", (_event, error) => hookErrors.push(error))
    server.hooker.hook("preconnect", (_hook, controller) => {
        controller.allowConnection = true
    })
    server.hooker.hook("preconnect", async () => {
        await Promise.resolve()
        throw new Error("admission backend failed")
    })
    server.hooker.hook("noneAuthentication", (_hook, _context, controller) => {
        controller.allowLogin = true
    })
    server.on("connection", () => {
        admitted++
    })
    server.listen({ host: "127.0.0.1", port: 0 })
    await once(server, "listening")

    const client = new Client({
        hostname: "127.0.0.1",
        port: (server.address() as AddressInfo).port,
        username: "rejected-admission",
        authenticationMethodsOrder: [SSHAuthenticationMethods.None],
        algorithms: { kex: ["curve25519-sha256"] },
    })
    client.hooker.hook("hostKey", (_hook, controller) => {
        controller.allowHostKey = true
    })

    try {
        const settlement = await client.connect().then(
            () => "fulfilled" as const,
            () => "rejected" as const,
        )

        expect(settlement).toBe("rejected")
        expect(admitted).toBe(0)
        expect(hookErrors.map((error) => error.message)).toEqual(["admission backend failed"])
        expect(server.clients.size).toBe(0)
    } finally {
        client.destroy()
        for (const connection of server.clients) connection.terminate()
        await server.close()
    }
}, 15_000)

test("the handshake deadline includes an awaited preconnect policy", async () => {
    const diagnostics: unknown[][] = []
    const server = new Server({
        hostKeys: [await PrivateKey.generate("ssh-ed25519")],
        handshakeTimeout: 35,
        debug: (...message) => diagnostics.push(message),
    })
    let resolveClientClose!: () => void
    const clientClosed = new Promise<void>((resolve) => {
        resolveClientClose = resolve
    })
    let admitted = 0
    server.hooker.hook("preconnect", (_hook, _controller, client) => {
        client.once("close", resolveClientClose)
        return neverSettles()
    })
    server.on("connection", () => {
        admitted++
    })
    server.listen({ host: "127.0.0.1", port: 0 })
    await once(server, "listening")

    const socket = createConnection({
        host: "127.0.0.1",
        port: (server.address() as AddressInfo).port,
    })
    socket.on("error", () => undefined)
    const socketClosed = new Promise<void>((resolve) => socket.once("close", resolve))

    try {
        await clientClosed
        await socketClosed
        expect(socket.destroyed).toBe(true)
        expect(admitted).toBe(0)
        expect(server.clients.size).toBe(0)
        expect(await server.getConnections()).toBe(0)
        expect(
            diagnostics.some(
                (message) =>
                    message.includes(
                        "SSH transport error before an error listener was attached:",
                    ) &&
                    message.some(
                        (value) =>
                            value instanceof Error &&
                            value.message === "Timed out while waiting for SSH handshake",
                    ),
            ),
        ).toBe(true)
    } finally {
        socket.destroy()
        await server.close()
    }
}, 15_000)
