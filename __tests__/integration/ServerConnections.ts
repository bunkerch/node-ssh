import { expect, test } from "bun:test"
import { once } from "node:events"
import { createConnection, type AddressInfo } from "node:net"
import { PassThrough } from "node:stream"
import Server from "../../src/Server.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

test("the server connection limit accepts only non-negative integers or infinity", async () => {
    const server = new Server({
        hostKeys: [await PrivateKey.generate("ssh-ed25519")],
        sendAllHostKeys: false,
    })

    expect(server.maxConnections).toBe(Infinity)
    server.maxConnections = 0
    expect(server.maxConnections).toBe(0)
    server.maxConnections = 12
    expect(server.maxConnections).toBe(12)
    server.maxConnections = Infinity
    expect(server.maxConnections).toBe(Infinity)
    expect(() => (server.maxConnections = -1)).toThrow(
        "SSH server maximum connections must be a non-negative integer or Infinity",
    )
    expect(() => (server.maxConnections = 1.5)).toThrow(
        "SSH server maximum connections must be a non-negative integer or Infinity",
    )
    expect(() => (server.maxConnections = Number.NaN)).toThrow(
        "SSH server maximum connections must be a non-negative integer or Infinity",
    )
})

test("a pending TCP admission counts toward the server connection limit", async () => {
    const server = new Server({
        hostKeys: [await PrivateKey.generate("ssh-ed25519")],
        sendAllHostKeys: false,
    })
    server.maxConnections = 1
    const admissionStarted = Promise.withResolvers<void>()
    const releaseAdmission = Promise.withResolvers<void>()
    let admissionAttempts = 0
    server.hooker.hook("preconnect", async (_hook, controller) => {
        admissionAttempts++
        admissionStarted.resolve()
        await releaseAdmission.promise
        controller.allowConnection = true
    })
    server.listen({ host: "127.0.0.1", port: 0 })
    await once(server, "listening")

    const first = createConnection({
        host: "127.0.0.1",
        port: (server.address() as AddressInfo).port,
    })
    first.on("error", () => undefined)
    const second = createConnection({
        host: "127.0.0.1",
        port: (server.address() as AddressInfo).port,
    })
    second.on("error", () => undefined)

    try {
        await admissionStarted.promise
        expect(await server.getConnections()).toBe(1)

        await once(second, "close")
        expect(admissionAttempts).toBe(1)

        const admitted = once(server, "connection")
        releaseAdmission.resolve()
        const [client] = await admitted
        const closed = once(client, "close")
        client.terminate()
        await closed
        expect(await server.getConnections()).toBe(0)
    } finally {
        releaseAdmission.resolve()
        first.destroy()
        second.destroy()
        for (const client of server.clients) client.terminate()
        await server.close()
    }
}, 15_000)

test("an injected transport reserves its connection slot synchronously", async () => {
    const server = new Server({
        hostKeys: [await PrivateKey.generate("ssh-ed25519")],
        sendAllHostKeys: false,
    })
    server.maxConnections = 1
    const first = new PassThrough()
    const second = new PassThrough()

    try {
        expect(server.injectSocket(first)).toBe(server)
        expect(await server.getConnections()).toBe(1)

        const rejected = once(second, "close")
        expect(server.injectSocket(second)).toBe(server)
        await rejected
        expect(await server.getConnections()).toBe(1)
    } finally {
        first.destroy()
        second.destroy()
    }
})
