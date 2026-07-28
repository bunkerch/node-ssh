import { expect, test } from "bun:test"
import { once } from "node:events"
import { createConnection, type AddressInfo } from "node:net"
import { PassThrough } from "node:stream"
import { setImmediate } from "node:timers/promises"
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

test("the server exposes synchronous lifecycle state and async disposal", async () => {
    const server = new Server({
        hostKeys: [await PrivateKey.generate("ssh-ed25519")],
        sendAllHostKeys: false,
    })
    expect(server.listening).toBe(false)
    expect(server.connections).toBe(0)

    server.listen({ host: "127.0.0.1", port: 0 })
    await once(server, "listening")
    expect(server.listening).toBe(true)

    await server[Symbol.asyncDispose]()
    expect(server.listening).toBe(false)
    expect(server.connections).toBe(0)
    await server[Symbol.asyncDispose]()
})

test("server close is idempotent while shutdown is in progress", async () => {
    const server = new Server({
        hostKeys: [await PrivateKey.generate("ssh-ed25519")],
        sendAllHostKeys: false,
    })
    server.listen({ host: "127.0.0.1", port: 0 })
    await once(server, "listening")

    const socket = createConnection({
        host: "127.0.0.1",
        port: (server.address() as AddressInfo).port,
    })
    socket.on("error", () => undefined)
    await once(socket, "connect")

    const firstClose = server.close()
    expect(server.close()).toBe(firstClose)
    expect(() => server.listen({ host: "127.0.0.1", port: 0 })).toThrow("SSH server is closing")
    let disposed = false
    const disposal = server[Symbol.asyncDispose]().then(() => {
        disposed = true
    })
    await setImmediate()
    expect(disposed).toBe(false)

    socket.destroy()
    await Promise.all([firstClose, disposal])
    await expect(server.close()).resolves.toBeUndefined()

    server.listen({ host: "127.0.0.1", port: 0 })
    await once(server, "listening")
    await server[Symbol.asyncDispose]()
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
    const dropped = once(server, "drop")
    const second = createConnection({
        host: "127.0.0.1",
        port: (server.address() as AddressInfo).port,
    })
    second.on("error", () => undefined)
    const secondClosed = once(second, "close")

    try {
        await admissionStarted.promise
        expect(await server.getConnections()).toBe(1)
        expect(server.connections).toBe(1)

        const [dropInfo] = await dropped
        await secondClosed
        expect(Object.isFrozen(dropInfo)).toBe(true)
        expect(dropInfo.remoteAddress).toBe("127.0.0.1")
        expect(dropInfo.localAddress).toBe("127.0.0.1")
        expect(admissionAttempts).toBe(1)

        const admitted = once(server, "connection")
        releaseAdmission.resolve()
        const [client] = await admitted
        const closed = once(client, "close")
        client.terminate()
        await closed
        expect(await server.getConnections()).toBe(0)
        expect(server.connections).toBe(0)
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
        expect(server.connections).toBe(1)

        const dropped = once(server, "drop")
        const rejected = once(second, "close")
        expect(server.injectSocket(second)).toBe(server)
        const [dropInfo] = await dropped
        await rejected
        expect(dropInfo).toEqual({
            remoteAddress: undefined,
            remoteFamily: undefined,
            remotePort: undefined,
            localAddress: undefined,
            localFamily: undefined,
            localPort: undefined,
        })
        expect(await server.getConnections()).toBe(1)
        expect(server.connections).toBe(1)
    } finally {
        first.destroy()
        second.destroy()
    }
})
