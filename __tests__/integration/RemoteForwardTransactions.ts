import { once } from "node:events"
import { mkdtemp, rm } from "node:fs/promises"
import type { AddressInfo } from "node:net"
import { tmpdir } from "node:os"
import { join } from "node:path"

import Client from "../../src/Client.js"
import type Packet from "../../src/packet.js"
import { ProtocolError } from "../../src/packets/Disconnect.js"
import RequestSuccess from "../../src/packets/RequestSuccess.js"
import Server from "../../src/Server.js"
import type ServerClient from "../../src/ServerClient.js"
import { SSHAuthenticationMethods } from "../../src/constants.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

function within<T>(operation: Promise<T>, label: string): Promise<T> {
    let timer: NodeJS.Timeout | undefined
    const timeout = new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => reject(new Error(`Timed out waiting for ${label}`)), 500)
        timer.unref()
    })
    return Promise.race([operation, timeout]).finally(() => {
        if (timer !== undefined) clearTimeout(timer)
    })
}

async function createPeers(options: { maxRemoteForwardings?: number } = {}): Promise<{
    client: Client
    server: Server
    connection: ServerClient
    tcpPolicyCalls: () => number
    streamLocalPolicyCalls: () => number
}> {
    let tcpPolicyCalls = 0
    let streamLocalPolicyCalls = 0
    const server = new Server({
        hostKeys: [await PrivateKey.generate("ssh-ed25519")],
        sendAllHostKeys: false,
        maxRemoteForwardings: options.maxRemoteForwardings,
    })
    server.hooker.hook("noneAuthentication", (_hook, _context, decision) => {
        decision.allowLogin = true
    })
    server.hooker.hook("tcpipForward", (_hook, _context, decision) => {
        tcpPolicyCalls++
        decision.allow = true
    })
    server.hooker.hook("streamLocalForward", (_hook, _context, decision) => {
        streamLocalPolicyCalls++
        decision.allow = true
    })
    server.listen({ host: "127.0.0.1", port: 0 })
    await once(server, "listening")

    const client = new Client({
        hostname: "127.0.0.1",
        port: (server.address() as AddressInfo).port,
        username: "remote-forward-transaction-test",
        authenticationMethodsOrder: [SSHAuthenticationMethods.None],
        strictVendor: false,
    })
    client.hooker.hook("hostKey", (_hook, decision) => {
        decision.allowHostKey = true
    })
    await client.connect()
    const [connection] = server.clients
    if (!connection) throw new Error("Server connection was not registered")
    return {
        client,
        server,
        connection,
        tcpPolicyCalls: () => tcpPolicyCalls,
        streamLocalPolicyCalls: () => streamLocalPolicyCalls,
    }
}

function transformNextSuccess(connection: ServerClient, transform: (args: Buffer) => Buffer): void {
    const sendPacket = connection.sendPacket.bind(connection)
    let transformed = false
    connection.sendPacket = (packet: Packet): number => {
        if (!transformed && packet instanceof RequestSuccess) {
            transformed = true
            return sendPacket(
                new RequestSuccess({ args: Buffer.from(transform(Buffer.from(packet.data.args))) }),
            )
        }
        return sendPacket(packet)
    }
}

async function closePeers(client: Client, server: Server): Promise<void> {
    client.destroy()
    for (const connection of server.clients) connection.terminate()
    await server.close()
}

function failNextServerRequestSuccess(server: Server): void {
    const failSuccess = (...message: unknown[]) => {
        const packet = message[2]
        if (
            message[1] !== "Sending packet:" ||
            typeof packet !== "object" ||
            packet === null ||
            !("type" in packet) ||
            packet.type !== "SSH_MSG_REQUEST_SUCCESS"
        ) {
            return
        }
        server.off("debug", failSuccess)
        throw new Error("request success observer failed")
    }
    server.on("debug", failSuccess)
}

test("rejects active and pending fixed TCP forwarding duplicates locally", async () => {
    const { client, server, tcpPolicyCalls } = await createPeers()
    let releasePolicy!: () => void
    const blocked = new Promise<void>((resolve) => {
        releasePolicy = resolve
    })
    let reportPolicyStarted!: () => void
    const policyStarted = new Promise<void>((resolve) => {
        reportPolicyStarted = resolve
    })

    try {
        const port = await client.forwardIn("127.0.0.1", 0)
        expect(tcpPolicyCalls()).toBe(1)
        await expect(client.forwardIn("127.0.0.1", port)).rejects.toThrow(
            `Remote forwarding already exists for 127.0.0.1:${port}`,
        )
        expect(tcpPolicyCalls()).toBe(1)
        await client.unforwardIn("127.0.0.1", port)

        server.hooker.hook("tcpipForward", async (_hook, _context, decision) => {
            reportPolicyStarted()
            await blocked
            decision.allow = true
        })
        const first = client.forwardIn("127.0.0.1", port)
        await within(policyStarted, "the first fixed TCP forwarding policy")
        await expect(client.forwardIn("127.0.0.1", port)).rejects.toThrow(
            `Remote forwarding already exists for 127.0.0.1:${port}`,
        )
        expect(tcpPolicyCalls()).toBe(2)
        releasePolicy()
        expect(await first).toBe(port)
        await client.unforwardIn("127.0.0.1", port)
    } finally {
        releasePolicy()
        await closePeers(client, server)
    }
}, 15_000)

test("rejects active and pending stream-local forwarding duplicates locally", async () => {
    const directory = await mkdtemp(join(tmpdir(), "modernssh-forward-transaction-"))
    const socketPath = join(directory, "forwarded.sock")
    const { client, server, streamLocalPolicyCalls } = await createPeers()
    let releasePolicy!: () => void
    const blocked = new Promise<void>((resolve) => {
        releasePolicy = resolve
    })
    let reportPolicyStarted!: () => void
    const policyStarted = new Promise<void>((resolve) => {
        reportPolicyStarted = resolve
    })
    server.hooker.hook("streamLocalForward", async (_hook, _context, decision) => {
        reportPolicyStarted()
        await blocked
        decision.allow = true
    })

    try {
        const first = client.openssh_forwardInStreamLocal(socketPath)
        await within(policyStarted, "the first stream-local forwarding policy")
        await expect(client.openssh_forwardInStreamLocal(socketPath)).rejects.toThrow(
            `Remote stream-local forwarding already exists for ${socketPath}`,
        )
        expect(streamLocalPolicyCalls()).toBe(1)
        releasePolicy()
        await first

        await expect(client.openssh_forwardInStreamLocal(socketPath)).rejects.toThrow(
            `Remote stream-local forwarding already exists for ${socketPath}`,
        )
        expect(streamLocalPolicyCalls()).toBe(1)
        await client.openssh_unforwardInStreamLocal(socketPath)
    } finally {
        releasePolicy()
        await closePeers(client, server)
        await rm(directory, { recursive: true, force: true })
    }
}, 15_000)

test("rolls back a TCP listener when its success response cannot be emitted", async () => {
    const { client, server } = await createPeers({ maxRemoteForwardings: 1 })
    let failResponse = true
    server.hooker.hook("tcpipForward", (_hook, _context, decision) => {
        if (!failResponse) return
        failResponse = false
        server.once("debug", () => {
            throw new Error("forwarding response observer failed")
        })
        decision.allow = true
    })

    try {
        await expect(client.forwardIn("127.0.0.1", 0)).rejects.toThrow("failed")

        const recoveredPort = await client.forwardIn("127.0.0.1", 0)
        expect(recoveredPort).toBeGreaterThan(0)
        await client.unforwardIn("127.0.0.1", recoveredPort)
    } finally {
        await closePeers(client, server)
    }
}, 15_000)

test("rolls back a stream-local listener when its success response cannot be emitted", async () => {
    const directory = await mkdtemp(join(tmpdir(), "modernssh-forward-rollback-"))
    const failedPath = join(directory, "failed.sock")
    const recoveredPath = join(directory, "recovered.sock")
    const { client, server } = await createPeers({ maxRemoteForwardings: 1 })
    let failResponse = true
    server.hooker.hook("streamLocalForward", (_hook, _context, decision) => {
        if (!failResponse) return
        failResponse = false
        server.once("debug", () => {
            throw new Error("forwarding response observer failed")
        })
        decision.allow = true
    })

    try {
        await expect(client.openssh_forwardInStreamLocal(failedPath)).rejects.toThrow("failed")

        await client.openssh_forwardInStreamLocal(recoveredPath)
        await client.openssh_unforwardInStreamLocal(recoveredPath)
    } finally {
        await closePeers(client, server)
        await rm(directory, { recursive: true, force: true })
    }
}, 15_000)

test("retains a TCP listener when its cancellation success cannot be emitted", async () => {
    const { client, server } = await createPeers()

    try {
        const port = await client.forwardIn("127.0.0.1", 0)
        failNextServerRequestSuccess(server)

        await expect(client.unforwardIn("127.0.0.1", port)).rejects.toThrow("failed")
        await client.unforwardIn("127.0.0.1", port)
    } finally {
        await closePeers(client, server)
    }
}, 15_000)

test("retains a stream-local listener when its cancellation success cannot be emitted", async () => {
    const directory = await mkdtemp(join(tmpdir(), "modernssh-cancel-rollback-"))
    const socketPath = join(directory, "forwarded.sock")
    const { client, server } = await createPeers()

    try {
        await client.openssh_forwardInStreamLocal(socketPath)
        failNextServerRequestSuccess(server)

        await expect(client.openssh_unforwardInStreamLocal(socketPath)).rejects.toThrow("failed")
        await client.openssh_unforwardInStreamLocal(socketPath)
    } finally {
        await closePeers(client, server)
        await rm(directory, { recursive: true, force: true })
    }
}, 15_000)

test("closes after a malformed allocated-port success leaves remote state ambiguous", async () => {
    const { client, server, connection } = await createPeers()
    const closed = once(connection, "close")
    transformNextSuccess(connection, (args) => Buffer.concat([args, Buffer.from([0])]))

    try {
        await expect(client.forwardIn("127.0.0.1", 0)).rejects.toBeInstanceOf(ProtocolError)
        await within(closed, "the malformed forwarding response to close the connection")
        expect(client.isConnected).toBe(false)
    } finally {
        await closePeers(client, server)
    }
}, 15_000)

test("closes after a truncated allocated-port success leaves remote state ambiguous", async () => {
    const { client, server, connection } = await createPeers()
    const closed = once(connection, "close")
    transformNextSuccess(connection, (args) => args.subarray(0, 3))

    try {
        await expect(client.forwardIn("127.0.0.1", 0)).rejects.toBeInstanceOf(ProtocolError)
        await within(closed, "the truncated forwarding response to close the connection")
        expect(client.isConnected).toBe(false)
    } finally {
        await closePeers(client, server)
    }
}, 15_000)

test("closes when a dynamic request reports an already active forwarding port", async () => {
    const { client, server, connection } = await createPeers()

    try {
        const activePort = await client.forwardIn("127.0.0.1", 0)
        const repeatedPort = Buffer.alloc(4)
        repeatedPort.writeUInt32BE(activePort)
        const closed = once(connection, "close")
        transformNextSuccess(connection, () => repeatedPort)
        await expect(client.forwardIn("127.0.0.1", 0)).rejects.toBeInstanceOf(ProtocolError)
        await within(closed, "the repeated allocated port to close the connection")
        expect(client.isConnected).toBe(false)
    } finally {
        await closePeers(client, server)
    }
}, 15_000)

test("closes after response data accompanies fixed TCP forwarding success", async () => {
    const { client, server, connection } = await createPeers()
    const closed = once(connection, "close")
    transformNextSuccess(connection, () => Buffer.from([0]))

    try {
        await expect(client.forwardIn("127.0.0.1", 42_123)).rejects.toBeInstanceOf(ProtocolError)
        await within(closed, "the fixed forwarding response to close the connection")
        expect(client.isConnected).toBe(false)
    } finally {
        await closePeers(client, server)
    }
}, 15_000)

test("closes after response data accompanies stream-local forwarding success", async () => {
    const directory = await mkdtemp(join(tmpdir(), "modernssh-forward-response-"))
    const socketPath = join(directory, "forwarded.sock")
    const { client, server, connection } = await createPeers()
    const closed = once(connection, "close")
    transformNextSuccess(connection, () => Buffer.from([0]))

    try {
        await expect(client.openssh_forwardInStreamLocal(socketPath)).rejects.toBeInstanceOf(
            ProtocolError,
        )
        await within(closed, "the stream-local response to close the connection")
        expect(client.isConnected).toBe(false)
    } finally {
        await closePeers(client, server)
        await rm(directory, { recursive: true, force: true })
    }
}, 15_000)

test("closes after response data accompanies TCP forwarding cancellation", async () => {
    const { client, server, connection } = await createPeers()

    try {
        const port = await client.forwardIn("127.0.0.1", 0)
        const closed = once(connection, "close")
        transformNextSuccess(connection, () => Buffer.from([0]))
        await expect(client.unforwardIn("127.0.0.1", port)).rejects.toBeInstanceOf(ProtocolError)
        await within(closed, "the malformed TCP cancellation response to close the connection")
        expect(client.isConnected).toBe(false)
    } finally {
        await closePeers(client, server)
    }
}, 15_000)

test("closes after response data accompanies stream-local forwarding cancellation", async () => {
    const directory = await mkdtemp(join(tmpdir(), "modernssh-cancel-response-"))
    const socketPath = join(directory, "forwarded.sock")
    const { client, server, connection } = await createPeers()

    try {
        await client.openssh_forwardInStreamLocal(socketPath)
        const closed = once(connection, "close")
        transformNextSuccess(connection, () => Buffer.from([0]))
        await expect(client.openssh_unforwardInStreamLocal(socketPath)).rejects.toBeInstanceOf(
            ProtocolError,
        )
        await within(
            closed,
            "the malformed stream-local cancellation response to close the connection",
        )
        expect(client.isConnected).toBe(false)
    } finally {
        await closePeers(client, server)
        await rm(directory, { recursive: true, force: true })
    }
}, 15_000)

test("closes after response data accompanies no-more-sessions success", async () => {
    const { client, server, connection } = await createPeers()
    const closed = once(connection, "close")
    transformNextSuccess(connection, () => Buffer.from([0]))

    try {
        await expect(client.openssh_noMoreSessions()).rejects.toBeInstanceOf(ProtocolError)
        await within(closed, "the malformed no-more-sessions response to close the connection")
        expect(client.isConnected).toBe(false)
    } finally {
        await closePeers(client, server)
    }
}, 15_000)
