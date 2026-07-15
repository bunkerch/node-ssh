import { once } from "node:events"
import { mkdtemp, rm } from "node:fs/promises"
import type { AddressInfo } from "node:net"
import { tmpdir } from "node:os"
import { join } from "node:path"

import Client from "../../src/Client.js"
import Server from "../../src/Server.js"
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

async function createPeers(): Promise<{
    client: Client
    server: Server
    tcpPolicyCalls: () => number
    streamLocalPolicyCalls: () => number
}> {
    let tcpPolicyCalls = 0
    let streamLocalPolicyCalls = 0
    const server = new Server({
        hostKeys: [await PrivateKey.generate("ssh-ed25519")],
        sendAllHostKeys: false,
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
    return {
        client,
        server,
        tcpPolicyCalls: () => tcpPolicyCalls,
        streamLocalPolicyCalls: () => streamLocalPolicyCalls,
    }
}

async function closePeers(client: Client, server: Server): Promise<void> {
    client.destroy()
    for (const connection of server.clients) connection.terminate()
    await server.close()
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
