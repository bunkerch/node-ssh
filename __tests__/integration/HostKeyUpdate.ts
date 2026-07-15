import { once } from "node:events"
import Client, { GlobalRequestError } from "../../src/Client.js"
import { SSHAuthenticationMethods } from "../../src/constants.js"
import Packet from "../../src/packet.js"
import GlobalRequest from "../../src/packets/GlobalRequest.js"
import Server from "../../src/Server.js"
import { serializeBuffer } from "../../src/utils/Buffer.js"
import {
    HOST_KEYS_EXTENSION,
    HOST_KEYS_EXTENSION_VERSION,
    HOST_KEYS_PROOF_REQUEST,
    HOST_KEYS_REQUEST,
    LEGACY_HOST_KEYS_PROOF_REQUEST,
} from "../../src/utils/HostKeysProof.js"
import PrivateKey from "../../src/utils/PrivateKey.js"
import PublicKey from "../../src/utils/PublicKey.js"

class GlobalRequestRecordingClient extends Client {
    readonly globalRequests: string[] = []

    override sendPacket(packet: Packet): number {
        if (packet instanceof GlobalRequest) this.globalRequests.push(packet.data.request_name)
        return super.sendPacket(packet)
    }
}

async function close(server: Server, client: Client): Promise<void> {
    client.destroy()
    for (const peer of server.clients) peer.terminate()
    await new Promise<void>((resolve, reject) => {
        server.server.close((error) => (error ? reject(error) : resolve()))
    })
}

function allowNoneAuthentication(server: Server): void {
    server.hooker.hook("noneAuthentication", (_hook, context, decision) => {
        decision.allowLogin = context.username === "rotation"
    })
}

function allowHostKey(client: Client): void {
    client.hooker.hook("hostKey", (_hook, decision) => {
        decision.allowHostKey = true
    })
}

describe("standard SSH host-key update", () => {
    test("negotiates version 0 and uses the standard proof request", async () => {
        const hostKeys = await Promise.all([
            PrivateKey.generate("ssh-ed25519"),
            PrivateKey.generate("ecdsa-sha2-nistp256"),
        ])
        const server = new Server({ hostKeys, sendAllHostKeys: true })
        allowNoneAuthentication(server)
        server.listen({ host: "127.0.0.1", port: 0 })
        await once(server.server, "listening")

        const client = new GlobalRequestRecordingClient({
            hostname: "127.0.0.1",
            port: (server.server.address() as { port: number }).port,
            username: "rotation",
            authenticationMethodsOrder: [SSHAuthenticationMethods.None],
        })
        allowHostKey(client)
        const announced = once(client, "hostKeys")

        try {
            await client.connect()
            const [verified] = (await announced) as [readonly PublicKey[]]
            expect(verified).toHaveLength(hostKeys.length)
            expect(
                client.serverExtensions.find(({ name }) => name === HOST_KEYS_EXTENSION),
            ).toEqual({
                name: HOST_KEYS_EXTENSION,
                value: HOST_KEYS_EXTENSION_VERSION,
            })
            expect(client.globalRequests).toContain(HOST_KEYS_PROOF_REQUEST)
            expect(client.globalRequests).not.toContain(LEGACY_HOST_KEYS_PROOF_REQUEST)
        } finally {
            await close(server, client)
        }
    }, 15_000)

    test("falls back to the compatibility proof after a replacement omits version 0", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({ hostKeys: [hostKey], sendAllHostKeys: true })
        server.hooker.hook("noneAuthentication", (_hook, context, decision, connection) => {
            if (connection.clientSupportsAuthenticationExtensionInfo) {
                connection.sendAuthenticationExtensions([
                    { name: "account-policy@example.com", value: Buffer.from(context.username) },
                ])
            }
            decision.allowLogin = context.username === "rotation"
        })
        server.listen({ host: "127.0.0.1", port: 0 })
        await once(server.server, "listening")

        const client = new GlobalRequestRecordingClient({
            hostname: "127.0.0.1",
            port: (server.server.address() as { port: number }).port,
            username: "rotation",
            authenticationMethodsOrder: [SSHAuthenticationMethods.None],
        })
        allowHostKey(client)
        const announced = once(client, "hostKeys")

        try {
            await client.connect()
            await announced
            expect(client.serverExtensions.map(({ name }) => name)).toEqual([
                "account-policy@example.com",
            ])
            expect(client.globalRequests).toContain(LEGACY_HOST_KEYS_PROOF_REQUEST)
            expect(client.globalRequests).not.toContain(HOST_KEYS_PROOF_REQUEST)
        } finally {
            await close(server, client)
        }
    }, 15_000)

    test("accepts a standard advertisement and verifies its standard-domain proof", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({ hostKeys: [hostKey], sendAllHostKeys: false })
        allowNoneAuthentication(server)
        server.on("connection", (peer) => {
            peer.once("connect", () => {
                peer.sendPacket(
                    new GlobalRequest({
                        request_name: HOST_KEYS_REQUEST,
                        want_reply: false,
                        args: serializeBuffer(hostKey.data.publicKey.serialize()),
                    }),
                )
            })
        })
        server.listen({ host: "127.0.0.1", port: 0 })
        await once(server.server, "listening")

        const client = new GlobalRequestRecordingClient({
            hostname: "127.0.0.1",
            port: (server.server.address() as { port: number }).port,
            username: "rotation",
            authenticationMethodsOrder: [SSHAuthenticationMethods.None],
        })
        allowHostKey(client)
        const announced = once(client, "hostKeys")

        try {
            await client.connect()
            const [verified] = (await announced) as [readonly PublicKey[]]
            expect(verified).toHaveLength(1)
            expect(verified[0].equals(hostKey.data.publicKey)).toBe(true)
            expect(client.globalRequests).toContain(HOST_KEYS_PROOF_REQUEST)
        } finally {
            await close(server, client)
        }
    }, 15_000)

    test("uses the initially negotiated RSA-SHA2 algorithm for RSA proofs", async () => {
        const hostKey = await PrivateKey.generate("ssh-rsa")
        const algorithms = { serverHostKey: ["rsa-sha2-256"] }
        const server = new Server({
            hostKeys: [hostKey],
            sendAllHostKeys: true,
            algorithms,
        })
        allowNoneAuthentication(server)
        server.listen({ host: "127.0.0.1", port: 0 })
        await once(server.server, "listening")

        const client = new GlobalRequestRecordingClient({
            hostname: "127.0.0.1",
            port: (server.server.address() as { port: number }).port,
            username: "rotation",
            authenticationMethodsOrder: [SSHAuthenticationMethods.None],
            algorithms,
        })
        allowHostKey(client)
        const announced = once(client, "hostKeys")

        try {
            await client.connect()
            const [verified] = (await announced) as [readonly PublicKey[]]
            expect(verified).toHaveLength(1)
            expect(verified[0].equals(hostKey.data.publicKey)).toBe(true)
            expect(client.globalRequests).toContain(HOST_KEYS_PROOF_REQUEST)
        } finally {
            await close(server, client)
        }
    }, 15_000)

    test("fails proof requests after an explicitly negotiated RSA-SHA1 exchange", async () => {
        const hostKey = await PrivateKey.generate("ssh-rsa")
        const algorithms = { serverHostKey: ["ssh-rsa"] }
        const server = new Server({
            hostKeys: [hostKey],
            sendAllHostKeys: false,
            algorithms,
        })
        allowNoneAuthentication(server)
        server.listen({ host: "127.0.0.1", port: 0 })
        await once(server.server, "listening")

        const client = new Client({
            hostname: "127.0.0.1",
            port: (server.server.address() as { port: number }).port,
            username: "rotation",
            authenticationMethodsOrder: [SSHAuthenticationMethods.None],
            algorithms,
        })
        allowHostKey(client)

        try {
            await client.connect()
            await expect(
                client.globalRequest(
                    HOST_KEYS_PROOF_REQUEST,
                    serializeBuffer(hostKey.data.publicKey.serialize()),
                ),
            ).rejects.toBeInstanceOf(GlobalRequestError)
        } finally {
            await close(server, client)
        }
    }, 15_000)

    test("rejects duplicate keys in a standard advertisement", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const encoded = serializeBuffer(hostKey.data.publicKey.serialize())
        const server = new Server({ hostKeys: [hostKey], sendAllHostKeys: false })
        allowNoneAuthentication(server)
        server.on("connection", (peer) => {
            peer.once("connect", () => {
                peer.sendPacket(
                    new GlobalRequest({
                        request_name: HOST_KEYS_REQUEST,
                        want_reply: false,
                        args: Buffer.concat([encoded, encoded]),
                    }),
                )
            })
        })
        server.listen({ host: "127.0.0.1", port: 0 })
        await once(server.server, "listening")

        const client = new Client({
            hostname: "127.0.0.1",
            port: (server.server.address() as { port: number }).port,
            username: "rotation",
            authenticationMethodsOrder: [SSHAuthenticationMethods.None],
        })
        allowHostKey(client)
        const failed = once(client, "error")

        try {
            await client.connect()
            const [error] = (await failed) as [Error]
            expect(error.message).toContain("advertisement repeats a key")
        } finally {
            await close(server, client)
        }
    }, 15_000)

    test("rejects a second host-key advertisement on the same transport", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({ hostKeys: [hostKey], sendAllHostKeys: false })
        allowNoneAuthentication(server)
        server.on("connection", (peer) => {
            peer.once("connect", () => {
                for (const requestName of [HOST_KEYS_REQUEST, HOST_KEYS_REQUEST]) {
                    peer.sendPacket(
                        new GlobalRequest({
                            request_name: requestName,
                            want_reply: false,
                            args: serializeBuffer(hostKey.data.publicKey.serialize()),
                        }),
                    )
                }
            })
        })
        server.listen({ host: "127.0.0.1", port: 0 })
        await once(server.server, "listening")

        const client = new Client({
            hostname: "127.0.0.1",
            port: (server.server.address() as { port: number }).port,
            username: "rotation",
            authenticationMethodsOrder: [SSHAuthenticationMethods.None],
        })
        allowHostKey(client)
        const failed = once(client, "error")

        try {
            await client.connect()
            const [error] = (await failed) as [Error]
            expect(error.message).toContain("more than one host-key advertisement")
        } finally {
            await close(server, client)
        }
    }, 15_000)

    test("fails empty and duplicate standard proof requests", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const encoded = serializeBuffer(hostKey.data.publicKey.serialize())
        const server = new Server({ hostKeys: [hostKey], sendAllHostKeys: false })
        allowNoneAuthentication(server)
        server.listen({ host: "127.0.0.1", port: 0 })
        await once(server.server, "listening")

        const client = new Client({
            hostname: "127.0.0.1",
            port: (server.server.address() as { port: number }).port,
            username: "rotation",
            authenticationMethodsOrder: [SSHAuthenticationMethods.None],
        })
        allowHostKey(client)

        try {
            await client.connect()
            await expect(client.globalRequest(HOST_KEYS_PROOF_REQUEST)).rejects.toBeInstanceOf(
                GlobalRequestError,
            )
            await expect(
                client.globalRequest(HOST_KEYS_PROOF_REQUEST, Buffer.concat([encoded, encoded])),
            ).rejects.toBeInstanceOf(GlobalRequestError)
            expect(await client.ping(Buffer.from("still-connected"))).toEqual(
                Buffer.from("still-connected"),
            )
        } finally {
            await close(server, client)
        }
    }, 15_000)
})
