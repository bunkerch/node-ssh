import { access, rm } from "node:fs/promises"
import { AddressInfo, createConnection } from "node:net"
import { tmpdir } from "node:os"
import { join } from "node:path"
import Client from "../../src/Client.js"
import Server from "../../src/Server.js"
import ServerClient from "../../src/ServerClient.js"
import SessionChannel from "../../src/channels/SessionChannel.js"
import RequestFailure from "../../src/packets/RequestFailure.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

describe("client/server integration", () => {
    test("completes an encrypted handshake and none authentication over fragmented-safe transport", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({ hostKeys: [hostKey], sendAllHostKeys: false })
        const serverErrors: Error[] = []
        server.hooker.hook("noneAuthentication", (_hook, _context, controller) => {
            controller.allowLogin = true
        })
        server.hooker.hook("tcpipForward", (_hook, context, controller) => {
            controller.allow = context.bindAddress === "127.0.0.1" && context.bindPort === 0
        })
        const streamLocalPath = join(
            tmpdir(),
            `modernssh-integration-${process.pid}-${Date.now()}.sock`,
        )
        server.hooker.hook("streamLocalForward", (_hook, context, controller) => {
            controller.allow = context.socketPath === streamLocalPath
        })
        server.hooker.hook("channelOpenRequest", (_hook, channel, controller) => {
            controller.allowOpen = channel instanceof SessionChannel
        })
        let serverPeer: ServerClient | undefined
        server.on("connection", (peer) => {
            serverPeer = peer
            peer.on("error", (error) => serverErrors.push(error))
        })

        server.listen({ host: "127.0.0.1", port: 0 })
        await new Promise<void>((resolve) => server.server!.once("listening", resolve))

        const address = server.server!.address() as AddressInfo
        const client = new Client({
            hostname: "127.0.0.1",
            port: address.port,
            username: "integration-test",
        })
        const clientErrors: Error[] = []
        let connectEvents = 0
        client.on("error", (error) => clientErrors.push(error))
        client.on("connect", () => connectEvents++)

        try {
            await client.connect()

            expect(client.hasAuthenticated).toBe(true)
            expect(client.isConnected).toBe(true)
            expect(client.setNoDelay()).toBe(client)
            expect(connectEvents).toBe(1)
            expect(serverErrors).toEqual([])
            expect(clientErrors).toEqual([])

            const forwardedPort = await client.forwardIn("127.0.0.1", 0)
            expect(forwardedPort).toBeGreaterThan(0)
            expect(forwardedPort).toBeLessThanOrEqual(65_535)
            await client.unforwardIn("127.0.0.1", forwardedPort)
            const listenerStillAccepts = await new Promise<boolean>((resolve) => {
                const probe = createConnection({ host: "127.0.0.1", port: forwardedPort })
                probe.once("connect", () => {
                    probe.destroy()
                    resolve(true)
                })
                probe.once("error", () => resolve(false))
            })
            expect(listenerStillAccepts).toBe(false)

            await client.openssh_forwardInStreamLocal(streamLocalPath)
            await access(streamLocalPath)
            await client.openssh_unforwardInStreamLocal(streamLocalPath)
            for (let attempt = 0; attempt < 50; attempt++) {
                try {
                    await access(streamLocalPath)
                } catch (error) {
                    if ((error as NodeJS.ErrnoException).code === "ENOENT") break
                    throw error
                }
                await new Promise<void>((resolve) => setTimeout(resolve, 10))
            }
            await expect(access(streamLocalPath)).rejects.toMatchObject({ code: "ENOENT" })

            const existingSession = await client.openSession()
            await client.openssh_noMoreSessions()
            expect(serverPeer?.noMoreSessions).toBe(true)
            expect(existingSession.destroyed).toBe(false)
            await expect(client.openSession()).rejects.toThrow(
                "Additional SSH session channels have been disabled",
            )
            const sessionClosed = new Promise<void>((resolve) =>
                existingSession.once("close", resolve),
            )
            existingSession.close()
            await sessionClosed
            expect(serverErrors).toEqual([])
            expect(clientErrors).toEqual([])
        } finally {
            const closed = new Promise<void>((resolve) => client.once("close", resolve))
            expect(client.end()).toBe(client)
            expect(client.end()).toBe(client)
            await closed
            expect(client.isConnected).toBe(false)
            await new Promise<void>((resolve, reject) => {
                server.server!.close((error) => (error ? reject(error) : resolve()))
            })
            await rm(streamLocalPath, { force: true })
        }
    }, 15_000)

    test("disconnects after the configured unanswered keepalive limit", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({ hostKeys: [hostKey], sendAllHostKeys: false })
        server.hooker.hook("noneAuthentication", (_hook, _context, controller) => {
            controller.allowLogin = true
        })
        server.on("connection", (peer) => {
            const sendPacket = peer.sendPacket.bind(peer)
            peer.sendPacket = (packet) =>
                packet instanceof RequestFailure ? 0 : sendPacket(packet)
            peer.on("error", () => undefined)
        })
        server.listen({ host: "127.0.0.1", port: 0 })
        await new Promise<void>((resolve) => server.server!.once("listening", resolve))

        const client = new Client({
            hostname: "127.0.0.1",
            port: (server.server!.address() as AddressInfo).port,
            username: "keepalive-test",
            keepaliveInterval: 20,
            keepaliveCountMax: 1,
        })
        const errors: Error[] = []
        client.on("error", (error) => errors.push(error))

        await client.connect()
        await new Promise<void>((resolve) => client.once("close", resolve))
        expect(errors.map((error) => error.message)).toEqual(["SSH keepalive timeout"])
        expect(client.isConnected).toBe(false)

        await new Promise<void>((resolve, reject) => {
            server.server!.close((error) => (error ? reject(error) : resolve()))
        })
    })
})
