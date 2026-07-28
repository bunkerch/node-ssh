import { once } from "node:events"
import type { AddressInfo } from "node:net"
import Client from "../../src/Client.js"
import SessionChannel from "../../src/channels/SessionChannel.js"
import { SSHAuthenticationMethods } from "../../src/constants.js"
import Server from "../../src/Server.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

function neverSettles<T>(): Promise<T> {
    return new Promise<T>(() => undefined)
}

describe("SFTP request deadlines", () => {
    test("closes only the timed-out SFTP channel and keeps the SSH connection usable", async () => {
        const server = new Server({
            hostKeys: [await PrivateKey.generate("ssh-ed25519")],
            sendAllHostKeys: false,
        })
        server.hooker.hook("noneAuthentication", (_hook, _context, decision) => {
            decision.allowLogin = true
        })
        server.hooker.hook("channelOpenRequest", (_hook, channel, decision) => {
            decision.allowOpen = channel instanceof SessionChannel
        })
        server.on("connection", (connection) => {
            connection.on("channel", (channel) => {
                if (!(channel instanceof SessionChannel)) return
                channel.hooker.hook("subsystemRequest", (_hook, context, decision) => {
                    if (context.subsystem !== "sftp") return
                    decision.success = true
                    decision.sftp = {}
                })
                channel.events.on("sftp", (sftp) => {
                    sftp.hooker.hook("STAT", async () => neverSettles())
                })
            })
        })
        server.listen({ host: "127.0.0.1", port: 0 })
        await once(server, "listening")

        const client = new Client({
            hostname: "127.0.0.1",
            port: (server.address() as AddressInfo).port,
            username: "sftp-timeout-test",
            authenticationMethodsOrder: [SSHAuthenticationMethods.None],
        })
        client.hooker.hook("hostKey", (_hook, decision) => {
            decision.allowHostKey = true
        })

        try {
            await client.connect()
            const sftp = await client.sftp({}, { requestTimeout: 40 })
            await expect(sftp.stat("unanswered")).rejects.toThrow(
                "Timed out waiting for SFTP request 1 reply",
            )

            expect(sftp.channel.destroyed).toBe(true)
            expect(client.isConnected).toBe(true)
            const replacement = await client.openSession()
            const replacementClosed = once(replacement, "close")
            replacement.close()
            await replacementClosed
            expect(client.isConnected).toBe(true)
        } finally {
            client.destroy()
            await server.close()
        }
    })

    test("server request timeout closes only the SFTP channel", async () => {
        const server = new Server({
            hostKeys: [await PrivateKey.generate("ssh-ed25519")],
            sendAllHostKeys: false,
        })
        server.hooker.hook("noneAuthentication", (_hook, _context, decision) => {
            decision.allowLogin = true
        })
        server.hooker.hook("channelOpenRequest", (_hook, channel, decision) => {
            decision.allowOpen = channel instanceof SessionChannel
        })
        let timeoutResolve!: (error: Error) => void
        const timedOut = new Promise<Error>((resolve) => {
            timeoutResolve = resolve
        })
        let policySignal: AbortSignal | undefined
        let policyAbortResolve!: () => void
        const policyAborted = new Promise<void>((resolve) => {
            policyAbortResolve = resolve
        })
        server.on("connection", (connection) => {
            connection.on("channel", (channel) => {
                if (!(channel instanceof SessionChannel)) return
                channel.hooker.hook("subsystemRequest", (_hook, context, decision) => {
                    if (context.subsystem !== "sftp") return
                    decision.success = true
                    decision.sftp = { requestTimeout: 40 }
                })
                channel.events.on("sftp", (sftp) => {
                    sftp.on("error", timeoutResolve)
                    sftp.hooker.hook("STAT", async (_hook, _request, operation) => {
                        policySignal = operation.signal
                        operation.signal.addEventListener("abort", policyAbortResolve, {
                            once: true,
                        })
                        await neverSettles()
                    })
                })
            })
        })
        server.listen({ host: "127.0.0.1", port: 0 })
        await once(server, "listening")

        const client = new Client({
            hostname: "127.0.0.1",
            port: (server.address() as AddressInfo).port,
            username: "sftp-server-timeout-test",
            authenticationMethodsOrder: [SSHAuthenticationMethods.None],
        })
        client.hooker.hook("hostKey", (_hook, decision) => {
            decision.allowHostKey = true
        })

        try {
            await client.connect()
            const sftp = await client.sftp({}, { requestTimeout: 1_000 })
            await expect(sftp.stat("unanswered")).rejects.toBeInstanceOf(Error)
            expect((await timedOut).message).toBe("Timed out waiting for SFTP server request 1")
            await policyAborted
            expect(policySignal?.aborted).toBe(true)
            expect((policySignal?.reason as Error).message).toBe(
                "Timed out waiting for SFTP server request 1",
            )

            expect(sftp.channel.destroyed).toBe(true)
            expect(client.isConnected).toBe(true)
            const replacement = await client.openSession()
            const replacementClosed = once(replacement, "close")
            replacement.close()
            await replacementClosed
            expect(client.isConnected).toBe(true)
        } finally {
            client.destroy()
            await server.close()
        }
    })
})
