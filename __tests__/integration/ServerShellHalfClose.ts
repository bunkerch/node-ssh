import { once } from "node:events"
import type { AddressInfo } from "node:net"
import Client from "../../src/Client.js"
import { SSHAuthenticationMethods } from "../../src/constants.js"
import Server from "../../src/Server.js"
import type ServerClient from "../../src/ServerClient.js"
import SessionChannel from "../../src/channels/SessionChannel.js"
import type Shell from "../../src/channels/Session/Shell.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

test("ending server stdout keeps the shell open for client stdin", async () => {
    const hostKey = await PrivateKey.generate("ssh-ed25519")
    const server = new Server({ hostKeys: [hostKey], sendAllHostKeys: false })
    server.hooker.hook("noneAuthentication", (_hook, _context, controller) => {
        controller.allowLogin = true
    })
    server.hooker.hook("channelOpenRequest", (_hook, channel, controller) => {
        controller.allowOpen = channel instanceof SessionChannel
    })
    let peer: ServerClient | undefined
    let serverChannel: SessionChannel | undefined
    server.on("connection", (connection) => {
        peer = connection
        connection.on("channel", (channel) => {
            if (!(channel instanceof SessionChannel)) return
            serverChannel = channel
            channel.hooker.hook("shellRequest", (_hook, controller) => {
                controller.success = true
            })
        })
    })
    server.listen({ host: "127.0.0.1", port: 0 })
    await once(server, "listening")

    const client = new Client({
        hostname: "127.0.0.1",
        port: (server.address() as AddressInfo).port,
        username: "shell-half-close-test",
        authenticationMethodsOrder: [SSHAuthenticationMethods.None],
    })
    client.hooker.hook("hostKey", (_hook, controller) => {
        controller.allowHostKey = true
    })

    try {
        await client.connect()
        const clientChannel = await client.openSession()
        const shellOpened = once(serverChannel!.events, "shell")
        await clientChannel.shell()
        const [serverShell] = (await shellOpened) as [Shell]

        const clientOutput: Buffer[] = []
        const serverInput: Buffer[] = []
        clientChannel.on("data", (data: Buffer) => clientOutput.push(data))
        serverShell.on("data", (data: Buffer) => serverInput.push(data))
        serverShell.on("end", () => serverShell.close())
        const outputEnded = once(clientChannel, "end")
        const channelClosed = once(clientChannel, "close")

        serverShell.end("server output complete")
        await outputEnded
        await new Promise<void>((resolve) => setImmediate(resolve))

        expect(Buffer.concat(clientOutput).toString()).toBe("server output complete")
        expect(clientChannel.isOpen).toBe(true)
        expect(clientChannel.destroyed).toBe(false)
        expect(clientChannel.allowHalfOpen).toBe(true)
        expect(clientChannel.writableEnded).toBe(false)
        expect(serverShell.destroyed).toBe(false)
        expect(serverShell.readableEnded).toBe(false)

        const channelDataReceived = once(serverShell, "data", {
            signal: AbortSignal.timeout(1_000),
        })
        await clientChannel.sendData("client input after server EOF")
        const [channelData] = await channelDataReceived
        expect(channelData.toString()).toBe("client input after server EOF")
        clientChannel.end()
        await channelClosed
        expect(Buffer.concat(serverInput).toString()).toBe("client input after server EOF")
    } finally {
        client.destroy()
        peer?.terminate()
        await server.close()
    }
}, 15_000)
