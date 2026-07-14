import { once } from "node:events"
import { AddressInfo } from "node:net"

import Client from "../../src/Client.js"
import Channel from "../../src/Channel.js"
import ClientChannel from "../../src/channels/ClientChannel.js"
import ClientSessionChannel from "../../src/channels/ClientSessionChannel.js"
import SessionChannel from "../../src/channels/SessionChannel.js"
import Shell from "../../src/channels/Session/Shell.js"
import { SSHAuthenticationMethods } from "../../src/constants.js"
import type { NoFlowControlPreference } from "../../src/NoFlowControl.js"
import { ChannelOpenFailureReasonCodes } from "../../src/packets/ChannelOpenFailure.js"
import Server from "../../src/Server.js"
import type ServerClient from "../../src/ServerClient.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

async function connectPeers(
    clientPreference: NoFlowControlPreference,
    serverPreference: NoFlowControlPreference,
    replaceServerExtensions = false,
): Promise<{ server: Server; peer: ServerClient; client: Client }> {
    const server = new Server({
        hostKeys: [PrivateKey.generateSync("ssh-ed25519")],
        sendAllHostKeys: false,
        noFlowControl: serverPreference,
    })
    server.hooker.hook("noneAuthentication", (_hook, _context, decision, peer) => {
        if (replaceServerExtensions) peer.sendAuthenticationExtensions([])
        decision.allowLogin = true
    })
    server.hooker.hook("channelOpenRequest", (_hook, channel, decision) => {
        decision.allowOpen = channel instanceof SessionChannel
    })
    let peer: ServerClient | undefined
    server.on("connection", (connection) => {
        peer = connection
        connection.on("error", () => undefined)
        connection.on("channel", (channel) => {
            if (!(channel instanceof SessionChannel)) return
            channel.hooker.hook("shellRequest", (_hook, decision) => {
                decision.success = true
            })
        })
    })
    server.listen({ host: "127.0.0.1", port: 0 })
    await once(server.server, "listening")

    const client = new Client({
        hostname: "127.0.0.1",
        port: (server.address() as AddressInfo).port,
        username: "no-flow-control-test",
        authenticationMethodsOrder: [SSHAuthenticationMethods.None],
        noFlowControl: clientPreference,
    })
    client.on("error", () => undefined)
    client.hooker.hook("hostKey", (_hook, decision) => {
        decision.allowHostKey = true
    })
    await client.connect()
    return { server, peer: peer!, client }
}

async function closePeers(server: Server, client: Client): Promise<void> {
    client.destroy()
    for (const peer of server.clients) peer.terminate()
    await server.close()
}

describe("RFC 8308 no-flow-control integration", () => {
    test.each([
        ["preferred", "supported", true],
        ["supported", "preferred", true],
        ["supported", "supported", false],
        [false, "preferred", false],
        ["preferred", false, false],
    ] as const)(
        "negotiates client %s with server %s as %s",
        async (clientPreference, serverPreference, expected) => {
            const { server, peer, client } = await connectPeers(clientPreference, serverPreference)
            try {
                expect(client.noFlowControl).toBe(expected)
                expect(peer.noFlowControl).toBe(expected)
            } finally {
                await closePeers(server, client)
            }
        },
        15_000,
    )

    test("ignores channel windows in both directions without disabling packet limits", async () => {
        const { server, peer, client } = await connectPeers("preferred", "supported")
        const serverChannelPromise = once(peer, "channel")

        try {
            const clientChannel = await client.openSession()
            const [serverChannel] = (await serverChannelPromise) as [SessionChannel]
            const serverShellPromise = once(serverChannel.events, "shell")
            await clientChannel.shell()
            const [serverShell] = (await serverShellPromise) as [Shell]
            expect(clientChannel).toBeInstanceOf(ClientChannel)
            expect(serverChannel).toBeInstanceOf(Channel)

            clientChannel.remoteWindowSize = 0
            serverChannel.local_window_size = 0
            const clientPayload = Buffer.from("client payload beyond the advertised window")
            const serverData = once(serverShell, "data")
            await clientChannel.sendData(clientPayload)
            expect((await serverData)[0]).toEqual(clientPayload)

            serverChannel.remote_window_size = 0
            clientChannel.localWindowSize = 0
            const serverPayload = Buffer.from("server payload beyond the advertised window")
            const clientData = once(clientChannel, "data")
            await serverShell.writeStdout(serverPayload)
            expect((await clientData)[0]).toEqual(serverPayload)

            clientChannel.remoteWindowSize = 1
            serverChannel.remote_window_size = 1
            clientChannel.receiveWindowAdjust(0xffff_ffff)
            serverChannel.receiveWindowAdjust(0xffff_ffff)
            expect(clientChannel.remoteWindowSize).toBe(1)
            expect(serverChannel.remote_window_size).toBe(1)
        } finally {
            await closePeers(server, client)
        }
    }, 15_000)

    test("allows only one live channel and permits another after complete close", async () => {
        const { server, client } = await connectPeers("preferred", "supported")
        try {
            const first = await client.openSession()
            await expect(client.openSession()).rejects.toThrow("only one simultaneous SSH channel")

            const forcedSecond = new ClientSessionChannel(client)
            client.channels.set(forcedSecond.localId, forcedSecond)
            client.sendPacket(forcedSecond.getOpenPacket())
            await expect(forcedSecond.waitUntilOpen()).rejects.toMatchObject({
                reason_code: ChannelOpenFailureReasonCodes.SSH_OPEN_RESOURCE_SHORTAGE,
            })

            const closed = once(first, "close")
            first.close()
            await closed

            const second = await client.openSession()
            const secondClosed = once(second, "close")
            second.close()
            await secondClosed
        } finally {
            await closePeers(server, client)
        }
    }, 15_000)

    test("re-evaluates the extension when the server replaces its advertised set", async () => {
        const { server, peer, client } = await connectPeers("preferred", "supported", true)
        try {
            expect(client.noFlowControl).toBe(false)
            expect(peer.noFlowControl).toBe(false)

            const first = await client.openSession()
            const second = await client.openSession()
            first.close()
            second.close()
        } finally {
            await closePeers(server, client)
        }
    }, 15_000)
})
