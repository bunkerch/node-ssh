import { AddressInfo } from "node:net"
import type { Duplex } from "node:stream"
import Client from "../../src/Client.js"
import { SSHAuthenticationMethods } from "../../src/constants.js"
import Server from "../../src/Server.js"
import SessionChannel from "../../src/channels/SessionChannel.js"
import Agent, { AgentType } from "../../src/publickey/Agent.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

const forwardableAgent: Agent<string> = {
    type: AgentType.NonInteractive,
    async getPublicKeys() {
        return []
    },
    async getPublicKey() {
        throw new Error("No fixture identity")
    },
    async sign() {
        throw new Error("No fixture identity")
    },
    async getStream(): Promise<Duplex> {
        throw new Error("The server must not open an agent channel in this test")
    },
}

describe("client agent-forwarding defaults", () => {
    test("awaits the connection default before the program request and honors a session opt-out", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({ hostKeys: [hostKey], sendAllHostKeys: false })
        const requests: string[] = []
        server.hooker.hook("noneAuthentication", (_hook, _context, decision) => {
            decision.allowLogin = true
        })
        server.hooker.hook("channelOpenRequest", (_hook, channel, decision) => {
            decision.allowOpen = channel instanceof SessionChannel
        })
        server.on("connection", (connection) => {
            connection.on("channel", (channel) => {
                if (!(channel instanceof SessionChannel)) return
                channel.hooker.hook("agentForwardRequest", async (_hook, decision) => {
                    await Promise.resolve()
                    requests.push("agent")
                    decision.success = true
                })
                channel.hooker.hook("execRequest", (_hook, context, decision) => {
                    requests.push(`exec:${context.command}`)
                    decision.success = true
                })
            })
        })
        server.listen({ host: "127.0.0.1", port: 0 })
        await new Promise<void>((resolve) => server.server!.once("listening", resolve))

        const client = new Client({
            hostname: "127.0.0.1",
            port: (server.server!.address() as AddressInfo).port,
            username: "forwarding-default",
            agent: forwardableAgent,
            agentForward: true,
            strictVendor: false,
            authenticationMethodsOrder: [SSHAuthenticationMethods.None],
        })
        client.hooker.hook("hostKey", (_hook, decision) => {
            decision.allowHostKey = true
        })
        let optInClient: Client | undefined

        try {
            await client.connect()
            const forwarded = await client.exec("forwarded")
            const isolated = await client.exec("isolated", { agentForward: false })
            expect(requests).toEqual(["agent", "exec:forwarded", "exec:isolated"])
            forwarded.close()
            isolated.close()

            optInClient = new Client({
                hostname: "127.0.0.1",
                port: (server.server!.address() as AddressInfo).port,
                username: "forwarding-opt-in",
                agent: forwardableAgent,
                strictVendor: false,
                authenticationMethodsOrder: [SSHAuthenticationMethods.None],
            })
            optInClient.hooker.hook("hostKey", (_hook, decision) => {
                decision.allowHostKey = true
            })
            await optInClient.connect()
            const explicit = await optInClient.exec("explicit", { agentForward: true })
            expect(requests).toEqual([
                "agent",
                "exec:forwarded",
                "exec:isolated",
                "agent",
                "exec:explicit",
            ])
            explicit.close()
        } finally {
            client.destroy()
            optInClient?.destroy()
            for (const connection of server.clients) connection.terminate()
            await new Promise<void>((resolve, reject) => {
                server.server!.close((error) => (error ? reject(error) : resolve()))
            })
        }
    }, 15_000)

    test("keeps the connection default disabled", () => {
        expect(new Client({}).options.agentForward).toBe(false)
    })
})
