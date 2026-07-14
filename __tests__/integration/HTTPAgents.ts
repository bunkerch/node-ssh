import { createServer as createHTTPServer } from "node:http"
import { AddressInfo, createConnection, type Server as NetServer } from "node:net"
import type { Duplex } from "node:stream"
import { SSHHTTPAgent } from "../../src/HTTPAgents.js"
import DirectTCPIPChannel from "../../src/channels/DirectTCPIPChannel.js"
import Server from "../../src/Server.js"
import { SSHAuthenticationMethods } from "../../src/constants.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

function listen(server: NetServer): Promise<void> {
    return new Promise((resolve) => {
        server.once("listening", resolve)
        server.listen(0, "127.0.0.1")
    })
}

function close(server: NetServer): Promise<void> {
    return new Promise((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()))
    })
}

describe("SSH-backed HTTP agents", () => {
    test("performs an HTTP request through an RFC 4254 direct-tcpip channel", async () => {
        const destination = createHTTPServer((request, response) => {
            response.setHeader("content-type", "text/plain")
            response.end(`${request.method} ${request.url} via ${request.headers.host}`)
        })
        await listen(destination)
        const destinationPort = (destination.address() as AddressInfo).port

        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({ hostKeys: [hostKey], sendAllHostKeys: false })
        const forwarded: DirectTCPIPChannel[] = []
        const errors: Error[] = []
        server.hooker.hook("noneAuthentication", (_hook, _context, decision) => {
            decision.allowLogin = true
        })
        server.hooker.hook("channelOpenRequest", (_hook, channel, decision) => {
            decision.allowOpen =
                channel instanceof DirectTCPIPChannel &&
                channel.details.destinationHost === "127.0.0.1" &&
                channel.details.destinationPort === destinationPort
        })
        server.on("connection", (connection) => {
            connection.on("error", (error) => errors.push(error))
            connection.on("channel", (channel) => {
                if (!(channel instanceof DirectTCPIPChannel)) return
                forwarded.push(channel)
                const socket = createConnection({
                    host: channel.details.destinationHost,
                    port: channel.details.destinationPort,
                })
                socket.on("error", (error) => channel.stream.destroy(error))
                channel.stream.pipe(socket).pipe(channel.stream)
            })
        })
        server.listen({ host: "127.0.0.1", port: 0 })
        await new Promise<void>((resolve) => server.server!.once("listening", resolve))
        const sshPort = (server.server!.address() as AddressInfo).port
        const agent = new SSHHTTPAgent(
            {
                hostname: "127.0.0.1",
                port: sshPort,
                username: "interop",
                authenticationMethodsOrder: [SSHAuthenticationMethods.None],
            },
            { sourceHost: "agent.example", sourcePort: 42_424 },
        )

        try {
            const socket = await new Promise<Duplex>((resolve, reject) => {
                agent.createConnection(
                    { host: "127.0.0.1", port: destinationPort },
                    (error, stream) => (error || !stream ? reject(error) : resolve(stream)),
                )
            })
            const response = new Promise<string>((resolve, reject) => {
                const chunks: Buffer[] = []
                socket.on("data", (chunk: Buffer) => chunks.push(chunk))
                socket.on("end", () => resolve(Buffer.concat(chunks).toString()))
                socket.on("error", reject)
            })
            socket.write(
                `GET /health?full=1 HTTP/1.1\r\nHost: 127.0.0.1:${destinationPort}\r\nConnection: close\r\n\r\n`,
            )
            const rawResponse = await response

            expect(rawResponse).toContain("HTTP/1.1 200 OK")
            expect(rawResponse).toEndWith(`GET /health?full=1 via 127.0.0.1:${destinationPort}`)
            expect(forwarded).toHaveLength(1)
            expect(forwarded[0]?.details).toEqual({
                destinationHost: "127.0.0.1",
                destinationPort,
                sourceHost: "agent.example",
                sourcePort: 42_424,
            })
            expect(errors).toEqual([])

            let callbacks = 0
            await new Promise<void>((resolve) => {
                agent.createConnection({ host: "127.0.0.1", port: 0 }, (error) => {
                    callbacks++
                    expect(error).toBeInstanceOf(RangeError)
                    resolve()
                })
            })
            await new Promise<void>((resolve) => queueMicrotask(resolve))
            expect(callbacks).toBe(1)
        } finally {
            agent.destroy()
            for (const client of server.clients) client.terminate()
            await close(server.server!)
            await close(destination)
        }
    })
})
