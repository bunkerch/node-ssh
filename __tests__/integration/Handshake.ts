import { access, rm } from "node:fs/promises"
import { execFile } from "node:child_process"
import { AddressInfo, createConnection, createServer } from "node:net"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { promisify } from "node:util"
import Client from "../../src/Client.js"
import ProtocolVersionExchange from "../../src/ProtocolVersionExchange.js"
import Server from "../../src/Server.js"
import ServerClient from "../../src/ServerClient.js"
import SessionChannel from "../../src/channels/SessionChannel.js"
import ClientForwardedTCPIPChannel from "../../src/channels/ClientForwardedTCPIPChannel.js"
import ClientForwardedStreamLocalChannel from "../../src/channels/ClientForwardedStreamLocalChannel.js"
import ForwardedTCPIPChannel from "../../src/channels/ForwardedTCPIPChannel.js"
import Shell from "../../src/channels/Session/Shell.js"
import RequestFailure from "../../src/packets/RequestFailure.js"
import RequestSuccess from "../../src/packets/RequestSuccess.js"
import GlobalRequest from "../../src/packets/GlobalRequest.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

const execFileAsync = promisify(execFile)

describe("client/server integration", () => {
    test("completes an encrypted handshake and none authentication over fragmented-safe transport", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({
            hostKeys: [hostKey],
            sendAllHostKeys: false,
            greeting: "Authorized integration only\nMaintenance at 02:00",
            algorithms: {
                kex: ["curve25519-sha256"],
                serverHostKey: ["ssh-ed25519"],
                cipher: ["aes128-ctr"],
                hmac: ["hmac-sha2-256-etm@openssh.com"],
                compress: ["none"],
            },
        })
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
        let serverRekeys = 0
        const serverHandshakes: unknown[] = []
        const serverExchangeEvents: string[] = []
        let configuredSession: SessionChannel | undefined
        let configuredShell: Shell | undefined
        const breakDurations: number[] = []
        const serverGlobalRequests: string[] = []
        let resolveOneWayGlobalRequest: (() => void) | undefined
        const oneWayGlobalRequest = new Promise<void>((resolve) => {
            resolveOneWayGlobalRequest = resolve
        })
        server.hooker.hook("globalRequest", async (_hook, context, controller) => {
            serverGlobalRequests.push(context.name)
            if (context.name === "ordered-one@example.test") {
                await new Promise<void>((resolve) => setTimeout(resolve, 10))
                controller.success = true
                controller.response = Buffer.from(context.args.toString().toUpperCase())
            } else if (context.name === "ordered-two@example.test") {
                controller.success = true
                controller.response = Buffer.from(context.args.toString().toUpperCase())
            } else if (context.name === "one-way@example.test") {
                resolveOneWayGlobalRequest?.()
            }
        })
        server.on("connection", (peer) => {
            serverPeer = peer
            peer.on("error", (error) => serverErrors.push(error))
            peer.on("rekey", () => serverRekeys++)
            peer.on("handshake", (negotiated) => {
                serverHandshakes.push(negotiated)
                serverExchangeEvents.push("handshake")
            })
            peer.on("rekey", () => serverExchangeEvents.push("rekey"))
            peer.on("channel", (channel) => {
                if (!(channel instanceof SessionChannel)) return
                channel.hooker.hook("ptyRequest", (_hook, _pty, controller) => {
                    controller.success = true
                })
                channel.hooker.hook("envRequest", (_hook, _environment, controller) => {
                    controller.success = true
                })
                channel.hooker.hook("execRequest", (_hook, context, controller) => {
                    controller.success = context.command === "configured-command"
                    if (controller.success) configuredSession = channel
                })
                channel.hooker.hook("breakRequest", async (_hook, context, controller) => {
                    await Promise.resolve()
                    breakDurations.push(context.duration)
                    controller.success = context.duration === 750
                })
                channel.events.on("exec", (_command, shell) => {
                    configuredShell = shell
                })
            })
        })

        server.listen({ host: "127.0.0.1", port: 0 })
        await new Promise<void>((resolve) => server.server!.once("listening", resolve))
        expect(server.ref()).toBe(server)
        expect(server.unref()).toBe(server)
        expect(server.ref()).toBe(server)

        const address = server.address() as AddressInfo
        const client = new Client({
            hostname: "127.0.0.1",
            port: address.port,
            username: "integration-test",
            ident: "modernssh_integration fixed-comment",
            strictVendor: false,
            algorithms: {
                kex: ["curve25519-sha256"],
                serverHostKey: ["ssh-ed25519"],
                cipher: ["aes128-ctr"],
                hmac: ["hmac-sha2-256-etm@openssh.com"],
                compress: ["none"],
            },
        })
        const clientErrors: Error[] = []
        let connectEvents = 0
        let clientRekeys = 0
        const clientHandshakes: unknown[] = []
        const clientExchangeEvents: string[] = []
        const greetings: string[] = []
        client.on("error", (error) => clientErrors.push(error))
        client.on("greeting", (greeting) => greetings.push(greeting))
        client.on("connect", () => connectEvents++)
        client.on("rekey", () => clientRekeys++)
        client.on("handshake", (negotiated) => {
            clientHandshakes.push(negotiated)
            clientExchangeEvents.push("handshake")
        })
        client.on("rekey", () => clientExchangeEvents.push("rekey"))
        const clientGlobalRequests: string[] = []
        client.hooker.hook("globalRequest", async (_hook, context, controller) => {
            clientGlobalRequests.push(context.name)
            await Promise.resolve()
            if (context.name === "server-query@example.test") {
                controller.success = true
                controller.response = Buffer.concat([Buffer.from("reply:"), context.args])
            }
        })

        try {
            await client.connect()

            expect(
                await Promise.all([
                    client.ping(Buffer.from("first-ping")),
                    client.ping(Buffer.from("second-ping")),
                ]),
            ).toEqual([Buffer.from("first-ping"), Buffer.from("second-ping")])
            await new Promise<void>((resolve, reject) => {
                expect(
                    client.ping(Buffer.from("callback-ping"), (error, reply) => {
                        if (error) reject(error)
                        else {
                            expect(reply).toEqual(Buffer.from("callback-ping"))
                            resolve()
                        }
                    }),
                ).toBe(client)
            })

            expect(
                await Promise.all([
                    client.globalRequest("ordered-one@example.test", Buffer.from("first")),
                    client.globalRequest("ordered-two@example.test", Buffer.from("second")),
                ]),
            ).toEqual([Buffer.from("FIRST"), Buffer.from("SECOND")])
            expect(serverGlobalRequests).toEqual([
                "ordered-one@example.test",
                "ordered-two@example.test",
            ])
            await expect(client.globalRequest("denied@example.test")).rejects.toThrow(
                "SSH global request denied@example.test failed",
            )
            await expect(client.globalRequest("invalid request name")).rejects.toThrow(
                "SSH global request name must be non-empty printable ASCII",
            )
            await new Promise<void>((resolve, reject) => {
                expect(
                    client.globalRequest(
                        "ordered-one@example.test",
                        Buffer.from("callback"),
                        (error, response) => {
                            if (error) reject(error)
                            else {
                                expect(response).toEqual(Buffer.from("CALLBACK"))
                                resolve()
                            }
                        },
                    ),
                ).toBe(client)
            })

            const serverRequestReply = new Promise<RequestSuccess>((resolve) => {
                const listener = (packet: unknown) => {
                    if (!(packet instanceof RequestSuccess)) return
                    serverPeer!.off("packet", listener)
                    resolve(packet)
                }
                serverPeer!.on("packet", listener)
            })
            serverPeer!.sendPacket(
                new GlobalRequest({
                    request_name: "server-query@example.test",
                    want_reply: true,
                    args: Buffer.from("opaque"),
                }),
            )
            expect((await serverRequestReply).data.args).toEqual(Buffer.from("reply:opaque"))
            expect(clientGlobalRequests).toEqual(["server-query@example.test"])

            client.sendPacket(
                new GlobalRequest({
                    request_name: "one-way@example.test",
                    want_reply: false,
                    args: Buffer.from("notice"),
                }),
            )
            await oneWayGlobalRequest
            expect(serverGlobalRequests).toContain("one-way@example.test")

            expect(client.hasAuthenticated).toBe(true)
            expect(client.isConnected).toBe(true)
            expect(client.setNoDelay()).toBe(client)
            expect(connectEvents).toBe(1)
            expect(serverErrors).toEqual([])
            expect(clientErrors).toEqual([])
            expect(greetings).toEqual(["Authorized integration only\r\nMaintenance at 02:00\r\n"])
            expect(serverPeer?.clientProtocolVersion).toEqual(
                new ProtocolVersionExchange("2.0", "modernssh_integration", "fixed-comment"),
            )
            expect((client.kexAlgorithm?.constructor as { alg_name?: string }).alg_name).toBe(
                "curve25519-sha256",
            )
            expect(client.clientEncryptionAlgorithm?.alg_name).toBe("aes128-ctr")
            expect(client.clientMacAlgorithm?.alg_name).toBe("hmac-sha2-256-etm@openssh.com")
            expect(serverPeer?.serverEncryptionAlgorithm?.alg_name).toBe("aes128-ctr")
            expect(serverPeer?.serverMacAlgorithm?.alg_name).toBe("hmac-sha2-256-etm@openssh.com")
            const expectedNegotiated = {
                kex: "curve25519-sha256",
                srvHostKey: "ssh-ed25519",
                cs: {
                    cipher: "aes128-ctr",
                    mac: "hmac-sha2-256-etm@openssh.com",
                    compress: "none",
                    lang: "",
                },
                sc: {
                    cipher: "aes128-ctr",
                    mac: "hmac-sha2-256-etm@openssh.com",
                    compress: "none",
                    lang: "",
                },
            }
            expect(clientHandshakes).toEqual([expectedNegotiated])
            expect(serverHandshakes).toEqual([expectedNegotiated])
            await new Promise<void>((resolve, reject) => {
                expect(
                    server.getConnections((error, count) => {
                        if (error) reject(error)
                        else {
                            expect(count).toBe(1)
                            resolve()
                        }
                    }),
                ).toBe(server)
            })

            const initialClientSessionId = Buffer.from(client.sessionID!)
            const initialServerSessionId = Buffer.from(serverPeer!.sessionID!)
            const initialClientExchangeHash = Buffer.from(client.H!)
            const initialServerExchangeHash = Buffer.from(serverPeer!.H!)

            const clientRekey = client.rekey()
            const pingDuringRekey = client.ping(Buffer.from("queued-during-rekey"))
            const sessionDuringRekey = client.openSession()
            await clientRekey
            expect(await pingDuringRekey).toEqual(Buffer.from("queued-during-rekey"))
            const existingSession = await sessionDuringRekey
            expect(clientRekeys).toBe(1)
            expect(serverRekeys).toBe(1)
            expect(clientExchangeEvents).toEqual(["handshake", "handshake", "rekey"])
            expect(serverExchangeEvents).toEqual(["handshake", "handshake", "rekey"])
            expect(client.sessionID).toEqual(initialClientSessionId)
            expect(serverPeer!.sessionID).toEqual(initialServerSessionId)
            expect(client.H).not.toEqual(initialClientExchangeHash)
            expect(serverPeer!.H).not.toEqual(initialServerExchangeHash)
            expect(client.H).toEqual(serverPeer!.H)

            const clientAcceptedServerRekey = new Promise<void>((resolve) =>
                client.once("rekey", resolve),
            )
            const serverRekey = new Promise<void>((resolve, reject) => {
                expect(serverPeer!.rekey((error) => (error ? reject(error) : resolve()))).toBe(
                    serverPeer!,
                )
            })
            await serverRekey
            await clientAcceptedServerRekey
            expect(clientRekeys).toBe(2)
            expect(serverRekeys).toBe(2)
            expect(clientHandshakes).toEqual([
                expectedNegotiated,
                expectedNegotiated,
                expectedNegotiated,
            ])
            expect(serverHandshakes).toEqual([
                expectedNegotiated,
                expectedNegotiated,
                expectedNegotiated,
            ])
            expect(client.sessionID).toEqual(initialClientSessionId)
            expect(serverPeer!.sessionID).toEqual(initialServerSessionId)
            expect(existingSession.destroyed).toBe(false)

            const configured = await client.exec("configured-command", {
                allowHalfOpen: false,
                env: { LANG: "C.UTF-8", ROLE: "integration" },
                pty: { term: "xterm-256color", cols: 101, rows: 37 },
            })
            expect(configured.allowHalfOpen).toBe(false)
            expect(configuredSession?.env).toEqual(
                new Map([
                    ["LANG", "C.UTF-8"],
                    ["ROLE", "integration"],
                ]),
            )
            expect(configuredSession?.pty).toMatchObject({
                term: "xterm-256color",
                columns: 101,
                rows: 37,
            })
            await configured.break(750)
            expect(breakDurations).toEqual([750])
            await expect(configured.sendBreak(4_000)).rejects.toThrow("request failed")
            expect(breakDurations).toEqual([750, 4_000])
            const xonXoff = new Promise<boolean>((resolve) => configured.once("xonXoff", resolve))
            expect(configuredShell!.setXonXoff(false)).toBe(configuredShell!)
            expect(await xonXoff).toBe(false)
            const configuredClosed = new Promise<void>((resolve) =>
                configured.once("close", resolve),
            )
            configured.close()
            await configuredClosed

            const forwardedPort = await client.forwardIn("127.0.0.1", 0)
            expect(forwardedPort).toBeGreaterThan(0)
            expect(forwardedPort).toBeLessThanOrEqual(65_535)
            await expect(
                serverPeer!.forwardOut("127.0.0.1", -1, "192.0.2.50", 51_234),
            ).rejects.toThrow("between 0 and 65535")
            const incomingTCP = new Promise<{
                details: {
                    destinationHost: string
                    destinationPort: number
                    sourceHost: string
                    sourcePort: number
                }
                channel: ClientForwardedTCPIPChannel
            }>((resolve) => {
                client.once("tcp connection", (details, accept) => {
                    resolve({ details, channel: accept()! })
                })
            })
            const serverTCP = new Promise<ForwardedTCPIPChannel>((resolve, reject) => {
                expect(
                    serverPeer!.forwardOut(
                        "127.0.0.1",
                        forwardedPort,
                        "192.0.2.50",
                        51_234,
                        (error, channel) => (error ? reject(error) : resolve(channel!)),
                    ),
                ).toBe(serverPeer!)
            })
            const [{ details: tcpDetails, channel: clientTCP }, serverTCPChannel] =
                await Promise.all([incomingTCP, serverTCP])
            expect(tcpDetails).toEqual({
                destinationHost: "127.0.0.1",
                destinationPort: forwardedPort,
                sourceHost: "192.0.2.50",
                sourcePort: 51_234,
            })
            const serverTCPData = new Promise<Buffer>((resolve) =>
                serverTCPChannel.stream.once("data", resolve),
            )
            clientTCP.write(Buffer.from("client-to-server"))
            expect(await serverTCPData).toEqual(Buffer.from("client-to-server"))
            const clientTCPData = new Promise<Buffer>((resolve) => clientTCP.once("data", resolve))
            serverTCPChannel.stream.write(Buffer.from("server-to-client"))
            expect(await clientTCPData).toEqual(Buffer.from("server-to-client"))
            clientTCP.close()
            await client.unforwardIn("127.0.0.1", forwardedPort)
            await expect(
                serverPeer!.forwardOut("127.0.0.1", forwardedPort, "192.0.2.50", 51_234),
            ).rejects.toThrow("did not request forwarding")
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
            await expect(serverPeer!.openssh_forwardOutStreamLocal("bad\0path")).rejects.toThrow(
                "contain no NUL",
            )
            const incomingUnix = new Promise<ClientForwardedStreamLocalChannel>((resolve) => {
                client.once("unix connection", (_details, accept) => resolve(accept()!))
            })
            const [clientUnix, serverUnix] = await Promise.all([
                incomingUnix,
                serverPeer!.openssh_forwardOutStreamLocal(streamLocalPath),
            ])
            const serverUnixData = new Promise<Buffer>((resolve) =>
                serverUnix.stream.once("data", resolve),
            )
            clientUnix.write(Buffer.from("unix-client"))
            expect(await serverUnixData).toEqual(Buffer.from("unix-client"))
            const clientUnixData = new Promise<Buffer>((resolve) =>
                clientUnix.once("data", resolve),
            )
            serverUnix.stream.write(Buffer.from("unix-server"))
            expect(await clientUnixData).toEqual(Buffer.from("unix-server"))
            clientUnix.close()
            await client.openssh_unforwardInStreamLocal(streamLocalPath)
            await expect(
                serverPeer!.openssh_forwardOutStreamLocal(streamLocalPath),
            ).rejects.toThrow("did not request stream-local forwarding")
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
                expect(server.close((error) => (error ? reject(error) : resolve()))).toBe(server)
            })
            await rm(streamLocalPath, { force: true })
        }
    }, 15_000)

    test("maintains immediate and delayed compression streams across packets and rekey", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const contents = Buffer.from("compressible-payload\n".repeat(6_000))

        for (const compression of ["zlib", "zlib@openssh.com"] as const) {
            const server = new Server({
                hostKeys: [hostKey],
                sendAllHostKeys: false,
                algorithms: { compress: [compression] },
            })
            const serverErrors: Error[] = []
            const serverHandshakes: string[] = []
            server.hooker.hook("noneAuthentication", (_hook, _context, decision) => {
                decision.allowLogin = true
            })
            server.hooker.hook("channelOpenRequest", (_hook, channel, decision) => {
                decision.allowOpen = channel instanceof SessionChannel
            })
            server.on("connection", (connection) => {
                connection.on("error", (error) => serverErrors.push(error))
                connection.on("handshake", (negotiated) => {
                    serverHandshakes.push(negotiated.cs.compress)
                    expect(negotiated.sc.compress).toBe(compression)
                })
                connection.on("channel", (channel) => {
                    if (!(channel instanceof SessionChannel)) return
                    channel.hooker.hook("execRequest", (_hook, _context, decision) => {
                        decision.success = true
                    })
                    channel.events.on("exec", (_command, shell) => {
                        const input: Buffer[] = []
                        shell.on("data", (data: Buffer) => input.push(data))
                        shell.on("end", () => {
                            shell.stdout.write(Buffer.concat(input), () => shell.exit(0).end())
                        })
                    })
                })
            })
            server.listen({ host: "127.0.0.1", port: 0 })
            await new Promise<void>((resolve) => server.server!.once("listening", resolve))

            const client = new Client({
                hostname: "127.0.0.1",
                port: (server.server!.address() as AddressInfo).port,
                username: "compression-test",
                strictVendor: false,
                algorithms: { compress: [compression] },
            })
            const clientErrors: Error[] = []
            const clientHandshakes: string[] = []
            client.on("error", (error) => clientErrors.push(error))
            client.on("handshake", (negotiated) => {
                clientHandshakes.push(negotiated.cs.compress)
                expect(negotiated.sc.compress).toBe(compression)
            })

            try {
                await client.connect()
                expect(client.clientCompressionAlgorithm?.alg_name).toBe(compression)
                expect(client.serverCompressionAlgorithm?.alg_name).toBe(compression)
                await client.rekey()

                const session = await client.exec("compression-roundtrip")
                const output: Buffer[] = []
                session.on("data", (data: Buffer) => output.push(data))
                session.end(contents)
                await new Promise<void>((resolve) => session.once("close", resolve))

                expect(Buffer.concat(output)).toEqual(contents)
                expect(clientHandshakes).toEqual([compression, compression])
                expect(serverHandshakes).toEqual([compression, compression])
                expect(clientErrors).toEqual([])
                expect(serverErrors).toEqual([])
            } finally {
                const closed = new Promise<void>((resolve) => client.once("close", resolve))
                client.end()
                await closed
                await new Promise<void>((resolve, reject) => {
                    server.server!.close((error) => (error ? reject(error) : resolve()))
                })
            }
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

    test("accepts an injected TCP socket through the normal admission path", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({ hostKeys: [hostKey], sendAllHostKeys: false })
        let preconnects = 0
        let peer: ServerClient | undefined
        server.hooker.hook("preconnect", (_hook, controller) => {
            preconnects++
            controller.allowConnection = true
        })
        server.hooker.hook("noneAuthentication", (_hook, _context, controller) => {
            controller.allowLogin = true
        })
        server.on("connection", (connection) => {
            peer = connection
            connection.on("error", () => undefined)
        })

        const socketAcceptor = createServer((socket) => {
            expect(server.injectSocket(socket)).toBe(server)
        })
        socketAcceptor.listen({ host: "127.0.0.1", port: 0 })
        await new Promise<void>((resolve) => socketAcceptor.once("listening", resolve))
        const client = new Client({
            hostname: "127.0.0.1",
            port: (socketAcceptor.address() as AddressInfo).port,
            username: "injected-socket",
        })
        client.on("error", () => undefined)

        await client.connect()
        expect(preconnects).toBe(1)
        let globalRequests = 0
        peer!.on("packet", (packet) => {
            if (packet instanceof GlobalRequest) globalRequests++
        })
        await expect(client.opensshNoMoreSessions()).rejects.toThrow(
            "strictVendor enabled and server is not OpenSSH or compatible version",
        )
        await Promise.resolve()
        expect(globalRequests).toBe(0)
        expect(peer?.setNoDelay(false)).toBe(peer)
        expect(server.clients.size).toBe(1)

        const clientClosed = new Promise<void>((resolve) => client.once("close", resolve))
        const peerClosed = new Promise<void>((resolve) => peer!.once("close", resolve))
        client.end()
        await Promise.all([clientClosed, peerClosed])
        expect(server.clients.size).toBe(0)
        await new Promise<void>((resolve, reject) => {
            socketAcceptor.close((error) => (error ? reject(error) : resolve()))
        })
    })

    test("bounds the complete SSH readiness phase for a silent peer", async () => {
        const silentPeer = createServer(() => undefined)
        silentPeer.listen({ host: "127.0.0.1", port: 0 })
        await new Promise<void>((resolve) => silentPeer.once("listening", resolve))
        const client = new Client({
            hostname: "127.0.0.1",
            port: (silentPeer.address() as AddressInfo).port,
            readyTimeout: 40,
        })
        const errors: Error[] = []
        client.on("error", (error) => errors.push(error))

        await expect(client.connect()).rejects.toThrow("Timed out while waiting for handshake")
        if (!client.canConnect) {
            await new Promise<void>((resolve) => client.once("close", resolve))
        }
        expect(client.canConnect).toBe(true)
        expect(errors.map((error) => error.message)).toEqual([
            "Timed out while waiting for handshake",
        ])
        await new Promise<void>((resolve, reject) => {
            silentPeer.close((error) => (error ? reject(error) : resolve()))
        })
        expect(() => new Client({ readyTimeout: -1 })).toThrow(
            "SSH ready timeout must be a non-negative number",
        )
    })

    test("binds and resolves a new TCP connection with the configured address family", async () => {
        const script = String.raw`
            import net from "node:net"
            import Client from "./dist/Client.js"

            const reserve = net.createServer()
            await new Promise((resolve) => reserve.listen(0, "127.0.0.1", resolve))
            const localPort = reserve.address().port
            await new Promise((resolve, reject) =>
                reserve.close((error) => error ? reject(error) : resolve()),
            )

            let accept
            const accepted = new Promise((resolve) => { accept = resolve })
            const server = net.createServer((socket) =>
                accept({ address: socket.remoteAddress, port: socket.remotePort }),
            )
            await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve))
            const client = new Client({
                hostname: "localhost",
                port: server.address().port,
                localAddress: "127.0.0.1",
                localPort,
                forceIPv4: true,
                readyTimeout: 1_000,
            })
            client.on("error", () => undefined)
            void client.connect()
            const remote = await accepted
            const closed = new Promise((resolve) => client.once("close", resolve))
            client.destroy()
            await closed
            await new Promise((resolve, reject) =>
                server.close((error) => error ? reject(error) : resolve()),
            )
            process.stdout.write(JSON.stringify({ localPort, remote }))
        `
        const { stdout, stderr } = await execFileAsync("node", [
            "--input-type=module",
            "--eval",
            script,
        ])
        expect(stderr).toBe("")
        const result = JSON.parse(stdout) as {
            localPort: number
            remote: { address: string; port: number }
        }
        expect(result.remote).toEqual({ address: "127.0.0.1", port: result.localPort })
        expect(() => new Client({ localPort: 65_536 })).toThrow(
            "SSH local port must be an integer between 0 and 65535",
        )
    })

    test("rejects a disallowed raw host key and closes the transport", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({ hostKeys: [hostKey], sendAllHostKeys: false })
        server.hooker.hook("noneAuthentication", (_hook, _context, controller) => {
            controller.allowLogin = true
        })
        server.on("connection", (peer) => peer.on("error", () => undefined))
        server.listen({ host: "127.0.0.1", port: 0 })
        await new Promise<void>((resolve) => server.server!.once("listening", resolve))

        let presentedKey: Buffer | string | undefined
        const client = new Client({
            hostname: "127.0.0.1",
            port: (server.address() as AddressInfo).port,
            hostVerifier: (key) => {
                presentedKey = key
                return false
            },
        })
        client.on("error", () => undefined)
        await expect(client.connect()).rejects.toThrow("Host key not allowed by verifier")
        if (!client.canConnect) await new Promise<void>((resolve) => client.once("close", resolve))
        expect(presentedKey).toEqual(hostKey.data.publicKey.serialize())
        expect(client.canConnect).toBe(true)

        await new Promise<void>((resolve, reject) => {
            server.close((error) => (error ? reject(error) : resolve()))
        })
        expect(() => new Client({ hostHash: "not-a-real-hash" })).toThrow(
            "Unsupported SSH host hash algorithm: not-a-real-hash",
        )
    })
})
