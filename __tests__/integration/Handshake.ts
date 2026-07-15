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
import Shell from "../../src/channels/Session/Shell.js"
import RequestFailure from "../../src/packets/RequestFailure.js"
import GlobalRequest from "../../src/packets/GlobalRequest.js"
import PrivateKey from "../../src/utils/PrivateKey.js"
import Packet from "../../src/packet.js"
import { serializeBuffer, serializeUint32 } from "../../src/utils/Buffer.js"
import { SFTPPacketType } from "../../src/sftp/constants.js"
import { SSHAuthenticationMethods } from "../../src/constants.js"
import KexInit from "../../src/packets/KexInit.js"

class UnsupportedPacket {
    static type = 200

    constructor(private readonly marker: number) {}

    serialize(): Buffer {
        return Buffer.from([UnsupportedPacket.type, this.marker])
    }
}

function asPacket(marker: number): Packet {
    return new UnsupportedPacket(marker) as unknown as Packet
}

function within<T>(promise: Promise<T>, label: string): Promise<T> {
    return new Promise<T>((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error(`Timed out waiting for ${label}`)), 1_000)
        timer.unref()
        promise.then(
            (value) => {
                clearTimeout(timer)
                resolve(value)
            },
            (error: unknown) => {
                clearTimeout(timer)
                reject(error as Error)
            },
        )
    })
}

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
        const receivedClientExtensions: string[][] = []
        let initialClientKexInit: KexInit | undefined
        let initialServerKexInit: KexInit | undefined
        let configuredSession: SessionChannel | undefined
        let configuredShell: Shell | undefined
        const breakDurations: number[] = []
        const runtimeControls: string[] = []
        let resolveRuntimeControls: (() => void) | undefined
        const runtimeControlsComplete = new Promise<void>((resolve) => {
            resolveRuntimeControls = resolve
        })
        const serverChannelRequests: string[] = []
        let resolveServerChannelNotification: (() => void) | undefined
        const serverChannelNotification = new Promise<void>((resolve) => {
            resolveServerChannelNotification = resolve
        })
        server.hooker.hook(
            "channelRequest",
            async (_hook, _channel, controller, _client, request) => {
                if (!request.data.request_type.startsWith("custom-")) return
                serverChannelRequests.push(request.data.request_type)
                controller.handled = true
                if (request.data.request_type === "custom-one@example.test") {
                    await new Promise<void>((resolve) => setTimeout(resolve, 10))
                    controller.success = true
                } else if (request.data.request_type === "custom-two@example.test") {
                    controller.success = true
                } else if (request.data.request_type === "custom-notify@example.test") {
                    resolveServerChannelNotification?.()
                } else if (request.data.request_type === "custom-never@example.test") {
                    await new Promise<never>(() => undefined)
                }
            },
        )
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
            peer.once("clientKexInit", (packet) => {
                initialClientKexInit = packet
            })
            peer.on("error", (error) => serverErrors.push(error))
            peer.on("rekey", () => serverRekeys++)
            peer.on("handshake", (negotiated) => {
                serverHandshakes.push(negotiated)
                serverExchangeEvents.push("handshake")
            })
            peer.on("rekey", () => serverExchangeEvents.push("rekey"))
            peer.on("clientExtensions", (extensions) => {
                receivedClientExtensions.push(extensions.map(({ name }) => name))
            })
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
                channel.hooker.hook("subsystemRequest", (_hook, context, controller) => {
                    if (context.subsystem !== "sftp") return
                    controller.success = true
                    controller.sftp = {
                        extensions: [
                            { name: "query@example.test", data: Buffer.from("1", "ascii") },
                        ],
                    }
                })
                channel.hooker.hook("breakRequest", async (_hook, context, controller) => {
                    await Promise.resolve()
                    breakDurations.push(context.duration)
                    controller.success = context.duration === 750
                })
                channel.hooker.hook("windowChange", async (_hook, dimensions) => {
                    await new Promise<void>((resolve) => setTimeout(resolve, 10))
                    runtimeControls.push(`hook:window:${dimensions.columns}x${dimensions.rows}`)
                })
                channel.hooker.hook("signal", async (_hook, context) => {
                    await Promise.resolve()
                    runtimeControls.push(`hook:signal:${context.signal}`)
                })
                channel.events.on("windowChange", (dimensions) => {
                    runtimeControls.push(`event:window:${dimensions.columns}x${dimensions.rows}`)
                })
                channel.events.on("signal", (signal) => {
                    runtimeControls.push(`event:signal:${signal}`)
                    resolveRuntimeControls?.()
                })
                channel.events.on("sftp", (sftp) => {
                    sftp.hooker.hook("EXTENDED", async (_hook, request) => {
                        await Promise.resolve()
                        if (request.request !== "query@example.test") return
                        await sftp.extendedReply(
                            request.requestId,
                            Buffer.from(request.data.toString("ascii").toUpperCase()),
                        )
                    })
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
        const receivedServerExtensions: string[][] = []
        client.on("error", (error) => clientErrors.push(error))
        client.on("greeting", (greeting) => greetings.push(greeting))
        client.on("connect", () => connectEvents++)
        client.on("rekey", () => clientRekeys++)
        client.on("handshake", (negotiated) => {
            clientHandshakes.push(negotiated)
            clientExchangeEvents.push("handshake")
        })
        client.on("rekey", () => clientExchangeEvents.push("rekey"))
        client.once("serverKexInit", (packet) => {
            initialServerKexInit = packet
        })
        client.on("serverExtensions", (extensions) => {
            receivedServerExtensions.push(extensions.map(({ name }) => name))
        })
        const clientGlobalRequests: string[] = []
        client.hooker.hook("globalRequest", async (_hook, context, controller) => {
            clientGlobalRequests.push(context.name)
            if (context.name === "server-query-one@example.test") {
                await new Promise<void>((resolve) => setTimeout(resolve, 10))
                controller.success = true
                controller.response = Buffer.concat([Buffer.from("reply:"), context.args])
            } else if (context.name === "server-query-two@example.test") {
                controller.success = true
                controller.response = Buffer.concat([Buffer.from("reply:"), context.args])
            } else if (context.name === "never-reply@example.test") {
                await new Promise<never>(() => undefined)
            }
        })

        try {
            await client.connect()

            expect(initialClientKexInit?.data.kex_algorithms).toContain("ext-info-c")
            expect(initialServerKexInit?.data.kex_algorithms).toContain("ext-info-s")
            expect(receivedClientExtensions).toEqual([["ext-info-in-auth@openssh.com"]])
            expect(serverPeer!.clientExtensions).toEqual([
                { name: "ext-info-in-auth@openssh.com", value: Buffer.alloc(0) },
            ])
            expect(serverPeer!.clientSupportsAuthenticationExtensionInfo).toBe(true)
            expect(receivedServerExtensions).toEqual([
                ["server-sig-algs", "ping@openssh.com", "agent-forward"],
            ])
            expect(client.rfc9987AgentForwarding).toBe(true)
            const serverExtensionSnapshot = client.serverExtensions
            serverExtensionSnapshot[1]!.value.fill(0)
            expect(client.serverExtensions[1]).toEqual({
                name: "ping@openssh.com",
                value: Buffer.from("0", "ascii"),
            })

            expect(
                await Promise.all([
                    client.ping(Buffer.from("first-ping")),
                    client.ping(Buffer.from("second-ping")),
                ]),
            ).toEqual([Buffer.from("first-ping"), Buffer.from("second-ping")])
            expect(await client.ping(Buffer.from("third-ping"))).toEqual(Buffer.from("third-ping"))

            const clientUnimplemented = new Promise<number[]>((resolve) => {
                const replies: number[] = []
                const listener = (sequenceNumber: number) => {
                    replies.push(sequenceNumber)
                    if (replies.length !== 2) return
                    serverPeer!.off("unimplemented", listener)
                    resolve(replies)
                }
                serverPeer!.on("unimplemented", listener)
            })
            const serverUnknownSequences = [
                serverPeer!.sendPacket(asPacket(0xa1)),
                serverPeer!.sendPacket(asPacket(0xa2)),
            ]
            expect(await within(clientUnimplemented, "client UNIMPLEMENTED replies")).toEqual(
                serverUnknownSequences,
            )

            const serverUnimplemented = new Promise<number[]>((resolve) => {
                const replies: number[] = []
                const listener = (sequenceNumber: number) => {
                    replies.push(sequenceNumber)
                    if (replies.length !== 2) return
                    client.off("unimplemented", listener)
                    resolve(replies)
                }
                client.on("unimplemented", listener)
            })
            const clientUnknownSequences = [
                client.sendPacket(asPacket(0xb1)),
                client.sendPacket(asPacket(0xb2)),
            ]
            expect(await within(serverUnimplemented, "server UNIMPLEMENTED replies")).toEqual(
                clientUnknownSequences,
            )

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
            expect(
                await client.globalRequest("ordered-one@example.test", Buffer.from("third")),
            ).toEqual(Buffer.from("THIRD"))

            expect(
                await Promise.all([
                    serverPeer!.globalRequest(
                        "server-query-one@example.test",
                        Buffer.from("first"),
                    ),
                    serverPeer!.globalRequest(
                        "server-query-two@example.test",
                        Buffer.from("second"),
                    ),
                ]),
            ).toEqual([Buffer.from("reply:first"), Buffer.from("reply:second")])
            expect(clientGlobalRequests).toEqual([
                "server-query-one@example.test",
                "server-query-two@example.test",
            ])
            await expect(serverPeer!.globalRequest("server-denied@example.test")).rejects.toThrow(
                "SSH global request server-denied@example.test failed",
            )
            expect(
                await serverPeer!.globalRequest(
                    "server-query-two@example.test",
                    Buffer.from("third"),
                ),
            ).toEqual(Buffer.from("reply:third"))

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
            expect(client.keyExchangeAlgorithm).toBe("curve25519-sha256")
            expect(client.negotiatedAlgorithms?.cs.cipher).toBe("aes128-ctr")
            expect(client.negotiatedAlgorithms?.cs.mac).toBe("hmac-sha2-256-etm@openssh.com")
            expect(serverPeer?.negotiatedAlgorithms?.sc.cipher).toBe("aes128-ctr")
            expect(serverPeer?.negotiatedAlgorithms?.sc.mac).toBe("hmac-sha2-256-etm@openssh.com")
            expect(Object.isFrozen(client.negotiatedAlgorithms)).toBe(true)
            expect(Object.isFrozen(client.negotiatedAlgorithms?.cs)).toBe(true)
            expect(Object.isFrozen(client.negotiatedAlgorithms?.sc)).toBe(true)
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
            expect(await server.getConnections()).toBe(1)

            const initialClientSessionId = Buffer.from(client.sessionID!)
            const initialServerSessionId = Buffer.from(serverPeer!.sessionID!)
            const initialClientExchangeHash = Buffer.from(client.exchangeHash!)
            const initialServerExchangeHash = Buffer.from(serverPeer!.exchangeHash!)
            const exposedClientSessionId = client.sessionID!
            const exposedServerSessionId = serverPeer!.sessionID!
            const exposedClientExchangeHash = client.exchangeHash!
            const exposedServerExchangeHash = serverPeer!.exchangeHash!
            exposedClientSessionId.fill(0)
            exposedServerSessionId.fill(0)
            exposedClientExchangeHash.fill(0)
            exposedServerExchangeHash.fill(0)
            expect(client.sessionID).toEqual(initialClientSessionId)
            expect(serverPeer!.sessionID).toEqual(initialServerSessionId)
            expect(client.exchangeHash).toEqual(initialClientExchangeHash)
            expect(serverPeer!.exchangeHash).toEqual(initialServerExchangeHash)

            let clientObservedServerKexInit: KexInit | undefined
            let serverObservedClientKexInit: KexInit | undefined
            client.on("serverKexInit", (packet) => {
                clientObservedServerKexInit = packet
                packet.data.cookie.fill(0x11)
            })
            serverPeer!.on("clientKexInit", (packet) => {
                serverObservedClientKexInit = packet
                packet.data.cookie.fill(0x22)
            })
            const clientSendPacket = client.sendPacket.bind(client)
            client.sendPacket = (packet: Packet) => {
                const sequence = clientSendPacket(packet)
                if (packet instanceof KexInit) packet.data.cookie.fill(0xa5)
                return sequence
            }
            const clientRekey = client.rekey()
            const pingDuringRekey = client.ping(Buffer.from("queued-during-rekey"))
            const sessionDuringRekey = client.openSession()
            await clientRekey
            expect(await pingDuringRekey).toEqual(Buffer.from("queued-during-rekey"))
            const existingSession = await sessionDuringRekey
            expect(
                await Promise.all([
                    existingSession.request("custom-one@example.test", Buffer.from("first")),
                    existingSession.request("custom-two@example.test", Buffer.from("second")),
                ]),
            ).toEqual([undefined, undefined])
            await expect(existingSession.request("custom-denied@example.test")).rejects.toThrow(
                "request failed (custom-denied@example.test)",
            )
            await existingSession.request(
                "custom-notify@example.test",
                Buffer.from("notice"),
                false,
            )
            await serverChannelNotification
            expect(serverChannelRequests).toEqual([
                "custom-one@example.test",
                "custom-two@example.test",
                "custom-denied@example.test",
                "custom-notify@example.test",
            ])

            const clientChannelRequests: string[] = []
            let resolveClientChannelNotification: (() => void) | undefined
            const clientChannelNotification = new Promise<void>((resolve) => {
                resolveClientChannelNotification = resolve
            })
            existingSession.hooker.hook("request", async (_hook, context, controller) => {
                clientChannelRequests.push(context.type)
                if (context.type === "client-one@example.test") {
                    await new Promise<void>((resolve) => setTimeout(resolve, 10))
                    controller.success = true
                } else if (context.type === "client-two@example.test") {
                    controller.success = true
                } else if (context.type === "client-notify@example.test") {
                    resolveClientChannelNotification?.()
                } else if (context.type === "client-never@example.test") {
                    await new Promise<never>(() => undefined)
                }
            })
            const serverChannel = serverPeer!.channels.get(existingSession.remoteId!)!
            expect(
                await Promise.all([
                    serverChannel.request("client-one@example.test", Buffer.from("first")),
                    serverChannel.request("client-two@example.test", Buffer.from("second")),
                ]),
            ).toEqual([undefined, undefined])
            await expect(serverChannel.request("client-denied@example.test")).rejects.toThrow(
                "request failed (client-denied@example.test)",
            )
            await serverChannel.request("client-notify@example.test", Buffer.from("notice"), false)
            await clientChannelNotification
            expect(clientChannelRequests).toEqual([
                "client-one@example.test",
                "client-two@example.test",
                "client-denied@example.test",
                "client-notify@example.test",
            ])
            expect(clientRekeys).toBe(1)
            expect(serverRekeys).toBe(1)
            expect(clientExchangeEvents).toEqual(["handshake", "handshake", "rekey"])
            expect(serverExchangeEvents).toEqual(["handshake", "handshake", "rekey"])
            expect(client.sessionID).toEqual(initialClientSessionId)
            expect(serverPeer!.sessionID).toEqual(initialServerSessionId)
            expect(client.exchangeHash).not.toEqual(initialClientExchangeHash)
            expect(serverPeer!.exchangeHash).not.toEqual(initialServerExchangeHash)
            expect(client.exchangeHash).toEqual(serverPeer!.exchangeHash)
            expect(clientObservedServerKexInit).toBeDefined()
            expect(serverObservedClientKexInit).toBeDefined()

            const serverSendPacket = serverPeer!.sendPacket.bind(serverPeer!)
            serverPeer!.sendPacket = (packet: Packet) => {
                const sequence = serverSendPacket(packet)
                if (packet instanceof KexInit) packet.data.cookie.fill(0x5a)
                return sequence
            }
            const clientAcceptedServerRekey = new Promise<void>((resolve) =>
                client.once("rekey", resolve),
            )
            const serverRekey = serverPeer!.rekey()
            const serverRequestDuringRekey = serverPeer!.globalRequest(
                "server-query-two@example.test",
                Buffer.from("during-rekey"),
            )
            await serverRekey
            await clientAcceptedServerRekey
            expect(await serverRequestDuringRekey).toEqual(Buffer.from("reply:during-rekey"))
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
            await Promise.all([
                configured.setWindow({ columns: 132, rows: 43 }),
                configured.signal("SIGTERM"),
            ])
            await runtimeControlsComplete
            expect(runtimeControls).toEqual([
                "hook:window:132x43",
                "event:window:132x43",
                "hook:signal:TERM",
                "event:signal:TERM",
            ])
            await expect(
                configured.request("signal", serializeBuffer(Buffer.from("TERM", "ascii"))),
            ).rejects.toThrow("request failed (signal)")
            await expect(
                configured.request(
                    "window-change",
                    Buffer.concat([
                        serializeUint32(80),
                        serializeUint32(24),
                        serializeUint32(0),
                        serializeUint32(0),
                    ]),
                ),
            ).rejects.toThrow("request failed (window-change)")
            expect(runtimeControls).toHaveLength(4)
            const xonXoff = new Promise<boolean>((resolve) => configured.once("xonXoff", resolve))
            expect(configuredShell!.setXonXoff(false)).toBe(configuredShell!)
            expect(await xonXoff).toBe(false)
            const configuredClosed = new Promise<void>((resolve) =>
                configured.once("close", resolve),
            )
            configured.close()
            await configuredClosed

            const applicationSFTP = await client.sftp()
            const applicationReply = await applicationSFTP.extended(
                "query@example.test",
                Buffer.from("ordered extension"),
            )
            expect(applicationReply).toMatchObject({
                type: SFTPPacketType.ExtendedReply,
                data: Buffer.from("ORDERED EXTENSION"),
            })
            applicationSFTP.end()

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
            const serverTCP = serverPeer!.forwardOut(
                "127.0.0.1",
                forwardedPort,
                "192.0.2.50",
                51_234,
            )
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
            const pendingServerChannelRequest = serverChannel
                .request("client-never@example.test")
                .then(
                    () => "unexpected success",
                    (error: Error) => error.message,
                )
            const pendingClientChannelRequest = existingSession
                .request("custom-never@example.test")
                .then(
                    () => "unexpected success",
                    (error: Error) => error.message,
                )
            existingSession.close()
            await sessionClosed
            expect(await pendingServerChannelRequest).toBe(
                `SSH channel ${serverChannel.localId} closed during request`,
            )
            expect(await pendingClientChannelRequest).toBe(
                `SSH channel ${existingSession.localId} closed during request`,
            )
            expect(serverErrors).toEqual([])
            expect(clientErrors).toEqual([])
        } finally {
            const pendingServerRequest = serverPeer?.isConnected
                ? serverPeer.globalRequest("never-reply@example.test").then(
                      () => "unexpected success",
                      (error: Error) => error.message,
                  )
                : undefined
            const closed = new Promise<void>((resolve) => client.once("close", resolve))
            expect(client.end()).toBe(client)
            expect(client.end()).toBe(client)
            await closed
            if (pendingServerRequest) {
                expect(await pendingServerRequest).toBe("SSH peer disconnected (reason 11)")
            }
            expect(client.isConnected).toBe(false)
            await server.close()
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
                            shell.stdout.write(Buffer.concat(input), () => shell.exit(0).close())
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
                expect(client.negotiatedAlgorithms?.cs.compress).toBe(compression)
                expect(client.negotiatedAlgorithms?.sc.compress).toBe(compression)
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
            replyTimeout: 5,
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
        peer!.on("packet", (metadata) => {
            if (metadata.name === "SSH_MSG_GLOBAL_REQUEST") globalRequests++
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
            void client.connect().catch(() => undefined)
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

        await server.close()
        expect(() => new Client({ hostHash: "not-a-real-hash" })).toThrow(
            "Unsupported SSH host hash algorithm: not-a-real-hash",
        )
    })

    test("reuses a client with fresh transport state after a clean close", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({ hostKeys: [hostKey], sendAllHostKeys: false })
        server.hooker.hook("noneAuthentication", (_hook, _context, controller) => {
            controller.allowLogin = true
        })
        server.listen({ host: "127.0.0.1", port: 0 })
        await new Promise<void>((resolve) => server.server!.once("listening", resolve))

        const client = new Client({
            hostname: "127.0.0.1",
            port: (server.address() as AddressInfo).port,
            username: "reconnect-test",
            authenticationMethodsOrder: [SSHAuthenticationMethods.None],
        })
        client.hooker.hook("hostKey", (_hook, controller) => {
            controller.allowHostKey = true
        })
        let handshakes = 0
        client.on("handshake", () => handshakes++)

        try {
            const firstConnection = client.connect()
            await expect(client.connect()).rejects.toThrow("not in a state to connect")
            await firstConnection
            const firstSessionId = Buffer.from(client.sessionID!)

            const firstClose = new Promise<void>((resolve) => client.once("close", resolve))
            client.end()
            await firstClose
            expect(client.canConnect).toBe(true)

            await client.connect()
            expect(client.sessionID).toBeDefined()
            expect(client.sessionID).not.toEqual(firstSessionId)
            expect(client.hasAuthenticated).toBe(true)
            expect(handshakes).toBe(2)
            expect(server.clients.size).toBe(1)
        } finally {
            client.destroy()
            for (const peer of server.clients) peer.terminate()
            await server.close()
        }
    }, 15_000)
})
