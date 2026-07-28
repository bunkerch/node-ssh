import { once } from "node:events"
import type { AddressInfo } from "node:net"
import { PassThrough } from "node:stream"
import Client from "../../src/Client.js"
import SessionChannel from "../../src/channels/SessionChannel.js"
import { SSHAuthenticationMethods } from "../../src/constants.js"
import type Agent from "../../src/publickey/Agent.js"
import PrivateKeyAgent from "../../src/publickey/PrivateKeyAgent.js"
import Server from "../../src/Server.js"
import PrivateKey from "../../src/utils/PrivateKey.js"
import PublicKey, { type SSHCertificateOption } from "../../src/utils/PublicKey.js"
import { serializeBuffer, serializeUint32, serializeUint64 } from "../../src/utils/Buffer.js"

interface CertificateFixture {
    ca: PrivateKey
    certificate: PublicKey
    identity: PrivateKey
}

async function issueCertificate(
    criticalOptions: readonly SSHCertificateOption[] = [],
    extensions: readonly SSHCertificateOption[] = [],
): Promise<CertificateFixture> {
    const identity = await PrivateKey.generate("ssh-ed25519")
    const ca = await PrivateKey.generate("ssh-ed25519")
    const certificateType = "ssh-ed25519-cert"
    const encodeOptions = (options: readonly SSHCertificateOption[]) =>
        Buffer.concat(
            [...options]
                .sort((left, right) => Buffer.from(left.name).compare(Buffer.from(right.name)))
                .flatMap(({ name, data }) => [
                    serializeBuffer(Buffer.from(name)),
                    serializeBuffer(data),
                ]),
        )
    const signed = Buffer.concat([
        serializeBuffer(Buffer.from(certificateType)),
        serializeBuffer(Buffer.alloc(32, 0x5a)),
        identity.data.publicKey.data.algorithm.serialize(),
        serializeUint64(7n),
        serializeUint32(1),
        serializeBuffer(Buffer.from("authorization-test")),
        serializeBuffer(serializeBuffer(Buffer.from("alice"))),
        serializeUint64(0n),
        serializeUint64(0xffffffffffffffffn),
        serializeBuffer(encodeOptions(criticalOptions)),
        serializeBuffer(encodeOptions(extensions)),
        serializeBuffer(Buffer.alloc(0)),
        serializeBuffer(ca.data.publicKey.serialize()),
    ])
    return {
        ca,
        certificate: PublicKey.parse(
            Buffer.concat([signed, serializeBuffer(ca.sign(signed).serialize())]),
        ),
        identity,
    }
}

function nested(value: string): Buffer {
    return serializeBuffer(Buffer.from(value))
}

async function createPeers(
    fixture: CertificateFixture,
    options: {
        agent?: Agent<string>
        authenticationPolicyCalled?: () => void
        configureServer?: (server: Server) => void
        handledCriticalOptions?: readonly string[]
        passwordFactor?: string
    } = {},
): Promise<{ client: Client; server: Server }> {
    const server = new Server({
        hostKeys: [await PrivateKey.generate("ssh-ed25519")],
        sendAllHostKeys: false,
    })
    server.hooker.hook("publicKeyAuthentication", (_hook, context, decision) => {
        options.authenticationPolicyCalled?.()
        decision.handledCertificateCriticalOptions = options.handledCriticalOptions
        const accepted =
            context.signature !== undefined &&
            context.username === "alice" &&
            context.certificate?.data.signatureKey.equals(fixture.ca.data.publicKey) === true &&
            context.certificate.data.principals.includes("alice")
        if (options.passwordFactor === undefined) {
            decision.allowLogin = accepted
        } else {
            decision.partialSuccess = accepted
            decision.authenticationMethods = [SSHAuthenticationMethods.Password]
        }
    })
    if (options.passwordFactor !== undefined) {
        server.hooker.hook("passwordAuthentication", (_hook, context, decision) => {
            decision.allowLogin = context.password === options.passwordFactor
        })
    }
    options.configureServer?.(server)
    server.listen({ host: "127.0.0.1", port: 0 })
    await once(server, "listening")

    const client = new Client({
        hostname: "127.0.0.1",
        port: (server.address() as AddressInfo).port,
        username: "alice",
        ...(options.agent
            ? { agent: options.agent }
            : { privateKey: fixture.identity, certificate: fixture.certificate }),
        password: options.passwordFactor,
        authenticationMethodsOrder:
            options.passwordFactor === undefined
                ? [SSHAuthenticationMethods.PublicKey]
                : [SSHAuthenticationMethods.PublicKey, SSHAuthenticationMethods.Password],
    })
    client.hooker.hook("hostKey", (_hook, decision) => {
        decision.allowHostKey = true
    })
    return { client, server }
}

async function closePeers(server: Server, client: Client): Promise<void> {
    client.destroy()
    for (const connection of server.clients) connection.terminate()
    await server.close()
}

describe("user certificate authorization", () => {
    test.each([
        [
            "an unsupported critical option",
            [{ name: "future-critical@example.test", data: Buffer.alloc(0) }],
            1,
        ],
        [
            "a source-address mismatch",
            [{ name: "source-address", data: nested("192.0.2.0/24") }],
            0,
        ],
    ])(
        "rejects %s unless fully authorized",
        async (_name, criticalOptions, expectedPolicyCalls) => {
            const fixture = await issueCertificate(criticalOptions)
            let policyCalls = 0
            const { client, server } = await createPeers(fixture, {
                authenticationPolicyCalled: () => {
                    policyCalls++
                },
            })
            try {
                await expect(client.connect()).rejects.toThrow("All authentication methods failed")
                expect(policyCalls).toBe(expectedPolicyCalls)
            } finally {
                await closePeers(server, client)
            }
        },
    )

    test("accepts an application-enforced vendor critical option", async () => {
        const fixture = await issueCertificate([
            {
                name: "future-critical@example.test",
                data: Buffer.from("application policy data"),
            },
        ])
        const { client, server } = await createPeers(fixture, {
            handledCriticalOptions: ["future-critical@example.test"],
        })
        try {
            await client.connect()
            expect(client.isConnected).toBe(true)
        } finally {
            await closePeers(server, client)
        }
    })

    test("denies certificate-controlled forwarding and session features before hooks", async () => {
        const fixture = await issueCertificate()
        const calls = {
            agent: 0,
            channel: 0,
            pty: 0,
            tcp: 0,
            x11: 0,
        }
        class ForwardablePrivateKeyAgent extends PrivateKeyAgent {
            override async getStream() {
                return new PassThrough()
            }
        }
        const forwardingAgent = new ForwardablePrivateKeyAgent(
            fixture.identity.withCertificate(fixture.certificate),
        )
        const { client, server } = await createPeers(fixture, {
            agent: forwardingAgent,
            configureServer: (configuredServer) => {
                configuredServer.hooker.hook("channelOpenRequest", (_hook, channel, decision) => {
                    calls.channel++
                    decision.allowOpen = true
                    if (!(channel instanceof SessionChannel)) {
                        throw new Error("Certificate-restricted channel reached application policy")
                    }
                })
                configuredServer.hooker.hook("tcpipForward", (_hook, _context, decision) => {
                    calls.tcp++
                    decision.allow = true
                })
                configuredServer.on("connection", (connection) => {
                    connection.on("channel", (channel) => {
                        if (!(channel instanceof SessionChannel)) return
                        channel.hooker.hook("agentForwardRequest", (_hook, decision) => {
                            calls.agent++
                            decision.success = true
                        })
                        channel.hooker.hook("ptyRequest", (_hook, _context, decision) => {
                            calls.pty++
                            decision.success = true
                        })
                        channel.hooker.hook("x11Request", (_hook, _context, decision) => {
                            calls.x11++
                            decision.success = true
                        })
                    })
                })
            },
        })

        try {
            await client.connect()

            await expect(client.forwardOut("127.0.0.1", 0, "127.0.0.1", 22)).rejects.toThrow(
                "authenticated SSH certificate",
            )
            await expect(client.forwardIn("127.0.0.1", 0)).rejects.toThrow(
                "global request tcpip-forward failed",
            )

            const session = await client.openSession()
            await expect(session.requestPty()).rejects.toThrow("request failed")
            await expect(session.requestX11()).rejects.toThrow("request failed")
            await expect(session.forwardAgent()).rejects.toThrow("request failed")
            session.close()

            expect(calls).toEqual({ agent: 0, channel: 1, pty: 0, tcp: 0, x11: 0 })
        } finally {
            await closePeers(server, client)
        }
    }, 15_000)

    test("retains certificate restrictions after a second authentication factor", async () => {
        const fixture = await issueCertificate()
        let ptyPolicyCalls = 0
        const { client, server } = await createPeers(fixture, {
            passwordFactor: "second-factor",
            configureServer: (configuredServer) => {
                configuredServer.hooker.hook("channelOpenRequest", (_hook, channel, decision) => {
                    decision.allowOpen = channel instanceof SessionChannel
                })
                configuredServer.on("connection", (connection) => {
                    connection.on("channel", (channel) => {
                        if (!(channel instanceof SessionChannel)) return
                        channel.hooker.hook("ptyRequest", (_hook, _context, decision) => {
                            ptyPolicyCalls++
                            decision.success = true
                        })
                    })
                })
            },
        })

        try {
            await client.connect()
            const session = await client.openSession()
            await expect(session.requestPty()).rejects.toThrow("request failed")
            expect(ptyPolicyCalls).toBe(0)
            session.close()
        } finally {
            await closePeers(server, client)
        }
    })

    test("allows a session feature granted by its certificate extension", async () => {
        const fixture = await issueCertificate([], [{ name: "permit-pty", data: Buffer.alloc(0) }])
        let ptyPolicyCalls = 0
        const { client, server } = await createPeers(fixture, {
            configureServer: (configuredServer) => {
                configuredServer.hooker.hook("channelOpenRequest", (_hook, channel, decision) => {
                    decision.allowOpen = channel instanceof SessionChannel
                })
                configuredServer.on("connection", (connection) => {
                    connection.on("channel", (channel) => {
                        if (!(channel instanceof SessionChannel)) return
                        channel.hooker.hook("ptyRequest", (_hook, _context, decision) => {
                            ptyPolicyCalls++
                            decision.success = true
                        })
                    })
                })
            },
        })

        try {
            await client.connect()
            const session = await client.openSession()
            await session.requestPty()
            expect(ptyPolicyCalls).toBe(1)
            session.close()
        } finally {
            await closePeers(server, client)
        }
    })

    test("substitutes force-command for exec, shell, and subsystem requests", async () => {
        const fixture = await issueCertificate([
            { name: "force-command", data: nested("internal-backup") },
            { name: "source-address", data: nested("127.0.0.0/8") },
        ])
        const commands: string[] = []
        const { client, server } = await createPeers(fixture, {
            configureServer: (configuredServer) => {
                configuredServer.hooker.hook("channelOpenRequest", (_hook, channel, decision) => {
                    decision.allowOpen = channel instanceof SessionChannel
                })
                configuredServer.on("connection", (connection) => {
                    connection.on("channel", (channel) => {
                        if (!(channel instanceof SessionChannel)) return
                        channel.hooker.hook("execRequest", (_hook, context, decision) => {
                            commands.push(context.command)
                            decision.success = true
                        })
                    })
                })
            },
        })

        try {
            await client.connect()
            const exec = await client.exec("client-command")
            exec.close()
            const shell = await client.shell({ pty: false })
            shell.close()
            const subsystem = await client.subsystem("sftp")
            subsystem.close()
            expect(commands).toEqual(["internal-backup", "internal-backup", "internal-backup"])
        } finally {
            await closePeers(server, client)
        }
    }, 15_000)
})
