import { createHmac, timingSafeEqual } from "node:crypto"
import { once } from "node:events"
import type { AddressInfo } from "node:net"
import Client from "../../src/Client.js"
import { SSHAuthenticationMethods } from "../../src/constants.js"
import {
    GSSAPIError,
    KERBEROS_V5_GSSAPI_OID,
    type GSSAPIClientContextOptions,
    type GSSAPIClientMechanism,
    type GSSAPIServerContextOptions,
    type GSSAPIServerMechanism,
} from "../../src/GSSAPI.js"
import type Packet from "../../src/packet.js"
import {
    UserAuthGSSAPIExchangeComplete,
    UserAuthGSSAPIMIC,
    UserAuthGSSAPIResponse,
    UserAuthGSSAPIToken,
} from "../../src/packets/UserAuthGSSAPI.js"
import Ignore from "../../src/packets/Ignore.js"
import Unimplemented from "../../src/packets/Unimplemented.js"
import Server, { type ServerHookerGSSAPIAuthenticationContext } from "../../src/Server.js"
import type ServerClient from "../../src/ServerClient.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

const mechanismSecret = Buffer.from("independent-gssapi-test-credential")

function within<T>(operation: Promise<T>, label: string): Promise<T> {
    let timer: NodeJS.Timeout | undefined
    const timeout = new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => reject(new Error(`Timed out waiting for ${label}`)), 500)
        timer.unref()
    })
    return Promise.race([operation, timeout]).finally(() => {
        if (timer !== undefined) clearTimeout(timer)
    })
}

function token(label: string, data = Buffer.alloc(0)): Buffer {
    return createHmac("sha256", mechanismSecret).update(label).update(data).digest()
}

interface MechanismObservation {
    clientOptions?: Readonly<GSSAPIClientContextOptions>
    serverOptions?: Readonly<GSSAPIServerContextOptions>
    clientClosed: number
    serverClosed: number
}

function mechanisms(
    integrity: boolean,
    observation: MechanismObservation,
    options: { badMIC?: boolean; serverError?: boolean } = {},
): { client: GSSAPIClientMechanism; server: GSSAPIServerMechanism } {
    return {
        client: {
            oid: Buffer.from(KERBEROS_V5_GSSAPI_OID),
            createContext(contextOptions) {
                observation.clientOptions = contextOptions
                let round = 0
                return {
                    step(inputToken) {
                        if (round++ === 0) {
                            expect(inputToken).toBeUndefined()
                            return { complete: false, token: token("client-init") }
                        }
                        if (options.serverError && inputToken?.equals(token("server-error"))) {
                            return { complete: false }
                        }
                        expect(inputToken).toEqual(token("server-challenge"))
                        return {
                            complete: true,
                            integrity,
                            token: token("client-final"),
                        }
                    },
                    getMIC(message) {
                        const mic = token("mic", message)
                        if (options.badMIC) mic[0] ^= 0xff
                        return mic
                    },
                    close() {
                        observation.clientClosed++
                    },
                }
            },
        },
        server: {
            oid: Buffer.from(KERBEROS_V5_GSSAPI_OID),
            createContext(contextOptions) {
                observation.serverOptions = contextOptions
                let round = 0
                return {
                    step(inputToken) {
                        if (options.serverError) {
                            throw new GSSAPIError({
                                majorStatus: 0x000d_0000,
                                minorStatus: 7,
                                message: "test mechanism rejected credentials",
                                languageTag: "en-US",
                                token: token("server-error"),
                            })
                        }
                        if (round++ === 0) {
                            expect(inputToken).toEqual(token("client-init"))
                            return { complete: false, token: token("server-challenge") }
                        }
                        expect(inputToken).toEqual(token("client-final"))
                        return {
                            complete: true,
                            integrity,
                            peerIdentity: "alice@EXAMPLE.TEST",
                            delegatedCredentials: { cache: "delegated-test-cache" },
                        }
                    },
                    verifyMIC(message, mic) {
                        const expected = token("mic", message)
                        return expected.length === mic.length && timingSafeEqual(expected, mic)
                    },
                    close() {
                        observation.serverClosed++
                    },
                }
            },
        },
    }
}

async function createPeers(
    clientMechanism: GSSAPIClientMechanism,
    serverMechanism: GSSAPIServerMechanism,
    authorize: (context: ServerHookerGSSAPIAuthenticationContext) => boolean,
    authenticationMethodsOrder: readonly SSHAuthenticationMethods[] = [
        SSHAuthenticationMethods.GSSAPIWithMIC,
    ],
    authenticationTimeout = 30_000,
): Promise<{ client: Client; server: Server; peers: ServerClient[] }> {
    const server = new Server({
        hostKeys: [await PrivateKey.generate("ssh-ed25519")],
        gssapi: [serverMechanism],
        sendAllHostKeys: false,
        authenticationTimeout,
    })
    server.hooker.hook("gssapiAuthentication", (_hook, context, controller) => {
        controller.allowLogin = authorize(context)
    })
    const peers: ServerClient[] = []
    server.on("connection", (peer) => {
        peers.push(peer)
        peer.on("error", () => undefined)
    })
    server.listen({ host: "127.0.0.1", port: 0 })
    await once(server, "listening")

    const client = new Client({
        hostname: "127.0.0.1",
        port: (server.address() as AddressInfo).port,
        username: "alice",
        gssapi: [clientMechanism],
        gssapiDelegateCredentials: true,
        authenticationMethodsOrder,
    })
    client.hooker.hook("hostKey", (_hook, controller) => {
        controller.allowHostKey = true
    })
    return { client, server, peers }
}

async function closePeers(client: Client, server: Server, peers: ServerClient[]): Promise<void> {
    client.destroy()
    for (const peer of peers) peer.terminate()
    await server.close()
}

describe("RFC 4462 GSS-API user authentication", () => {
    test.each(["mechanism response", "context token"] as const)(
        "fails when the server GSS-API %s is unimplemented",
        async (rejectedPacket) => {
            const observation: MechanismObservation = { clientClosed: 0, serverClosed: 0 }
            const pair = mechanisms(true, observation)
            const clientReference: { current?: Client } = {}
            let rejectedSequence: number | undefined
            let rejectionTimer: NodeJS.Timeout | undefined
            const rejectedSequences: number[] = []
            const clientMechanism: GSSAPIClientMechanism = {
                oid: pair.client.oid,
                async createContext(options) {
                    const context = await pair.client.createContext!(options)
                    if (rejectedPacket === "mechanism response") {
                        expect(clientReference.current).toBeDefined()
                        expect(rejectedSequence).toBeDefined()
                        rejectionTimer = setTimeout(() => {
                            rejectionTimer = undefined
                            clientReference.current!.sendPacket(
                                new Unimplemented({
                                    sequence_number: rejectedSequence!,
                                }),
                            )
                        }, 10)
                    }
                    return {
                        async step(inputToken) {
                            const step = await context.step(inputToken)
                            if (rejectedPacket === "context token" && inputToken !== undefined) {
                                expect(clientReference.current).toBeDefined()
                                expect(rejectedSequence).toBeDefined()
                                rejectionTimer = setTimeout(() => {
                                    rejectionTimer = undefined
                                    clientReference.current!.sendPacket(
                                        new Unimplemented({
                                            sequence_number: rejectedSequence!,
                                        }),
                                    )
                                }, 10)
                            }
                            return step
                        },
                        getMIC: (message) => context.getMIC(message),
                        close: () => context.close?.(),
                    }
                },
            }
            const peers = await createPeers(
                clientMechanism,
                pair.server,
                () => true,
                [SSHAuthenticationMethods.GSSAPIWithMIC],
                500,
            )
            const client = peers.client
            clientReference.current = client
            peers.server.once("connection", (peer) => {
                const sendPacket = peer.sendPacket.bind(peer)
                peer.sendPacket = (packet: Packet) => {
                    const sequenceNumber = sendPacket(packet)
                    if (
                        (rejectedPacket === "mechanism response" &&
                            packet instanceof UserAuthGSSAPIResponse) ||
                        (rejectedPacket === "context token" &&
                            packet instanceof UserAuthGSSAPIToken)
                    ) {
                        rejectedSequence = sequenceNumber
                    }
                    return sequenceNumber
                }
                peer.on("unimplemented", (sequenceNumber) => rejectedSequences.push(sequenceNumber))
            })
            const sendPacket = client.sendPacket.bind(client)
            let clientTokens = 0
            client.sendPacket = (packet: Packet) => {
                if (packet instanceof UserAuthGSSAPIToken) {
                    clientTokens++
                    if (rejectedPacket === "mechanism response" || clientTokens > 1) return 0
                }
                if (
                    rejectedPacket === "context token" &&
                    (packet instanceof UserAuthGSSAPIMIC ||
                        packet instanceof UserAuthGSSAPIExchangeComplete)
                ) {
                    return 0
                }
                return sendPacket(packet)
            }

            try {
                const result = await client.connect().catch((error: Error) => error)
                expect(rejectedSequences).toEqual([rejectedSequence])
                expect(String(result)).toContain("All authentication methods failed")
            } finally {
                if (rejectionTimer) clearTimeout(rejectionTimer)
                await closePeers(client, peers.server, peers.peers)
            }
        },
        15_000,
    )

    test("treats an exact unimplemented reply as method failure", async () => {
        const observation: MechanismObservation = { clientClosed: 0, serverClosed: 0 }
        const pair = mechanisms(true, observation)
        const { client, server, peers } = await createPeers(pair.client, pair.server, () => true)

        server.once("connection", (peer) => {
            let requestSequence: number | undefined
            peer.on("packet", (metadata) => {
                if (metadata.name === "SSH_MSG_USERAUTH_REQUEST") {
                    requestSequence = metadata.sequenceNumber
                }
            })
            const sendPacket = peer.sendPacket.bind(peer)
            peer.sendPacket = (packet: Packet) =>
                packet instanceof UserAuthGSSAPIResponse && requestSequence !== undefined
                    ? sendPacket(new Unimplemented({ sequence_number: requestSequence }))
                    : sendPacket(packet)
        })

        try {
            await expect(client.connect()).rejects.toThrow("All authentication methods failed")
            expect(observation.clientOptions).toBeUndefined()
        } finally {
            await closePeers(client, server, peers)
        }
    }, 15_000)

    test.each([true, false])(
        "authenticates a multi-token context with integrity=%s",
        async (integrity) => {
            const observation: MechanismObservation = { clientClosed: 0, serverClosed: 0 }
            const pair = mechanisms(integrity, observation)
            let policyContext: ServerHookerGSSAPIAuthenticationContext | undefined
            const { client, server, peers } = await createPeers(
                pair.client,
                pair.server,
                (context) => {
                    policyContext = context
                    return (
                        context.username === "alice" &&
                        context.peerIdentity === "alice@EXAMPLE.TEST"
                    )
                },
            )

            try {
                await client.connect()
                expect(policyContext?.integrity).toBe(integrity)
                expect(policyContext?.mechanismOID).toEqual(KERBEROS_V5_GSSAPI_OID)
                expect(policyContext?.delegatedCredentials).toEqual({
                    cache: "delegated-test-cache",
                })
                expect(observation.clientOptions).toMatchObject({
                    hostname: "127.0.0.1",
                    username: "alice",
                    service: "ssh-connection",
                    delegateCredentials: true,
                })
                expect(observation.serverOptions).toMatchObject({
                    username: "alice",
                    service: "ssh-connection",
                })
                expect(observation.clientClosed).toBe(1)
                expect(observation.serverClosed).toBe(1)
            } finally {
                await closePeers(client, server, peers)
            }
        },
        15_000,
    )

    test("rejects an invalid MIC before application authorization", async () => {
        const observation: MechanismObservation = { clientClosed: 0, serverClosed: 0 }
        const pair = mechanisms(true, observation, { badMIC: true })
        let policyCalls = 0
        const { client, server, peers } = await createPeers(pair.client, pair.server, () => {
            policyCalls++
            return true
        })

        try {
            await expect(client.connect()).rejects.toThrow("All authentication methods failed")
            expect(policyCalls).toBe(0)
            expect(observation.clientClosed).toBe(1)
            expect(observation.serverClosed).toBe(1)
        } finally {
            await closePeers(client, server, peers)
        }
    }, 15_000)

    test.each([true, false])(
        "fails a premature final acknowledgement with integrity=%s",
        async (integrity) => {
            const observation: MechanismObservation = { clientClosed: 0, serverClosed: 0 }
            const clientMechanism: GSSAPIClientMechanism = {
                oid: KERBEROS_V5_GSSAPI_OID,
                createContext() {
                    return {
                        step() {
                            return { complete: true, integrity }
                        },
                        getMIC() {
                            return token("premature-mic")
                        },
                        close() {
                            observation.clientClosed++
                        },
                    }
                },
            }
            const serverMechanism: GSSAPIServerMechanism = {
                oid: KERBEROS_V5_GSSAPI_OID,
                createContext() {
                    return {
                        step() {
                            throw new Error(
                                "A premature acknowledgement must not reach the mechanism",
                            )
                        },
                        verifyMIC() {
                            throw new Error("A premature MIC must not be verified")
                        },
                        close() {
                            observation.serverClosed++
                        },
                    }
                },
            }
            let policyCalls = 0
            const { client, server, peers } = await createPeers(
                clientMechanism,
                serverMechanism,
                () => {
                    policyCalls++
                    return true
                },
            )

            try {
                await expect(client.connect()).rejects.toThrow("All authentication methods failed")
                expect(policyCalls).toBe(0)
                expect(observation.clientClosed).toBe(1)
                expect(observation.serverClosed).toBe(1)
            } finally {
                await closePeers(client, server, peers)
            }
        },
        15_000,
    )

    test("delivers server status and error tokens before authentication failure", async () => {
        const observation: MechanismObservation = { clientClosed: 0, serverClosed: 0 }
        const pair = mechanisms(true, observation, { serverError: true })
        const { client, server, peers } = await createPeers(pair.client, pair.server, () => true)
        const errors: unknown[] = []
        client.on("gssapiError", (error) => errors.push(error))

        try {
            await expect(client.connect()).rejects.toThrow("All authentication methods failed")
            expect(errors).toEqual([
                {
                    majorStatus: 0x000d_0000,
                    minorStatus: 7,
                    message: "test mechanism rejected credentials",
                    languageTag: "en-US",
                },
            ])
            expect(observation.clientClosed).toBe(1)
            expect(observation.serverClosed).toBe(1)
        } finally {
            await closePeers(client, server, peers)
        }
    }, 15_000)

    test("abandons a failed context with an error token before trying a new method", async () => {
        const observation: MechanismObservation = { clientClosed: 0, serverClosed: 0 }
        let receivedErrorToken = false
        const clientErrorToken = token("client-error")
        const clientMechanism: GSSAPIClientMechanism = {
            oid: KERBEROS_V5_GSSAPI_OID,
            createContext() {
                let initial = true
                return {
                    step(inputToken) {
                        if (initial) {
                            initial = false
                            return { complete: false, token: token("client-init") }
                        }
                        expect(inputToken).toEqual(token("server-challenge"))
                        throw new GSSAPIError({
                            majorStatus: 1,
                            minorStatus: 2,
                            message: "client-gssapi-private-metadata",
                            token: clientErrorToken,
                        })
                    },
                    getMIC() {
                        throw new Error("MIC must not be requested for a failed context")
                    },
                    close() {
                        observation.clientClosed++
                        throw new Error("client-gssapi-close-private-metadata")
                    },
                }
            },
        }
        const serverMechanism: GSSAPIServerMechanism = {
            oid: KERBEROS_V5_GSSAPI_OID,
            createContext() {
                let initial = true
                return {
                    step(inputToken) {
                        if (initial) {
                            initial = false
                            expect(inputToken).toEqual(token("client-init"))
                            return {
                                complete: true,
                                integrity: true,
                                token: token("server-challenge"),
                            }
                        }
                        receivedErrorToken = inputToken.equals(clientErrorToken)
                        throw new Error("server-gssapi-token-private-metadata")
                    },
                    verifyMIC() {
                        return false
                    },
                    close() {
                        observation.serverClosed++
                        throw new Error("server-gssapi-close-private-metadata")
                    },
                }
            },
        }
        const { client, server, peers } = await createPeers(
            clientMechanism,
            serverMechanism,
            () => false,
            [SSHAuthenticationMethods.GSSAPIWithMIC, SSHAuthenticationMethods.None],
        )
        server.hooker.hook("noneAuthentication", (_hook, context, controller) => {
            controller.allowLogin = context.username === "alice"
        })
        const diagnostics: unknown[][] = []
        client.on("debug", (...message) => diagnostics.push(message))
        server.on("debug", (...message) => diagnostics.push(message))

        try {
            await client.connect()
            expect(receivedErrorToken).toBe(true)
            expect(observation.clientClosed).toBe(1)
            expect(observation.serverClosed).toBe(1)
            const output = diagnostics
                .flatMap((message) => message)
                .map((value) =>
                    value instanceof Error
                        ? `${value.name}: ${value.message}`
                        : typeof value === "string"
                          ? value
                          : JSON.stringify(value),
                )
                .join("\n")
            expect(output).not.toContain("client-gssapi-private-metadata")
            expect(output).not.toContain("client-gssapi-close-private-metadata")
            expect(output).not.toContain("server-gssapi-token-private-metadata")
            expect(output).not.toContain("server-gssapi-close-private-metadata")
        } finally {
            await closePeers(client, server, peers)
        }
    }, 15_000)

    test("closes when packets accumulate beyond the GSS context wait bound", async () => {
        const observation: MechanismObservation = { clientClosed: 0, serverClosed: 0 }
        const pair = mechanisms(true, observation)
        let releaseServerStep!: () => void
        const serverStepReleased = new Promise<void>((resolve) => {
            releaseServerStep = resolve
        })
        let reportServerStepStarted!: () => void
        const serverStepStarted = new Promise<void>((resolve) => {
            reportServerStepStarted = resolve
        })
        const blockedServer: GSSAPIServerMechanism = {
            oid: pair.server.oid,
            async createContext(options) {
                const context = await pair.server.createContext!(options)
                let blocked = false
                return {
                    async step(inputToken) {
                        if (!blocked) {
                            blocked = true
                            reportServerStepStarted()
                            await serverStepReleased
                        }
                        return context.step(inputToken)
                    },
                    verifyMIC: (message, mic) => context.verifyMIC(message, mic),
                    close: () => context.close?.(),
                }
            },
        }
        const { client, server, peers } = await createPeers(pair.client, blockedServer, () => true)
        client.on("error", () => undefined)
        const closed = once(client, "close")
        let closeObserved = false
        client.once("close", () => {
            closeObserved = true
        })
        const connecting = client.connect()
        void connecting.catch(() => undefined)

        try {
            await serverStepStarted
            for (let index = 0; index < 64; index++) {
                client.sendPacket(new Ignore({ data: Buffer.alloc(0) }))
            }
            await new Promise<void>((resolve) => setImmediate(resolve))
            expect(closeObserved).toBe(false)

            client.sendPacket(new Ignore({ data: Buffer.alloc(0) }))
            await within(closed, "the overfull GSS packet queue to close the connection")
            await expect(connecting).rejects.toThrow()
        } finally {
            releaseServerStep()
            await closePeers(client, server, peers)
        }
    }, 15_000)
})
