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
import Server, { type ServerHookerGSSAPIAuthenticationContext } from "../../src/Server.js"
import type ServerClient from "../../src/ServerClient.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

const mechanismSecret = Buffer.from("independent-gssapi-test-credential")

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
): Promise<{ client: Client; server: Server; peers: ServerClient[] }> {
    const server = new Server({
        hostKeys: [await PrivateKey.generate("ssh-ed25519")],
        gssapi: [serverMechanism],
        sendAllHostKeys: false,
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
                            token: clientErrorToken,
                        })
                    },
                    getMIC() {
                        throw new Error("MIC must not be requested for a failed context")
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
                        return { complete: false }
                    },
                    verifyMIC() {
                        return false
                    },
                    close() {
                        observation.serverClosed++
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

        try {
            await client.connect()
            expect(receivedErrorToken).toBe(true)
            expect(observation.clientClosed).toBe(1)
            expect(observation.serverClosed).toBe(1)
        } finally {
            await closePeers(client, server, peers)
        }
    }, 15_000)
})
