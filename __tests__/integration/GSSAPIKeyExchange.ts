import { createHmac, timingSafeEqual } from "node:crypto"
import { once } from "node:events"
import type { AddressInfo } from "node:net"

import Client from "../../src/Client.js"
import {
    KERBEROS_V5_GSSAPI_OID,
    type GSSAPIClientMechanism,
    type GSSAPIKeyExchangeClientContext,
    type GSSAPIKeyExchangeClientContextOptions,
    type GSSAPIKeyExchangeServerContext,
    type GSSAPIKeyExchangeServerContextOptions,
    type GSSAPIServerMechanism,
} from "../../src/GSSAPI.js"
import Server from "../../src/Server.js"
import { SSHAuthenticationMethods } from "../../src/constants.js"
import { gssapiKeyExchangeMethodNames } from "../../src/algorithms/kex/gssapi-key-exchange.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

const micKey = Buffer.from("independent GSS-API key-exchange test key")
const methodNames = gssapiKeyExchangeMethodNames(KERBEROS_V5_GSSAPI_OID)

function mic(message: Buffer): Buffer {
    return createHmac("sha256", micKey).update(message).digest()
}

class TestClientContext implements GSSAPIKeyExchangeClientContext {
    #round = 0
    readonly closes: number[]

    constructor(closes: number[]) {
        this.closes = closes
    }

    step(input?: Buffer) {
        this.#round++
        if (this.#round === 1) {
            expect(input).toBeUndefined()
            return { complete: false, token: Buffer.from("client-one") }
        }
        if (this.#round === 2) {
            expect(input).toEqual(Buffer.from("server-one"))
            return { complete: false, token: Buffer.from("client-two") }
        }
        if (this.#round === 3) {
            expect(input).toEqual(Buffer.from("server-two"))
            return { complete: false, token: Buffer.from("client-three") }
        }
        expect(input).toEqual(Buffer.from("server-final"))
        return { complete: true, integrity: true, mutualAuthentication: true }
    }

    verifyMIC(message: Buffer, received: Buffer): boolean {
        const expected = mic(message)
        return received.length === expected.length && timingSafeEqual(received, expected)
    }

    getMIC(message: Buffer): Buffer {
        return mic(message)
    }

    close(): void {
        this.closes.push(this.#round)
    }
}

class TestServerContext implements GSSAPIKeyExchangeServerContext {
    #round = 0
    readonly closes: number[]

    constructor(closes: number[]) {
        this.closes = closes
    }

    step(input: Buffer) {
        this.#round++
        if (this.#round === 1) {
            expect(input).toEqual(Buffer.from("client-one"))
            return { complete: false, token: Buffer.from("server-one") }
        }
        if (this.#round === 2) {
            expect(input).toEqual(Buffer.from("client-two"))
            return { complete: false, token: Buffer.from("server-two") }
        }
        expect(input).toEqual(Buffer.from("client-three"))
        return {
            complete: true,
            integrity: true,
            mutualAuthentication: true,
            token: Buffer.from("server-final"),
            peerIdentity: "user@EXAMPLE.TEST",
            delegatedCredentials: { ticket: "delegated" },
        }
    }

    getMIC(message: Buffer): Buffer {
        return mic(message)
    }

    verifyMIC(message: Buffer, received: Buffer): boolean {
        const expected = mic(message)
        return received.length === expected.length && timingSafeEqual(received, expected)
    }

    close(): void {
        this.closes.push(this.#round)
    }
}

class InvalidMICServerContext extends TestServerContext {
    getMIC(): Buffer {
        return Buffer.alloc(32, 0xa5)
    }
}

describe("RFC 8732 GSS-API key exchange", () => {
    test("derives the RFC method suffix from the complete mechanism OID", () => {
        expect(methodNames).toEqual([
            "gss-curve25519-sha256-toWM5Slw5Ew8Mqkay+al2g==",
            "gss-nistp256-sha256-toWM5Slw5Ew8Mqkay+al2g==",
            "gss-nistp384-sha384-toWM5Slw5Ew8Mqkay+al2g==",
            "gss-nistp521-sha512-toWM5Slw5Ew8Mqkay+al2g==",
            "gss-curve448-sha512-toWM5Slw5Ew8Mqkay+al2g==",
            "gss-group16-sha512-toWM5Slw5Ew8Mqkay+al2g==",
            "gss-group14-sha256-toWM5Slw5Ew8Mqkay+al2g==",
            "gss-group18-sha512-toWM5Slw5Ew8Mqkay+al2g==",
            "gss-group17-sha512-toWM5Slw5Ew8Mqkay+al2g==",
            "gss-group15-sha512-toWM5Slw5Ew8Mqkay+al2g==",
        ])
    })

    test.each(methodNames)(
        "establishes, protects traffic, and rekeys with %s",
        async (method) => {
            const clientCloses: number[] = []
            const serverCloses: number[] = []
            const clientOptions: GSSAPIKeyExchangeClientContextOptions[] = []
            const serverOptions: GSSAPIKeyExchangeServerContextOptions[] = []
            const clientMechanism: GSSAPIClientMechanism = {
                oid: KERBEROS_V5_GSSAPI_OID,
                createKeyExchangeContext(options) {
                    clientOptions.push({ ...options })
                    return new TestClientContext(clientCloses)
                },
            }
            const serverMechanism: GSSAPIServerMechanism = {
                oid: KERBEROS_V5_GSSAPI_OID,
                createKeyExchangeContext(options) {
                    serverOptions.push({ ...options })
                    return new TestServerContext(serverCloses)
                },
            }
            const server = new Server({
                hostKeys: [PrivateKey.generateSync("ssh-ed25519")],
                sendAllHostKeys: false,
                gssapi: [serverMechanism],
                algorithms: { kex: [method] },
            })
            const serverErrors: Error[] = []
            const serverHandshakes: string[] = []
            server.hooker.hook("noneAuthentication", (_hook, _context, decision) => {
                decision.allowLogin = true
            })
            server.hooker.hook("globalRequest", (_hook, context, decision) => {
                if (context.name !== "echo@example.test") return
                decision.success = true
                decision.response = Buffer.from(context.args)
            })
            server.on("connection", (peer) => {
                peer.on("error", (error) => serverErrors.push(error))
                peer.on("handshake", (negotiated) => serverHandshakes.push(negotiated.kex))
            })

            server.listen(0, "127.0.0.1")
            await once(server, "listening")
            const client = new Client({
                hostname: "127.0.0.1",
                port: (server.address() as AddressInfo).port,
                username: "gss-kex-test",
                gssapi: [clientMechanism],
                authenticationMethodsOrder: [SSHAuthenticationMethods.None],
                algorithms: { kex: [method] },
            })
            const clientErrors: Error[] = []
            const clientHandshakes: string[] = []
            client.on("error", (error) => clientErrors.push(error))
            client.on("handshake", (negotiated) => clientHandshakes.push(negotiated.kex))
            client.hooker.hook("hostKey", (_hook, decision) => {
                decision.allowHostKey = true
            })

            try {
                await client.connect()
                const sessionId = Buffer.from(client.sessionID!)
                const firstHash = Buffer.from(client.H!)
                expect(
                    await client.globalRequest("echo@example.test", Buffer.from("first")),
                ).toEqual(Buffer.from("first"))
                await client.rekey()
                expect(client.sessionID).toEqual(sessionId)
                expect(client.H).not.toEqual(firstHash)
                expect(
                    await client.globalRequest("echo@example.test", Buffer.from("second")),
                ).toEqual(Buffer.from("second"))
                expect(clientHandshakes).toEqual([method, method])
                expect(serverHandshakes).toEqual([method, method])
                expect(clientCloses).toEqual([4, 4])
                expect(serverCloses).toEqual([3, 3])
                expect(clientOptions).toHaveLength(2)
                expect(clientOptions[0]).toMatchObject({
                    hostname: "127.0.0.1",
                    service: "host",
                    anonymous: true,
                    mutualAuthentication: true,
                    integrity: true,
                    replayDetection: false,
                    sequenceDetection: false,
                })
                expect(serverOptions).toHaveLength(2)
                expect(serverOptions[0]).toMatchObject({ service: "host" })
                expect(clientErrors).toEqual([])
                expect(serverErrors).toEqual([])
            } finally {
                if (client.isConnected) {
                    const closed = once(client, "close")
                    client.end()
                    await closed
                } else {
                    client.destroy()
                }
                await server.close()
            }
        },
        20_000,
    )

    test("authenticates with the context from the initial key exchange", async () => {
        const clientCloses: number[] = []
        const serverCloses: number[] = []
        const clientOptions: GSSAPIKeyExchangeClientContextOptions[] = []
        const clientMechanism: GSSAPIClientMechanism = {
            oid: KERBEROS_V5_GSSAPI_OID,
            createKeyExchangeContext: (options) => {
                clientOptions.push({ ...options })
                return new TestClientContext(clientCloses)
            },
        }
        const serverMechanism: GSSAPIServerMechanism = {
            oid: KERBEROS_V5_GSSAPI_OID,
            createKeyExchangeContext: () => new TestServerContext(serverCloses),
        }
        const method = methodNames[0]
        const server = new Server({
            hostKeys: [PrivateKey.generateSync("ssh-ed25519")],
            sendAllHostKeys: false,
            gssapi: [serverMechanism],
            algorithms: { kex: [method] },
        })
        const policyContexts: unknown[] = []
        server.hooker.hook("gssapiAuthentication", (_hook, context, decision) => {
            policyContexts.push(context)
            decision.allowLogin = context.peerIdentity === "user@EXAMPLE.TEST"
        })
        server.listen(0, "127.0.0.1")
        await once(server, "listening")
        const client = new Client({
            hostname: "127.0.0.1",
            port: (server.address() as AddressInfo).port,
            username: "gss-kex-test",
            gssapi: [clientMechanism],
            algorithms: { kex: [method] },
        })
        client.hooker.hook("hostKey", (_hook, decision) => {
            decision.allowHostKey = true
        })
        try {
            await client.connect()
            expect(clientCloses).toEqual([4])
            expect(serverCloses).toEqual([3])
            expect(clientOptions).toHaveLength(1)
            expect(clientOptions[0].anonymous).toBeFalse()
            expect(policyContexts).toEqual([
                {
                    username: "gss-kex-test",
                    service: "ssh-connection",
                    mechanismOID: KERBEROS_V5_GSSAPI_OID,
                    integrity: true,
                    peerIdentity: "user@EXAMPLE.TEST",
                    delegatedCredentials: { ticket: "delegated" },
                },
            ])
        } finally {
            if (client.isConnected) {
                const closed = once(client, "close")
                client.end()
                await closed
            } else {
                client.destroy()
            }
            await server.close()
        }
    })

    test("rejects an invalid exchange MIC before host-key policy", async () => {
        const clientMechanism: GSSAPIClientMechanism = {
            oid: KERBEROS_V5_GSSAPI_OID,
            createKeyExchangeContext: () => new TestClientContext([]),
        }
        const serverMechanism: GSSAPIServerMechanism = {
            oid: KERBEROS_V5_GSSAPI_OID,
            createKeyExchangeContext: () => new InvalidMICServerContext([]),
        }
        const method = methodNames[0]
        const server = new Server({
            hostKeys: [PrivateKey.generateSync("ssh-ed25519")],
            sendAllHostKeys: false,
            gssapi: [serverMechanism],
            algorithms: { kex: [method] },
        })
        server.hooker.hook("noneAuthentication", (_hook, _context, decision) => {
            decision.allowLogin = true
        })
        server.on("connection", (peer) => peer.on("error", () => undefined))
        server.listen(0, "127.0.0.1")
        await once(server, "listening")
        const client = new Client({
            hostname: "127.0.0.1",
            port: (server.address() as AddressInfo).port,
            username: "gss-kex-test",
            gssapi: [clientMechanism],
            authenticationMethodsOrder: [SSHAuthenticationMethods.None],
            algorithms: { kex: [method] },
        })
        let hostKeyCalls = 0
        client.on("error", () => undefined)
        client.hooker.hook("hostKey", (_hook, decision) => {
            hostKeyCalls++
            decision.allowHostKey = true
        })
        try {
            await expect(client.connect()).rejects.toThrow("Invalid GSS-API key-exchange MIC")
            expect(hostKeyCalls).toBe(0)
        } finally {
            client.destroy()
            await server.close()
        }
    })

    test("supports RFC 4462 null host-key negotiation without a host-key callback", async () => {
        const clientMechanism: GSSAPIClientMechanism = {
            oid: KERBEROS_V5_GSSAPI_OID,
            createKeyExchangeContext: () => new TestClientContext([]),
        }
        const serverMechanism: GSSAPIServerMechanism = {
            oid: KERBEROS_V5_GSSAPI_OID,
            createKeyExchangeContext: () => new TestServerContext([]),
        }
        const method = methodNames[0]
        const server = new Server({
            gssapi: [serverMechanism],
            algorithms: { kex: [method], serverHostKey: ["null"] },
        })
        expect(server.options.hostKeys).toEqual([])
        server.hooker.hook("noneAuthentication", (_hook, _context, decision) => {
            decision.allowLogin = true
        })
        server.listen(0, "127.0.0.1")
        await once(server, "listening")
        const client = new Client({
            hostname: "127.0.0.1",
            port: (server.address() as AddressInfo).port,
            username: "gss-kex-test",
            gssapi: [clientMechanism],
            authenticationMethodsOrder: [SSHAuthenticationMethods.None],
            algorithms: { kex: [method], serverHostKey: ["null"] },
        })
        let hostKeyCalls = 0
        client.hooker.hook("hostKey", () => {
            hostKeyCalls++
        })
        try {
            await client.connect()
            expect(client.serverHostKey).toBeUndefined()
            expect(hostKeyCalls).toBe(0)
            const handshakes: string[] = []
            client.on("handshake", (negotiated) => handshakes.push(negotiated.srvHostKey))
            await client.rekey()
            expect(handshakes).toEqual(["null"])
            expect(hostKeyCalls).toBe(0)
        } finally {
            if (client.isConnected) {
                const closed = once(client, "close")
                client.end()
                await closed
            } else {
                client.destroy()
            }
            await server.close()
        }
    })

    test("rejects advertising null beside another server host-key algorithm", () => {
        expect(
            () =>
                new Server({
                    hostKeys: [PrivateKey.generateSync("ssh-ed25519")],
                    algorithms: { serverHostKey: ["ssh-ed25519", "null"] },
                }),
        ).toThrow("null host key must be the only advertised host key")
    })
})
