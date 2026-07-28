import { once } from "node:events"
import type { AddressInfo } from "node:net"
import Client from "../../src/Client.js"
import Server from "../../src/Server.js"
import { SSHAuthenticationMethods } from "../../src/constants.js"
import Packet from "../../src/packet.js"
import ExtInfo from "../../src/packets/ExtInfo.js"
import PrivateKey, { SSHDSSPrivateKey } from "../../src/utils/PrivateKey.js"
import { rfc6979DSAParameters } from "../fixtures/DSAParameters.js"

function fixedDSAKey(): PrivateKey {
    const algorithm = new SSHDSSPrivateKey(rfc6979DSAParameters)
    return new PrivateKey({
        alg: "ssh-dss",
        algorithm,
        publicKey: algorithm.getPublicKey(),
    })
}

interface AuthenticationAttempt {
    attempts: number
    advertised: readonly string[]
    authenticated: boolean
}

async function attemptLegacyClientAuthentication(
    method: SSHAuthenticationMethods.PublicKey | SSHAuthenticationMethods.Hostbased,
    hostKey: PrivateKey,
    clientKey: PrivateKey,
    authenticationSignatureAlgorithms?: string[],
): Promise<Pick<AuthenticationAttempt, "attempts" | "authenticated">> {
    const server = new Server({
        hostKeys: [hostKey],
        sendAllHostKeys: false,
        authenticationSignatureAlgorithms: ["ssh-dss"],
    })
    let attempts = 0
    server.hooker.hook("publicKeyAuthentication", (_hook, context, decision) => {
        attempts++
        decision.allowLogin =
            context.signature !== undefined &&
            context.publicKey.equals(clientKey.data.publicKey) &&
            context.publicKey.verifySignature(context.signatureMessage, context.signature)
    })
    server.hooker.hook("hostbasedAuthentication", (_hook, context, decision) => {
        attempts++
        decision.allowLogin = context.publicKey.equals(clientKey.data.publicKey)
    })
    server.on("connection", (connection) => {
        const sendPacket = connection.sendPacket.bind(connection)
        connection.sendPacket = (packet: Packet) =>
            packet instanceof ExtInfo
                ? sendPacket(
                      new ExtInfo({
                          extensions: packet.data.extensions.filter(
                              ({ name }) => name !== "server-sig-algs",
                          ),
                      }),
                  )
                : sendPacket(packet)
    })
    server.listen({ host: "127.0.0.1", port: 0 })
    await once(server, "listening")

    const client = new Client({
        hostname: "127.0.0.1",
        port: (server.address() as AddressInfo).port,
        username: "client-signature-policy",
        privateKey: method === SSHAuthenticationMethods.PublicKey ? clientKey : undefined,
        hostbased:
            method === SSHAuthenticationMethods.Hostbased
                ? {
                      key: clientKey,
                      localHostname: "build.example.test",
                      localUsername: "builder",
                  }
                : undefined,
        authenticationMethodsOrder: [method],
        authenticationSignatureAlgorithms,
    })
    authenticationSignatureAlgorithms?.fill("ssh-ed25519")
    client.hooker.hook("hostKey", (_hook, decision) => {
        decision.allowHostKey = true
    })

    try {
        const authenticated = await client.connect().then(
            () => true,
            () => false,
        )
        return { attempts, authenticated }
    } finally {
        client.destroy()
        for (const connection of server.clients) connection.terminate()
        await server.close()
    }
}

async function attemptHostbasedAuthentication(
    hostKey: PrivateKey,
    clientKey: PrivateKey,
    authenticationSignatureAlgorithms?: string[],
): Promise<AuthenticationAttempt> {
    const server = new Server({
        hostKeys: [hostKey],
        sendAllHostKeys: false,
        authenticationSignatureAlgorithms,
    })
    authenticationSignatureAlgorithms?.fill("ssh-ed25519")
    let attempts = 0
    server.hooker.hook("hostbasedAuthentication", (_hook, context, decision) => {
        attempts++
        decision.allowLogin = context.publicKey.equals(clientKey.data.publicKey)
    })
    server.listen({ host: "127.0.0.1", port: 0 })
    await once(server, "listening")

    let advertised: readonly string[] = []
    const client = new Client({
        hostname: "127.0.0.1",
        port: (server.address() as AddressInfo).port,
        username: "signature-policy",
        hostbased: {
            key: clientKey,
            localHostname: "build.example.test",
            localUsername: "builder",
            algorithm: "ssh-dss",
        },
        authenticationMethodsOrder: [SSHAuthenticationMethods.Hostbased],
        authenticationSignatureAlgorithms: ["ssh-dss"],
    })
    client.hooker.hook("hostKey", (_hook, decision) => {
        decision.allowHostKey = true
    })
    client.on("serverExtensions", () => {
        advertised = client.serverSignatureAlgorithms ?? []
    })

    try {
        const authenticated = await client.connect().then(
            () => true,
            () => false,
        )
        return { attempts, advertised, authenticated }
    } finally {
        client.destroy()
        for (const connection of server.clients) connection.terminate()
        await server.close()
    }
}

async function attemptPublicKeyAuthentication(
    hostKey: PrivateKey,
    clientKey: PrivateKey,
    authenticationSignatureAlgorithms?: string[],
): Promise<AuthenticationAttempt> {
    const server = new Server({
        hostKeys: [hostKey],
        sendAllHostKeys: false,
        authenticationSignatureAlgorithms,
    })
    authenticationSignatureAlgorithms?.fill("ssh-ed25519")
    let attempts = 0
    server.hooker.hook("publicKeyAuthentication", (_hook, context, decision) => {
        attempts++
        decision.allowLogin =
            context.signature !== undefined &&
            context.publicKey.equals(clientKey.data.publicKey) &&
            context.publicKey.verifySignature(context.signatureMessage, context.signature)
    })
    server.listen({ host: "127.0.0.1", port: 0 })
    await once(server, "listening")

    let advertised: readonly string[] = []
    const client = new Client({
        hostname: "127.0.0.1",
        port: (server.address() as AddressInfo).port,
        username: "signature-policy",
        privateKey: clientKey,
        authenticationMethodsOrder: [SSHAuthenticationMethods.PublicKey],
        authenticationSignatureAlgorithms: ["ssh-dss"],
    })
    client.hooker.hook("hostKey", (_hook, decision) => {
        decision.allowHostKey = true
    })
    client.on("serverExtensions", () => {
        advertised = client.serverSignatureAlgorithms ?? []
    })

    try {
        const authenticated = await client.connect().then(
            () => true,
            () => false,
        )
        return { attempts, advertised, authenticated }
    } finally {
        client.destroy()
        for (const connection of server.clients) connection.terminate()
        await server.close()
    }
}

describe("server authentication signature algorithms", () => {
    test("rejects legacy host-based signatures before policy unless explicitly enabled", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const clientKey = fixedDSAKey()

        const denied = await attemptHostbasedAuthentication(hostKey, clientKey)
        expect(denied.authenticated).toBe(false)
        expect(denied.attempts).toBe(0)
        expect(denied.advertised).not.toContain("ssh-dss")
        expect(denied.advertised).not.toContain("ssh-rsa")
        expect(denied.advertised).toContain("rsa-sha2-512")

        const allowed = await attemptHostbasedAuthentication(hostKey, clientKey, ["ssh-dss"])
        expect(allowed).toEqual({
            attempts: 1,
            advertised: ["ssh-dss"],
            authenticated: true,
        })
    }, 15_000)

    test("advertises and accepts legacy public-key signatures only after opt-in", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const clientKey = fixedDSAKey()

        const denied = await attemptPublicKeyAuthentication(hostKey, clientKey)
        expect(denied.authenticated).toBe(false)
        expect(denied.attempts).toBe(0)
        expect(denied.advertised).not.toContain("ssh-dss")

        const allowed = await attemptPublicKeyAuthentication(hostKey, clientKey, ["ssh-dss"])
        expect(allowed).toEqual({
            attempts: 1,
            advertised: ["ssh-dss"],
            authenticated: true,
        })
    }, 15_000)
})

describe("client authentication signature algorithms", () => {
    for (const method of [
        SSHAuthenticationMethods.PublicKey,
        SSHAuthenticationMethods.Hostbased,
    ] as const) {
        test(`requires explicit legacy opt-in for ${method} when the server omits its signature list`, async () => {
            const hostKey = await PrivateKey.generate("ssh-ed25519")
            const clientKey = fixedDSAKey()

            const denied = await attemptLegacyClientAuthentication(method, hostKey, clientKey)
            expect(denied).toEqual({ attempts: 0, authenticated: false })

            const allowed = await attemptLegacyClientAuthentication(method, hostKey, clientKey, [
                "ssh-dss",
            ])
            expect(allowed).toEqual({ attempts: 1, authenticated: true })
        }, 15_000)
    }
})
