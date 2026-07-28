import { once } from "node:events"
import type { AddressInfo } from "node:net"
import Client from "../../src/Client.js"
import Server from "../../src/Server.js"
import { SSHAuthenticationMethods } from "../../src/constants.js"
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
