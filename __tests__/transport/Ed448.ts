import type { AddressInfo } from "node:net"
import Client from "../../src/Client.js"
import Server from "../../src/Server.js"
import { SSHAuthenticationMethods } from "../../src/constants.js"
import { default_algorithm_names, host_key_algorithms } from "../../src/algorithms.js"
import PrivateKey from "../../src/utils/PrivateKey.js"
import PublicKey from "../../src/utils/PublicKey.js"
import { serializeBuffer, serializeUint32, serializeUint64 } from "../../src/utils/Buffer.js"

describe("RFC 8709 Ed448 host keys", () => {
    test("is supported through explicit negotiation but excluded from defaults", () => {
        expect(host_key_algorithms.has("ssh-ed448")).toBe(true)
        expect(host_key_algorithms.has("ssh-ed448-cert")).toBe(true)
        expect(host_key_algorithms.get("rsa-sha2-512-cert")).toMatchObject({
            key_format: "ssh-rsa-cert",
            signature_algorithm: "rsa-sha2-512",
        })
        expect(default_algorithm_names.serverHostKey).not.toContain("ssh-ed448")
        expect(default_algorithm_names.serverHostKey).not.toContain("ssh-ed448-cert")
        expect(default_algorithm_names.serverHostKey).not.toContain("rsa-sha2-512-cert")
    })

    test("authenticates a library peer with an Ed448 host signature", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed448")
        const server = new Server({
            hostKeys: [hostKey],
            sendAllHostKeys: false,
            algorithms: { serverHostKey: ["ssh-ed448"] },
        })
        server.hooker.hook("noneAuthentication", async (_hook, _context, decision) => {
            decision.allowLogin = true
        })
        server.listen({ host: "127.0.0.1", port: 0 })
        await new Promise<void>((resolve) => server.server!.once("listening", resolve))

        const client = new Client({
            hostname: "127.0.0.1",
            port: (server.server!.address() as AddressInfo).port,
            algorithms: { serverHostKey: ["ssh-ed448"] },
            authenticationMethodsOrder: [SSHAuthenticationMethods.None],
        })
        client.hooker.hook("hostKey", async (_hook, decision, key) => {
            decision.allowHostKey = key.equals(hostKey.data.publicKey)
        })
        let negotiatedHostKey: string | undefined
        client.on("handshake", (algorithms) => {
            negotiatedHostKey = algorithms.srvHostKey
        })
        try {
            await client.connect()
            expect(negotiatedHostKey).toBe("ssh-ed448")
            expect(client.isConnected).toBe(true)
        } finally {
            client.destroy()
            for (const peer of server.clients) peer.terminate()
            await new Promise<void>((resolve, reject) => {
                server.server!.close((error) => (error ? reject(error) : resolve()))
            })
        }
    })

    test("authenticates with a standard CA-signed Ed448 host certificate", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed448")
        const ca = await PrivateKey.generate("ssh-ed25519")
        const certificateType = "ssh-ed448-cert"
        const principal = serializeBuffer(Buffer.from("127.0.0.1"))
        const signed = Buffer.concat([
            serializeBuffer(Buffer.from(certificateType)),
            serializeBuffer(Buffer.alloc(32, 0x42)),
            hostKey.data.publicKey.data.algorithm.serialize(),
            serializeUint64(7n),
            serializeUint32(2),
            serializeBuffer(Buffer.from("standard-ed448-host")),
            serializeBuffer(principal),
            serializeUint64(0n),
            serializeUint64(0xffffffffffffffffn),
            serializeBuffer(Buffer.alloc(0)),
            serializeBuffer(Buffer.alloc(0)),
            serializeBuffer(Buffer.alloc(0)),
            serializeBuffer(ca.data.publicKey.serialize()),
        ])
        const certificate = PublicKey.parse(
            Buffer.concat([signed, serializeBuffer(ca.sign(signed).serialize())]),
        )
        const certifiedHostKey = hostKey.withCertificate(certificate)
        const server = new Server({
            hostKeys: [certifiedHostKey],
            sendAllHostKeys: false,
            algorithms: { serverHostKey: [certificateType] },
        })
        server.hooker.hook("noneAuthentication", async (_hook, _context, decision) => {
            decision.allowLogin = true
        })
        server.listen({ host: "127.0.0.1", port: 0 })
        await new Promise<void>((resolve) => server.server!.once("listening", resolve))

        const client = new Client({
            hostname: "127.0.0.1",
            port: (server.server!.address() as AddressInfo).port,
            algorithms: { serverHostKey: [certificateType] },
            authenticationMethodsOrder: [SSHAuthenticationMethods.None],
        })
        client.hooker.hook("hostKey", async (_hook, decision, key) => {
            decision.allowHostKey = key.equals(certificate)
        })
        try {
            await client.connect()
            expect(client.negotiatedAlgorithms?.srvHostKey).toBe(certificateType)
            expect(client.serverHostKey).toEqual(certificate.serialize())
        } finally {
            client.destroy()
            for (const peer of server.clients) peer.terminate()
            await new Promise<void>((resolve, reject) => {
                server.server!.close((error) => (error ? reject(error) : resolve()))
            })
        }
    })
})
