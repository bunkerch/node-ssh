import { execFile } from "node:child_process"
import { mkdtemp, readFile, rm } from "node:fs/promises"
import { AddressInfo } from "node:net"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { promisify } from "node:util"
import Client from "../../src/Client.js"
import { SSHAuthenticationMethods } from "../../src/constants.js"
import Server from "../../src/Server.js"
import PrivateKeyAgent from "../../src/publickey/PrivateKeyAgent.js"
import PrivateKey from "../../src/utils/PrivateKey.js"
import PublicKey from "../../src/utils/PublicKey.js"
import EncodedSignature from "../../src/utils/Signature.js"
import { serializeBuffer, serializeUint32, serializeUint64 } from "../../src/utils/Buffer.js"

const execFileAsync = promisify(execFile)

describe("certificate user authentication", () => {
    test("rejects a bad possession signature before awaited policy", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const identity = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({ hostKeys: [hostKey], sendAllHostKeys: false })
        let policyCalls = 0
        server.hooker.hook("publicKeyAuthentication", () => {
            policyCalls++
        })
        class InvalidSignatureAgent extends PrivateKeyAgent {
            override async sign(id: string, data: Buffer, algorithm?: string) {
                const signature = await super.sign(id, data, algorithm)
                const corrupted = Buffer.from(signature.data.data)
                corrupted[0] ^= 1
                return new EncodedSignature({ ...signature.data, data: corrupted })
            }
        }
        server.listen({ host: "127.0.0.1", port: 0 })
        await new Promise<void>((resolve) => server.server!.once("listening", resolve))
        const client = new Client({
            hostname: "127.0.0.1",
            port: (server.server!.address() as AddressInfo).port,
            username: "alice",
            agent: new InvalidSignatureAgent(identity),
            authenticationMethodsOrder: [SSHAuthenticationMethods.PublicKey],
        })
        client.hooker.hook("hostKey", (_hook, decision) => {
            decision.allowHostKey = true
        })
        try {
            await expect(client.connect()).rejects.toThrow("All authentication methods failed")
            expect(policyCalls).toBe(0)
        } finally {
            client.destroy()
            for (const connection of server.clients) connection.terminate()
            await new Promise<void>((resolve, reject) => {
                server.server!.close((error) => (error ? reject(error) : resolve()))
            })
        }
    })

    test("authenticates a standard CA-signed Ed448 identity", async () => {
        const serverHostKey = await PrivateKey.generate("ssh-ed25519")
        const identity = await PrivateKey.generate("ssh-ed448")
        const ca = await PrivateKey.generate("ssh-ed25519")
        const certificateType = "ssh-ed448-cert"
        const signed = Buffer.concat([
            serializeBuffer(Buffer.from(certificateType)),
            serializeBuffer(Buffer.alloc(32, 0x24)),
            identity.data.publicKey.data.algorithm.serialize(),
            serializeUint64(9n),
            serializeUint32(1),
            serializeBuffer(Buffer.from("standard-ed448-user")),
            serializeBuffer(serializeBuffer(Buffer.from("alice"))),
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
        const server = new Server({ hostKeys: [serverHostKey], sendAllHostKeys: false })
        let observedAlgorithm: string | undefined
        server.hooker.hook("publicKeyAuthentication", async (_hook, context, decision) => {
            await Promise.resolve()
            observedAlgorithm = context.algorithm
            decision.allowLogin =
                context.username === "alice" &&
                context.certificate?.data.signatureKey.equals(ca.data.publicKey) === true &&
                context.certificate.data.principals.includes("alice")
        })
        server.listen({ host: "127.0.0.1", port: 0 })
        await new Promise<void>((resolve) => server.server!.once("listening", resolve))

        const client = new Client({
            hostname: "127.0.0.1",
            port: (server.server!.address() as AddressInfo).port,
            username: "alice",
            privateKey: identity,
            certificate,
            authenticationMethodsOrder: [SSHAuthenticationMethods.PublicKey],
        })
        client.hooker.hook("hostKey", async (_hook, decision) => {
            decision.allowHostKey = true
        })
        try {
            await client.connect()
            expect(observedAlgorithm).toBe(certificateType)
            expect(client.isConnected).toBe(true)
        } finally {
            client.destroy()
            for (const connection of server.clients) connection.terminate()
            await new Promise<void>((resolve, reject) => {
                server.server!.close((error) => (error ? reject(error) : resolve()))
            })
        }
    })

    test.each([
        ["ed25519", []],
        ["rsa", ["-b", "2048"]],
        ["ecdsa", ["-b", "256"]],
    ])(
        "authenticates an OpenSSH-issued %s identity",
        async (type, keyOptions) => {
            const directory = await mkdtemp(join(tmpdir(), "modernssh-certificate-auth-"))
            const serverHostKey = await PrivateKey.generate("ssh-ed25519")
            const server = new Server({ hostKeys: [serverHostKey], sendAllHostKeys: false })
            const contexts: unknown[] = []
            let client: Client | undefined
            try {
                const caPath = join(directory, "ca")
                const identityPath = join(directory, "identity")
                await execFileAsync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", caPath])
                await execFileAsync("ssh-keygen", [
                    "-q",
                    "-t",
                    type,
                    ...keyOptions,
                    "-N",
                    "",
                    "-f",
                    identityPath,
                ])
                await execFileAsync("ssh-keygen", [
                    "-q",
                    "-s",
                    caPath,
                    "-I",
                    "library-client",
                    "-n",
                    "alice",
                    "-V",
                    "-1m:+1h",
                    identityPath + ".pub",
                ])
                const ca = PublicKey.parseString(await readFile(caPath + ".pub", "utf8"))
                const certificate = PublicKey.parseString(
                    await readFile(identityPath + "-cert.pub", "utf8"),
                )
                const privateKey = PrivateKey.fromString(await readFile(identityPath, "utf8"))

                server.hooker.hook("publicKeyAuthentication", async (_hook, context, decision) => {
                    await Promise.resolve()
                    contexts.push(context)
                    const cert = context.certificate
                    if (!context.signature || !cert) return
                    decision.allowLogin =
                        context.username === "alice" &&
                        cert.data.signatureKey.equals(ca) &&
                        cert.data.principals.includes("alice") &&
                        cert.data.criticalOptions.length === 0
                })
                server.listen({ host: "127.0.0.1", port: 0 })
                await new Promise<void>((resolve) => server.server!.once("listening", resolve))

                client = new Client({
                    hostname: "127.0.0.1",
                    port: (server.server!.address() as AddressInfo).port,
                    username: "alice",
                    privateKey,
                    certificate,
                    authenticationMethodsOrder: [SSHAuthenticationMethods.PublicKey],
                })
                client.hooker.hook("hostKey", (_hook, decision) => {
                    decision.allowHostKey = true
                })
                await client.connect()

                expect(contexts).toHaveLength(1)
                const context = contexts[0] as {
                    algorithm: string
                    certificate?: { publicKey: PublicKey }
                    hostbound: boolean
                }
                expect(context.algorithm).toBe(
                    type === "rsa" ? "rsa-sha2-512-cert-v01@openssh.com" : certificate.data.alg,
                )
                expect(context.hostbound).toBe(true)
                expect(context.certificate?.publicKey.equals(privateKey.data.publicKey)).toBe(true)
            } finally {
                client?.destroy()
                for (const connection of server.clients) connection.terminate()
                if (server.server?.listening) {
                    await new Promise<void>((resolve, reject) => {
                        server.server!.close((error) => (error ? reject(error) : resolve()))
                    })
                }
                await rm(directory, { recursive: true, force: true })
            }
        },
        15_000,
    )
})
