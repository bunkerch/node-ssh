import { execFile } from "node:child_process"
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises"
import { AddressInfo } from "node:net"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { promisify } from "node:util"
import Client from "../../src/Client.js"
import { SSHAuthenticationMethods } from "../../src/constants.js"
import KnownHosts from "../../src/KnownHosts.js"
import Server from "../../src/Server.js"
import PrivateKey from "../../src/utils/PrivateKey.js"
import PublicKey, { SSHCertificatePublicKey } from "../../src/utils/PublicKey.js"

const execFileAsync = promisify(execFile)

describe("certificate host authentication", () => {
    test.each([
        ["user-role", [] as string[], "Invalid host certificate role"],
        ["wrong-principal", ["-h"], "Host certificate is not valid for the requested hostname"],
    ])("rejects a %s certificate before host trust policy", async (identity, options, message) => {
        const directory = await mkdtemp(join(tmpdir(), "modernssh-wrong-host-certificate-"))
        let server: Server | undefined
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        let client: Client | undefined
        try {
            const caPath = join(directory, "ca")
            const hostPath = join(directory, "host")
            await execFileAsync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", caPath])
            await writeFile(hostPath + ".pub", hostKey.data.publicKey.toString() + "\n")
            await execFileAsync("ssh-keygen", [
                "-q",
                "-s",
                caPath,
                "-I",
                identity,
                ...options,
                "-n",
                identity === "wrong-principal" ? "elsewhere.example.test" : "127.0.0.1",
                "-V",
                "-1m:+1h",
                hostPath + ".pub",
            ])
            server = new Server({
                hostKeys: [hostKey],
                hostCertificates: [await readFile(hostPath + "-cert.pub")],
                sendAllHostKeys: false,
            })
            server.hooker.hook("noneAuthentication", (_hook, _context, decision) => {
                decision.allowLogin = true
            })
            server.listen({ host: "127.0.0.1", port: 0 })
            await new Promise<void>((resolve) => server!.server!.once("listening", resolve))
            let policyCalls = 0
            client = new Client({
                hostname: "127.0.0.1",
                port: (server.server!.address() as AddressInfo).port,
                authenticationMethodsOrder: [SSHAuthenticationMethods.None],
            })
            client.hooker.hook("hostKey", () => {
                policyCalls++
            })
            await expect(client.connect()).rejects.toThrow(message)
            expect(policyCalls).toBe(0)
        } finally {
            client?.destroy()
            if (server) {
                for (const connection of server.clients) connection.terminate()
                if (server.server?.listening) {
                    await new Promise<void>((resolve, reject) => {
                        server!.server!.close((error) => (error ? reject(error) : resolve()))
                    })
                }
            }
            await rm(directory, { recursive: true, force: true })
        }
    })

    test.each([
        ["ed25519", []],
        ["rsa", ["-b", "2048"]],
        ["ecdsa", ["-b", "256"]],
    ])(
        "authenticates an OpenSSH-issued %s host identity",
        async (type, keyOptions) => {
            const directory = await mkdtemp(join(tmpdir(), "modernssh-host-certificate-"))
            let server: Server | undefined
            let client: Client | undefined
            try {
                const caPath = join(directory, "ca")
                const hostPath = join(directory, "host")
                await execFileAsync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", caPath])
                await execFileAsync("ssh-keygen", [
                    "-q",
                    "-t",
                    type,
                    ...keyOptions,
                    "-N",
                    "",
                    "-f",
                    hostPath,
                ])
                await execFileAsync("ssh-keygen", [
                    "-q",
                    "-s",
                    caPath,
                    "-I",
                    "library-server",
                    "-h",
                    "-n",
                    "127.0.0.1",
                    "-V",
                    "-1m:+1h",
                    hostPath + ".pub",
                ])
                const ca = PublicKey.parseString(await readFile(caPath + ".pub", "utf8"))
                const certificate = PublicKey.parseString(
                    await readFile(hostPath + "-cert.pub", "utf8"),
                )
                const hostKey = PrivateKey.fromString(await readFile(hostPath, "utf8"))
                server = new Server({
                    hostKeys: [hostKey],
                    hostCertificates: [certificate],
                    sendAllHostKeys: false,
                })
                server.hooker.hook("noneAuthentication", (_hook, _context, decision) => {
                    decision.allowLogin = true
                })
                server.listen({ host: "127.0.0.1", port: 0 })
                await new Promise<void>((resolve) => server!.server!.once("listening", resolve))

                let policyCalls = 0
                const serverPort = (server.server!.address() as AddressInfo).port
                client = new Client({
                    hostname: "127.0.0.1",
                    port: serverPort,
                    username: "host-certificate-test",
                    hostVerifier: KnownHosts.parse(
                        `@cert-authority [127.0.0.1]:${serverPort} ${ca.toString()}`,
                    ).verifier("127.0.0.1", serverPort),
                    authenticationMethodsOrder: [SSHAuthenticationMethods.None],
                })
                client.hooker.hook("hostKey", async (_hook, decision, key) => {
                    await Promise.resolve()
                    policyCalls++
                    const cert = key.data.algorithm
                    decision.allowHostKey =
                        cert instanceof SSHCertificatePublicKey &&
                        cert.data.signatureKey.equals(ca) &&
                        cert.data.principals.includes("127.0.0.1") &&
                        cert.data.criticalOptions.length === 0
                })
                await client.connect()

                expect(policyCalls).toBe(1)
                expect(client.negotiatedAlgorithms?.srvHostKey).toBe(
                    type === "rsa" ? "rsa-sha2-512-cert-v01@openssh.com" : certificate.data.alg,
                )
                expect(client.serverHostKey).toEqual(certificate.serialize())

                client.destroy()
                client = new Client({
                    hostname: "127.0.0.1",
                    port: (server.server!.address() as AddressInfo).port,
                    username: "plain-host-key-fallback",
                    algorithms: {
                        serverHostKey: [hostKey.data.publicKey.signatureAlgorithms[0]],
                    },
                    authenticationMethodsOrder: [SSHAuthenticationMethods.None],
                })
                client.hooker.hook("hostKey", (_hook, decision, key) => {
                    decision.allowHostKey = key.equals(hostKey.data.publicKey)
                })
                await client.connect()
                expect(client.serverHostKey).toEqual(hostKey.data.publicKey.serialize())
            } finally {
                client?.destroy()
                if (server) {
                    for (const connection of server.clients) connection.terminate()
                    if (server.server?.listening) {
                        await new Promise<void>((resolve, reject) => {
                            server!.server!.close((error) => (error ? reject(error) : resolve()))
                        })
                    }
                }
                await rm(directory, { recursive: true, force: true })
            }
        },
        15_000,
    )
})
