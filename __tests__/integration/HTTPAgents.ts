import { execFile } from "node:child_process"
import { once } from "node:events"
import { mkdtemp, readFile, rm } from "node:fs/promises"
import { createServer as createHTTPServer } from "node:http"
import { createServer as createHTTPSServer } from "node:https"
import { AddressInfo, createConnection, type Server as NetServer } from "node:net"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { PassThrough, type Duplex } from "node:stream"
import { promisify } from "node:util"
import { SSHHTTPAgent } from "../../src/HTTPAgents.js"
import DirectTCPIPChannel from "../../src/channels/DirectTCPIPChannel.js"
import Server from "../../src/Server.js"
import { SSHAuthenticationMethods } from "../../src/constants.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

const execFileAsync = promisify(execFile)

function listen(server: NetServer): Promise<void> {
    return new Promise((resolve) => {
        server.once("listening", resolve)
        server.listen(0, "127.0.0.1")
    })
}

function close(server: NetServer): Promise<void> {
    return new Promise((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()))
    })
}

describe("SSH-backed HTTP agents", () => {
    test("rejects a single preconnected transport that cannot be pooled", () => {
        const transport = new PassThrough()
        try {
            expect(() => new SSHHTTPAgent({ sock: transport })).toThrow(
                "SSH HTTP agents cannot reuse an already-connected transport",
            )
        } finally {
            transport.destroy()
        }
    })

    test("owns credentials and multiplexes HTTP channels over a recoverable connection", async () => {
        const destination = createHTTPServer((request, response) => {
            if (request.url === "/idle") return
            response.setHeader("content-type", "text/plain")
            response.end(`${request.method} ${request.url} via ${request.headers.host}`)
        })
        await listen(destination)
        const destinationPort = (destination.address() as AddressInfo).port

        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const userKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({ hostKeys: [hostKey], sendAllHostKeys: false })
        const forwarded: DirectTCPIPChannel[] = []
        const errors: Error[] = []
        const authenticatedUsernames: string[] = []
        server.hooker.hook("publicKeyAuthentication", (_hook, context, decision) => {
            authenticatedUsernames.push(context.username)
            if (
                context.username !== "interop" ||
                !context.publicKey.equals(userKey.data.publicKey)
            ) {
                return
            }
            if (!context.signature) {
                decision.requestSignature = true
                return
            }
            decision.allowLogin = context.publicKey.verifySignature(
                context.signatureMessage,
                context.signature,
            )
        })
        server.hooker.hook("channelOpenRequest", (_hook, channel, decision) => {
            decision.allowOpen =
                channel instanceof DirectTCPIPChannel &&
                channel.details.destinationHost === "127.0.0.1" &&
                channel.details.destinationPort === destinationPort
        })
        server.on("connection", (connection) => {
            connection.on("error", (error) => errors.push(error))
            connection.on("channel", (channel) => {
                if (!(channel instanceof DirectTCPIPChannel)) return
                forwarded.push(channel)
                const socket = createConnection({
                    host: channel.details.destinationHost,
                    port: channel.details.destinationPort,
                })
                socket.on("error", (error) => channel.stream.destroy(error))
                channel.stream.pipe(socket).pipe(channel.stream)
            })
        })
        server.listen({ host: "127.0.0.1", port: 0 })
        await new Promise<void>((resolve) => server.server!.once("listening", resolve))
        const sshPort = (server.server!.address() as AddressInfo).port
        const authenticationMethodsOrder = [SSHAuthenticationMethods.PublicKey]
        const authenticationSignatureAlgorithms = ["ssh-ed25519"]
        const encodedUserKey = userKey.serialize()
        const encodedUserKeyBase64 = encodedUserKey.toString("base64")
        const clientOptions = {
            hostname: "127.0.0.1",
            port: sshPort,
            username: "interop",
            privateKey: encodedUserKey,
            authenticationMethodsOrder,
            authenticationSignatureAlgorithms,
        }
        const agent = new SSHHTTPAgent(clientOptions, {
            sourceHost: "agent.example",
            sourcePort: 42_424,
        })
        clientOptions.username = "mutated"
        authenticationMethodsOrder[0] = SSHAuthenticationMethods.Password
        authenticationSignatureAlgorithms[0] = "ssh-rsa"
        encodedUserKey.fill(0)

        try {
            const createAgentSocket = () =>
                new Promise<Duplex>((resolve, reject) => {
                    agent.createConnection(
                        { host: "127.0.0.1", port: destinationPort },
                        (error, stream) => (error || !stream ? reject(error) : resolve(stream)),
                    )
                })
            const [socket, secondSocket] = await Promise.all([
                createAgentSocket(),
                createAgentSocket(),
            ])
            expect(server.clients.size).toBe(1)
            expect(forwarded).toHaveLength(2)
            const response = new Promise<string>((resolve, reject) => {
                const chunks: Buffer[] = []
                socket.on("data", (chunk: Buffer) => chunks.push(chunk))
                socket.on("end", () => resolve(Buffer.concat(chunks).toString()))
                socket.on("error", reject)
            })
            socket.write(
                `GET /health?full=1 HTTP/1.1\r\nHost: 127.0.0.1:${destinationPort}\r\nConnection: close\r\n\r\n`,
            )
            const rawResponse = await response

            expect(rawResponse).toContain("HTTP/1.1 200 OK")
            expect(rawResponse).toEndWith(`GET /health?full=1 via 127.0.0.1:${destinationPort}`)
            expect(authenticatedUsernames.length).toBeGreaterThan(0)
            expect(new Set(authenticatedUsernames)).toEqual(new Set(["interop"]))
            expect(forwarded[0]?.details).toEqual({
                destinationHost: "127.0.0.1",
                destinationPort,
                sourceHost: "agent.example",
                sourcePort: 42_424,
            })
            expect(errors).toEqual([])

            let timeouts = 0
            socket.setTimeout(20, () => timeouts++)
            await once(socket, "timeout")
            expect(timeouts).toBe(1)
            expect(socket.destroyed).toBe(false)
            socket.setTimeout(0)
            await new Promise<void>((resolve) => setTimeout(resolve, 40))
            expect(timeouts).toBe(1)
            expect(() => socket.setTimeout(-1)).toThrow("non-negative")

            const timeoutScript = String.raw`
                import { get } from "node:http"
                import {
                    SSHHTTPAgent,
                    SSHAuthenticationMethods,
                } from "./dist/index.js"

                const agent = new SSHHTTPAgent({
                    hostname: "127.0.0.1",
                    port: ${sshPort},
                    username: "interop",
                    privateKey: Buffer.from("${encodedUserKeyBase64}", "base64"),
                    authenticationMethodsOrder: [SSHAuthenticationMethods.PublicKey],
                })
                try {
                    const timedOut = await new Promise((resolve, reject) => {
                        let timeoutObserved = false
                        const request = get({
                            hostname: "127.0.0.1",
                            port: ${destinationPort},
                            path: "/idle",
                            agent,
                        })
                        request.once("error", (error) => {
                            if (!timeoutObserved) reject(error)
                        })
                        request.setTimeout(20, () => {
                            timeoutObserved = true
                            request.destroy()
                            resolve(true)
                        })
                    })
                    process.stdout.write(JSON.stringify({ timedOut }))
                } finally {
                    agent.destroy()
                }
            `
            const timeoutProcess = await execFileAsync("node", [
                "--input-type=module",
                "--eval",
                timeoutScript,
            ])
            expect(timeoutProcess.stderr).toBe("")
            expect(JSON.parse(timeoutProcess.stdout)).toEqual({ timedOut: true })

            let callbacks = 0
            await new Promise<void>((resolve) => {
                agent.createConnection({ host: "127.0.0.1", port: 0 }, (error) => {
                    callbacks++
                    expect(error).toBeInstanceOf(RangeError)
                    resolve()
                })
            })
            await new Promise<void>((resolve) => queueMicrotask(resolve))
            expect(callbacks).toBe(1)

            secondSocket.on("error", () => undefined)
            const secondSocketClosed = new Promise<void>((resolve) =>
                secondSocket.once("close", resolve),
            )
            const activeConnection = [...server.clients][0]
            expect(activeConnection).toBeDefined()
            activeConnection!.terminate()
            await secondSocketClosed
            const recoveredSocket = await createAgentSocket()

            recoveredSocket.on("error", () => undefined)
            const recoveredSocketClosed = new Promise<void>((resolve) =>
                recoveredSocket.once("close", resolve),
            )
            agent.destroy()
            await recoveredSocketClosed
            const replacementSocket = await createAgentSocket()
            replacementSocket.destroy()
        } finally {
            agent.destroy()
            for (const client of server.clients) client.terminate()
            await close(server.server!)
            await close(destination)
        }
    })

    test("performs an HTTPS request with TLS above the SSH channel", async () => {
        const directory = await mkdtemp(join(tmpdir(), "modernssh-https-agent-"))
        const keyPath = join(directory, "key.pem")
        const certificatePath = join(directory, "certificate.pem")
        await execFileAsync("openssl", [
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            "/CN=127.0.0.1",
            "-addext",
            "subjectAltName=IP:127.0.0.1",
            "-days",
            "1",
            "-keyout",
            keyPath,
            "-out",
            certificatePath,
        ])
        const destination = createHTTPSServer(
            {
                key: await readFile(keyPath),
                cert: await readFile(certificatePath),
            },
            (request, response) => {
                response.end(`secure ${request.method} ${request.url}`)
            },
        )
        await listen(destination)
        const destinationPort = (destination.address() as AddressInfo).port

        const server = new Server({
            hostKeys: [await PrivateKey.generate("ssh-ed25519")],
            sendAllHostKeys: false,
        })
        const forwarded: DirectTCPIPChannel[] = []
        const errors: Error[] = []
        server.hooker.hook("noneAuthentication", (_hook, _context, decision) => {
            decision.allowLogin = true
        })
        server.hooker.hook("channelOpenRequest", (_hook, channel, decision) => {
            decision.allowOpen =
                channel instanceof DirectTCPIPChannel &&
                channel.details.destinationHost === "127.0.0.1" &&
                channel.details.destinationPort === destinationPort
        })
        server.on("connection", (connection) => {
            connection.on("error", (error) => errors.push(error))
            connection.on("channel", (channel) => {
                if (!(channel instanceof DirectTCPIPChannel)) return
                forwarded.push(channel)
                const socket = createConnection({
                    host: channel.details.destinationHost,
                    port: channel.details.destinationPort,
                })
                socket.on("error", (error) => channel.stream.destroy(error))
                channel.stream.pipe(socket).pipe(channel.stream)
            })
        })
        server.listen({ host: "127.0.0.1", port: 0 })
        await once(server, "listening")
        const sshPort = (server.address() as AddressInfo).port

        try {
            const script = String.raw`
                import { get } from "node:https"
                import { SSHHTTPSAgent, SSHAuthenticationMethods } from "./dist/index.js"

                const agent = new SSHHTTPSAgent({
                    hostname: "127.0.0.1",
                    port: ${sshPort},
                    username: "secure-agent",
                    authenticationMethodsOrder: [SSHAuthenticationMethods.None],
                })
                try {
                    const result = await new Promise((resolve, reject) => {
                        const request = get({
                            hostname: "127.0.0.1",
                            port: ${destinationPort},
                            path: "/private?ready=1",
                            agent,
                            rejectUnauthorized: false,
                        }, (response) => {
                            const chunks = []
                            response.on("data", (chunk) => chunks.push(chunk))
                            response.on("end", () => resolve({
                                statusCode: response.statusCode ?? 0,
                                body: Buffer.concat(chunks).toString(),
                            }))
                        })
                        request.on("error", reject)
                    })
                    process.stdout.write(JSON.stringify(result))
                } finally {
                    agent.destroy()
                }
            `
            const { stdout, stderr } = await execFileAsync("node", [
                "--input-type=module",
                "--eval",
                script,
            ])
            const result = JSON.parse(stdout) as { statusCode: number; body: string }

            expect(stderr).toBe("")
            expect(result).toEqual({
                statusCode: 200,
                body: "secure GET /private?ready=1",
            })
            expect(forwarded).toHaveLength(1)
            expect(forwarded[0]?.details).toEqual({
                destinationHost: "127.0.0.1",
                destinationPort,
                sourceHost: "127.0.0.1",
                sourcePort: 0,
            })
            expect(errors).toEqual([])
        } finally {
            for (const client of server.clients) client.terminate()
            await close(server.server!)
            await close(destination)
            await rm(directory, { recursive: true, force: true })
        }
    }, 15_000)
})
