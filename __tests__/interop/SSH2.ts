import { AddressInfo } from "node:net"
import { Client as SSH2Client, Server as SSH2Server, type Algorithms } from "ssh2"
import Client from "../../src/Client.js"
import Server from "../../src/Server.js"
import PrivateKey from "../../src/utils/PrivateKey.js"
import { DEFAULT_CHANNEL_WINDOW_SIZE } from "../../src/channels/ClientChannel.js"

const algorithms: Algorithms = {
    kex: ["diffie-hellman-group14-sha256"],
    cipher: ["aes128-ctr"],
    serverHostKey: ["ssh-ed25519"],
    hmac: ["hmac-sha2-256"],
    compress: ["none"],
}

describe("ssh2 interoperability", () => {
    test("modernssh client authenticates with an ssh2 server", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const serverErrors: Error[] = []
        let serverReady = false
        let command = ""
        const expectedStdout = Buffer.alloc(DEFAULT_CHANNEL_WINDOW_SIZE + 65_536, "o")
        const server = new SSH2Server({ hostKeys: [hostKey.toString()], algorithms })
        server.on("error", (error) => serverErrors.push(error))
        server.on("connection", (connection) => {
            connection.on("error", (error) => serverErrors.push(error))
            connection.on("authentication", (context) => {
                if (context.method === "none" && context.username === "interop") {
                    context.accept()
                } else {
                    context.reject()
                }
            })
            connection.on("ready", () => {
                serverReady = true
            })
            connection.on("session", (accept) => {
                const session = accept()
                session.on("exec", (acceptExec, _reject, info) => {
                    command = info.command
                    const stream = acceptExec()
                    stream.stderr.write("diagnostic output")
                    stream.write(expectedStdout, () => {
                        stream.exit(7)
                        stream.end()
                    })
                })
            })
        })
        server.listen(0, "127.0.0.1")
        await new Promise<void>((resolve) => server.once("listening", resolve))

        const address = server.address() as AddressInfo
        const client = new Client({
            hostname: "127.0.0.1",
            port: address.port,
            username: "interop",
        })
        const clientErrors: Error[] = []
        client.on("error", (error) => clientErrors.push(error))
        client.hooker.hook("hostKey", (_hook, decision) => {
            decision.allowHostKey = true
        })

        try {
            await client.connect()
            const channel = await client.exec("produce-output")
            const stdout: Buffer[] = []
            const stderr: Buffer[] = []
            channel.on("data", (data: Buffer) => stdout.push(data))
            channel.stderr.on("data", (data: Buffer) => stderr.push(data))
            const exit = new Promise<number>((resolve) => channel.once("exit", resolve))
            await new Promise<void>((resolve) => channel.once("close", resolve))

            expect(client.hasAuthenticated).toBe(true)
            expect(serverReady).toBe(true)
            expect(command).toBe("produce-output")
            expect(Buffer.concat(stdout)).toEqual(expectedStdout)
            expect(Buffer.concat(stderr).toString()).toBe("diagnostic output")
            expect(await exit).toBe(7)
            expect(clientErrors).toEqual([])
            expect(serverErrors).toEqual([])
        } finally {
            const closed = new Promise<void>((resolve) => client.once("close", resolve))
            client.end()
            await closed
            await new Promise<void>((resolve, reject) => {
                server.close((error) => (error ? reject(error) : resolve()))
            })
        }
    }, 15_000)

    test("ssh2 client authenticates with a modernssh server", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({ hostKeys: [hostKey], sendAllHostKeys: false })
        const serverErrors: Error[] = []
        let serverReady = false
        server.hooker.hook("noneAuthentication", (_hook, context, decision) => {
            decision.allowLogin = context.username === "interop"
        })
        server.on("connection", (connection) => {
            connection.on("error", (error) => serverErrors.push(error))
            connection.on("connect", () => {
                serverReady = true
            })
        })
        server.listen({ host: "127.0.0.1", port: 0 })
        await new Promise<void>((resolve) => server.server!.once("listening", resolve))

        const address = server.server!.address() as AddressInfo
        const client = new SSH2Client()
        const clientErrors: Error[] = []
        client.on("error", (error) => clientErrors.push(error))

        try {
            client.connect({
                host: "127.0.0.1",
                port: address.port,
                username: "interop",
                authHandler: ["none"],
                algorithms,
                hostVerifier: () => true,
                readyTimeout: 10_000,
            })
            await new Promise<void>((resolve) => client.once("ready", resolve))
            await new Promise<void>((resolve) => setImmediate(resolve))

            expect(serverReady).toBe(true)
            expect(clientErrors).toEqual([])
            expect(serverErrors).toEqual([])
        } finally {
            const closed = new Promise<void>((resolve) => client.once("close", resolve))
            client.end()
            await closed
            await new Promise<void>((resolve, reject) => {
                server.server!.close((error) => (error ? reject(error) : resolve()))
            })
        }
    }, 15_000)
})
