import { once } from "node:events"
import { mkdtemp, rm, writeFile } from "node:fs/promises"
import { AddressInfo, createServer, type Socket } from "node:net"
import { tmpdir } from "node:os"
import { join } from "node:path"

import CygwinAgent from "../../src/publickey/CygwinAgent.js"
import { SSHAgentProtocolServer } from "../../src/publickey/SSHAgentProtocol.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

const descriptorSecret = "7B499653-622A1EB9-83E6B83E-A4E8D0C1"
const wireSecret = Buffer.from("5396497bb91e2a623eb8e683c1d0e8a4", "hex")
const discoveredCredentials = Buffer.from("6f000000de0000004d010000", "hex")
const finalPeerCredentials = Buffer.from("bc0100002b0200009a020000", "hex")

async function readExactly(socket: Socket, length: number): Promise<Buffer> {
    const result = Buffer.alloc(length)
    let offset = 0
    while (offset < length) {
        const chunk = socket.read(length - offset) as Buffer | null
        if (chunk) {
            chunk.copy(result, offset)
            offset += chunk.length
            continue
        }
        await once(socket, "readable")
    }
    return result
}

function writeFragmented(socket: Socket, data: Buffer): void {
    socket.write(data.subarray(0, 1))
    socket.write(data.subarray(1, 7))
    socket.write(data.subarray(7))
}

async function closeServer(server: ReturnType<typeof createServer>): Promise<void> {
    await new Promise<void>((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()))
    })
}

describe("Cygwin agent transport", () => {
    test("negotiates fixed fragmented secrets and credentials before agent requests", async () => {
        const directory = await mkdtemp(join(tmpdir(), "modernssh-cygwin-agent-"))
        const descriptorPath = join(directory, "agent.socket")
        const identity = PrivateKey.generateSync("ssh-ed25519")
        const protocolServer = new SSHAgentProtocolServer()
        protocolServer.hooker.hook("identities", (_hook, decision) => {
            decision.identities = [
                { publicKey: identity.data.publicKey, comment: "cygwin-fixture" },
            ]
        })
        protocolServer.hooker.hook("sign", (_hook, context, decision) => {
            decision.signature = identity.sign(context.data, context.algorithm)
        })
        const server = createServer()
        const tasks: Promise<void>[] = []
        const sockets = new Set<Socket>()
        const credentials: Buffer[] = []
        let connectionIndex = 0
        let fixtureError: Error | undefined
        server.on("connection", (socket) => {
            sockets.add(socket)
            socket.once("close", () => sockets.delete(socket))
            const index = connectionIndex++
            const task = (async () => {
                expect(await readExactly(socket, 16)).toEqual(wireSecret)
                writeFragmented(socket, wireSecret)
                credentials.push(await readExactly(socket, 12))
                writeFragmented(
                    socket,
                    index % 2 === 0 ? discoveredCredentials : finalPeerCredentials,
                )
                if (index % 2 === 1) await protocolServer.serve(socket)
            })()
            tasks.push(task)
            void task.catch((error: Error) => {
                fixtureError = error
                socket.destroy()
            })
        })
        server.listen(0, "127.0.0.1")
        await once(server, "listening")
        const port = (server.address() as AddressInfo).port
        await writeFile(
            descriptorPath,
            `!<socket >${String(port)} s ${descriptorSecret}\0`,
            "ascii",
        )

        try {
            const agent = new CygwinAgent(descriptorPath)
            const identities = await agent.getPublicKeys()
            expect(identities).toHaveLength(1)
            expect(identities[0][1].data.comment).toBe("cygwin-fixture")
            const message = Buffer.from("signed through a Cygwin agent transport")
            const signature = await agent.sign(identities[0][0], message)
            expect(identities[0][1].verifySignature(message, signature)).toBeTrue()
            expect(connectionIndex).toBe(4)
            const expectedCredentials = Buffer.from(discoveredCredentials)
            expectedCredentials.writeUInt32LE(process.pid, 0)
            expect(credentials).toEqual([
                Buffer.alloc(12),
                expectedCredentials,
                Buffer.alloc(12),
                expectedCredentials,
            ])
        } finally {
            for (const socket of sockets) socket.destroy()
            await closeServer(server)
            await Promise.all(tasks)
            await rm(directory, { recursive: true, force: true })
        }
        expect(fixtureError).toBeUndefined()
    })

    test("rejects malformed and oversized socket descriptor files before connecting", async () => {
        const directory = await mkdtemp(join(tmpdir(), "modernssh-cygwin-descriptor-"))
        const descriptorPath = join(directory, "agent.socket")
        try {
            await writeFile(descriptorPath, "not a socket", "ascii")
            await expect(new CygwinAgent(descriptorPath).getStream()).rejects.toThrow(
                "Malformed Cygwin agent socket descriptor",
            )
            await writeFile(descriptorPath, Buffer.alloc(33, 0x41))
            await expect(
                new CygwinAgent(descriptorPath, { maxSocketFileLength: 32 }).getStream(),
            ).rejects.toThrow("invalid length")
            await writeFile(descriptorPath, Buffer.from([0xff]))
            await expect(new CygwinAgent(descriptorPath).getStream()).rejects.toThrow("only ASCII")
        } finally {
            await rm(directory, { recursive: true, force: true })
        }
    })

    test("rejects a mismatched secret without opening the credentialed connection", async () => {
        const directory = await mkdtemp(join(tmpdir(), "modernssh-cygwin-secret-"))
        const descriptorPath = join(directory, "agent.socket")
        let connections = 0
        const sockets = new Set<Socket>()
        const server = createServer((socket) => {
            connections++
            sockets.add(socket)
            socket.once("close", () => sockets.delete(socket))
            void readExactly(socket, 16).then(() => socket.end(Buffer.alloc(16, 0xaa)))
        })
        server.listen(0, "127.0.0.1")
        await once(server, "listening")
        const port = (server.address() as AddressInfo).port
        await writeFile(descriptorPath, `!<socket >${String(port)} s ${descriptorSecret}`, "ascii")

        try {
            await expect(new CygwinAgent(descriptorPath).getStream()).rejects.toThrow(
                "wrong socket secret",
            )
            expect(connections).toBe(1)
        } finally {
            for (const socket of sockets) socket.destroy()
            await closeServer(server)
            await rm(directory, { recursive: true, force: true })
        }
    })

    test("times out and destroys a silent handshake peer", async () => {
        const directory = await mkdtemp(join(tmpdir(), "modernssh-cygwin-timeout-"))
        const descriptorPath = join(directory, "agent.socket")
        let accepted: Socket | undefined
        let closePeer: (() => void) | undefined
        const closed = new Promise<void>((resolve) => {
            closePeer = resolve
        })
        const server = createServer((socket) => {
            accepted = socket
            socket.once("close", () => closePeer?.())
        })
        server.listen(0, "127.0.0.1")
        await once(server, "listening")
        const port = (server.address() as AddressInfo).port
        await writeFile(descriptorPath, `!<socket >${String(port)} s ${descriptorSecret}`, "ascii")

        try {
            await expect(
                new CygwinAgent(descriptorPath, { handshakeTimeout: 20 }).getStream(),
            ).rejects.toThrow("timed out")
            await closed
            expect(accepted?.destroyed).toBeTrue()
        } finally {
            accepted?.destroy()
            await closeServer(server)
            await rm(directory, { recursive: true, force: true })
        }
    })

    test("validates public transport options", () => {
        expect(() => new CygwinAgent("socket", { handshakeTimeout: 0.5 })).toThrow(
            "integer between zero and 2147483647",
        )
        expect(() => new CygwinAgent("socket", { maxSocketFileLength: 0 })).toThrow(
            "integer between one and 1048576",
        )
        expect(() => new CygwinAgent("")).toThrow("non-empty string")
    })
})
