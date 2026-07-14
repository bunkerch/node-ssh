import { spawn } from "node:child_process"
import { access, mkdtemp, readFile, rm } from "node:fs/promises"
import { createServer } from "node:net"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { once } from "node:events"
import { AgentType } from "../../src/publickey/Agent.js"
import PageantAgent from "../../src/publickey/PageantAgent.js"
import { createSocketAgent } from "../../src/publickey/SocketAgent.js"

const requestIdentities = Buffer.from("000000010b", "hex")
const identitiesAnswer = Buffer.from(
    "000000470c00000001000000330000000b7373682d6564323535313900000020" +
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
        "0000000766697874757265",
    "hex",
)

describe("PageantAgent", () => {
    test.skipIf(process.platform === "win32")("rejects automatic discovery outside Windows", () => {
        expect(() => new PageantAgent()).toThrow(
            "Automatic Pageant discovery is only available on Windows",
        )
    })

    test("uses the standard agent protocol over an explicit socket", async () => {
        const directory = await mkdtemp(join(tmpdir(), "modernssh-pageant-agent-"))
        const socketPath =
            process.platform === "win32"
                ? String.raw`\\.\pipe\modernssh-pageant-test-${process.pid}-${Date.now()}`
                : join(directory, "agent.sock")
        const server = createServer((socket) => {
            socket.once("data", (request: Buffer) => {
                expect(request).toEqual(requestIdentities)
                socket.end(identitiesAnswer)
            })
        })
        server.listen(socketPath)
        await once(server, "listening")

        try {
            const agent = new PageantAgent(socketPath)
            expect(agent.type).toBe(AgentType.Interactive)
            expect(agent.socketPath).toBe(socketPath)
            const identities = await agent.getPublicKeys()
            expect(identities).toHaveLength(1)
            expect(identities[0][1].data.alg).toBe("ssh-ed25519")
            expect(identities[0][1].data.comment).toBe("fixture")
        } finally {
            await new Promise<void>((resolve, reject) => {
                server.close((error) => (error ? reject(error) : resolve()))
            })
            await rm(directory, { recursive: true, force: true })
        }
    })

    test.skipIf(process.platform !== "win32" || !process.env.PAGEANT_EXECUTABLE)(
        "discovers and communicates with a real Pageant process",
        async () => {
            const directory = await mkdtemp(join(tmpdir(), "modernssh-pageant-discovery-"))
            const configPath = join(directory, "pageant.conf")
            const pageant = spawn(
                process.env.PAGEANT_EXECUTABLE!,
                ["--openssh-config", configPath],
                { stdio: "ignore" },
            )

            try {
                for (let attempt = 0; attempt < 200; attempt++) {
                    try {
                        await access(configPath)
                        break
                    } catch {
                        await new Promise<void>((resolve) => setTimeout(resolve, 25))
                    }
                }
                await access(configPath)
                const config = await readFile(configPath, "utf8")
                const match = /^IdentityAgent "(.+)"\r?\n$/u.exec(config)
                expect(match).not.toBeNull()

                const agent = new PageantAgent()
                expect(agent.socketPath.replaceAll("\\", "/")).toBe(match![1])
                expect(createSocketAgent("pageant")).toBeInstanceOf(PageantAgent)
                expect(await agent.getPublicKeys()).toEqual([])
            } finally {
                if (pageant.exitCode === null && pageant.signalCode === null) {
                    pageant.kill()
                    await once(pageant, "close")
                }
                await rm(directory, { recursive: true, force: true })
            }
        },
        15_000,
    )
})
