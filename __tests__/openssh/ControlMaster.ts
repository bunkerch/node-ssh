import { execFile } from "node:child_process"
import { mkdtemp, rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { promisify } from "node:util"
import type Client from "../../src/Client.js"
import ControlMaster from "../../src/control/ControlMaster.js"
import { ControlMultiplexMessageType } from "../../src/control/ControlMultiplexCodec.js"

const execFileAsync = promisify(execFile)

function connectedClient(onEnd: () => void = () => undefined): Client {
    return {
        isConnected: true,
        end() {
            onEnd()
            return this
        },
    } as unknown as Client
}

describe("OpenSSH ControlMaster interoperability", () => {
    test("answers health checks and stops accepting clients through awaited policy", async () => {
        const directory = await mkdtemp(join(tmpdir(), "modernssh-mux-"))
        const path = join(directory, "control")
        const master = new ControlMaster(connectedClient(), { path })
        const errors: Error[] = []
        master.on("clientError", (error) => errors.push(error))
        master.hooker.hook("request", async (_hook, request, decision) => {
            await Promise.resolve()
            decision.allow = request.type === ControlMultiplexMessageType.StopListening
        })

        try {
            await master.listen()
            const check = await execFileAsync("ssh", ["-S", path, "-O", "check", "unused"])
            expect(`${check.stdout}${check.stderr}`).toContain(`pid=${process.pid}`)

            await execFileAsync("ssh", ["-S", path, "-O", "stop", "unused"])
            await expect(
                execFileAsync("ssh", ["-S", path, "-O", "check", "unused"]),
            ).rejects.toThrow()
            expect(master.isListening).toBe(false)
            expect(errors).toEqual([])
        } finally {
            await master.close()
            await rm(directory, { recursive: true, force: true })
        }
    }, 15_000)

    test("denies termination by default and ends the owned connection when allowed", async () => {
        const directory = await mkdtemp(join(tmpdir(), "modernssh-mux-"))
        const path = join(directory, "control")
        let ended = false
        const master = new ControlMaster(
            connectedClient(() => {
                ended = true
            }),
            { path },
        )
        const errors: Error[] = []
        master.on("clientError", (error) => errors.push(error))

        try {
            await master.listen()
            await expect(
                execFileAsync("ssh", ["-S", path, "-O", "exit", "unused"]),
            ).rejects.toThrow()
            expect(ended).toBe(false)

            master.hooker.hook("request", (_hook, request, decision) => {
                decision.allow = request.type === ControlMultiplexMessageType.Terminate
            })
            await execFileAsync("ssh", ["-S", path, "-O", "exit", "unused"])
            expect(ended).toBe(true)
            expect(errors).toEqual([])
        } finally {
            await master.close()
            await rm(directory, { recursive: true, force: true })
        }
    }, 15_000)
})
