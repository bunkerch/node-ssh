import { execFile } from "node:child_process"
import { promisify } from "node:util"

const execFileAsync = promisify(execFile)

test("a server applies its configured high-water mark to accepted TCP transports", async () => {
    const script = String.raw`
        import { once } from "node:events"
        import net from "node:net"
        import { PrivateKey, Server } from "./dist/index.js"

        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({ hostKeys: [hostKey], highWaterMark: 12_345 })
        server.listen({ host: "127.0.0.1", port: 0 })
        await once(server, "listening")

        const acceptedPromise = once(server.server, "connection")
        const transport = net.connect({
            host: "127.0.0.1",
            port: server.address().port,
        })
        const [accepted] = await acceptedPromise
        const result = {
            readable: accepted.readableHighWaterMark,
            writable: accepted.writableHighWaterMark,
        }

        const transportClosed = once(transport, "close")
        transport.destroy()
        accepted.destroy()
        await transportClosed
        await server.close()
        process.stdout.write(JSON.stringify(result))
    `
    const { stdout, stderr } = await execFileAsync("node", [
        "--input-type=module",
        "--eval",
        script,
    ])

    expect(stderr).toBe("")
    expect(JSON.parse(stdout)).toEqual({ readable: 12_345, writable: 12_345 })
})
