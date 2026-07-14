import Client from "../../src/Client.js"
import Server from "../../src/Server.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

describe("configured diagnostic sinks", () => {
    test("receives the client debug event arguments with options redacted", async () => {
        const configured: unknown[][] = []
        const emitted: unknown[][] = []
        const client = new Client({
            username: "diagnostic-user",
            password: "diagnostic-secret",
            debug: (...message) => configured.push(message),
        })
        client.on("debug", (...message) => emitted.push(message))

        await new Promise<void>((resolve) => setImmediate(resolve))

        expect(configured).toEqual(emitted)
        expect(configured[0]?.[0]).toBe("Client created with options:")
        const output = JSON.stringify(configured)
        expect(output).toContain("<redacted>")
        expect(output).toContain("<configured>")
        expect(output).not.toContain("diagnostic-secret")
    })

    test("receives the same server diagnostic arguments", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const configured: unknown[][] = []
        const emitted: unknown[][] = []
        const server = new Server({
            hostKeys: [hostKey],
            debug: (...message) => configured.push(message),
        })
        server.on("debug", (...message) => emitted.push(message))

        server.debug("server diagnostic", { ready: true })

        expect(configured).toEqual([["server diagnostic", { ready: true }]])
        expect(configured).toEqual(emitted)
    })

    test("rejects non-callable diagnostic options", () => {
        expect(() => new Client({ debug: "invalid" as never })).toThrow("must be a function")
        expect(() => new Server({ debug: "invalid" as never })).toThrow("must be a function")
    })
})
