import { expect, test } from "bun:test"
import { once } from "node:events"
import Server from "../../src/Server.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

test("rejects a duplicate listen request while server startup is pending", async () => {
    const hostKey = await PrivateKey.generate("ssh-ed25519")
    const server = new Server({ hostKeys: [hostKey], sendAllHostKeys: false })
    server.listen({ host: "127.0.0.1", port: 0 })

    expect(() => server.listen({ host: "127.0.0.1", port: 0 })).toThrow(
        "SSH server is already starting or listening",
    )

    await once(server, "listening")
    expect(server.address()).not.toBeNull()
    await server.close()
})
