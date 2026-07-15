import { once } from "node:events"
import type { AddressInfo } from "node:net"

import Client from "../../src/Client.js"
import Server, { type ServerOptions } from "../../src/Server.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

describe("RFC 4252 authentication banners", () => {
    test("rejects invalid banner text and language during server construction", () => {
        const hostKeys = [PrivateKey.generateSync("ssh-ed25519")]
        expect(() => new Server({ hostKeys, banner: "\ud800" })).toThrow(
            "SSH authentication banner is not valid UTF-8 text",
        )

        const options: ServerOptions = {
            hostKeys,
            banner: "Authorized access only",
            bannerLanguageTag: "en_XX",
        }
        expect(() => new Server(options)).toThrow(
            "SSH authentication banner language tag is not valid RFC 3066",
        )
        expect(() => new Server({ hostKeys, bannerLanguageTag: "en" })).toThrow(
            "SSH authentication banner language tag requires a banner",
        )
        expect(() => new Server({ hostKeys, banner: 42 as unknown as string })).toThrow(
            "SSH authentication banner must be a string",
        )
        expect(
            () =>
                new Server({
                    hostKeys,
                    banner: "notice",
                    bannerLanguageTag: 42 as unknown as string,
                }),
        ).toThrow("SSH authentication banner language tag must be a string")
    })

    test("delivers the owned banner text and language before authentication", async () => {
        const options = {
            hostKeys: [PrivateKey.generateSync("ssh-ed25519")],
            sendAllHostKeys: false,
            banner: "Authorized access only\r\n",
            bannerLanguageTag: "en-US",
        }
        const server = new Server(options)
        options.banner = "Changed after construction"
        options.bannerLanguageTag = "fr"
        server.hooker.hook("noneAuthentication", (_hook, _context, decision) => {
            decision.allowLogin = true
        })
        server.listen({ host: "127.0.0.1", port: 0 })
        await once(server, "listening")

        const client = new Client({
            hostname: "127.0.0.1",
            port: (server.address() as AddressInfo).port,
            username: "banner-test",
        })
        const banners: [message: string, languageTag: string][] = []
        client.on("banner", (message, languageTag) => banners.push([message, languageTag]))
        client.hooker.hook("hostKey", (_hook, decision) => {
            decision.allowHostKey = true
        })

        try {
            await client.connect()
            expect(banners).toEqual([["Authorized access only\r\n", "en-US"]])
        } finally {
            client.destroy()
            for (const connection of server.clients) connection.terminate()
            await server.close()
        }
    })
})
