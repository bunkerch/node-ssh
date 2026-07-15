import { describe, expect, test } from "bun:test"
import { Duplex } from "node:stream"
import type ClientSessionChannel from "../../src/channels/ClientSessionChannel.js"
import PublicKeySubsystemClient, {
    PublicKeySubsystemStatusError,
} from "../../src/publickey/PublicKeySubsystemClient.js"
import {
    decodePublicKeySubsystemPacket,
    encodePublicKeySubsystemPacket,
    MAX_PUBLIC_KEY_SUBSYSTEM_RESPONSES,
    type PublicKeySubsystemPacket,
    PublicKeySubsystemStatusCode,
} from "../../src/publickey/PublicKeySubsystemCodec.js"
import PublicKey from "../../src/utils/PublicKey.js"

const RFC_8709_KEY = Buffer.from(
    "0000000b7373682d6564323535313900000020" +
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "hex",
)

class PublicKeySubsystemServerFixture extends Duplex {
    constructor(private readonly receivePacket: (packet: PublicKeySubsystemPacket) => void) {
        super()
    }

    _read(): void {
        void this.readable
    }

    _write(
        chunk: Buffer,
        _encoding: BufferEncoding,
        callback: (error?: Error | null) => void,
    ): void {
        try {
            this.receivePacket(decodePublicKeySubsystemPacket(chunk))
            callback()
        } catch (error) {
            callback(error instanceof Error ? error : new Error(String(error)))
        }
    }

    send(packet: PublicKeySubsystemPacket): void {
        this.push(encodePublicKeySubsystemPacket(packet))
    }
}

class BlockedPublicKeySubsystemChannel extends Duplex {
    _read(): void {
        void this.readable
    }

    _write(
        _chunk: Buffer,
        _encoding: BufferEncoding,
        callback: (error?: Error | null) => void,
    ): void {
        void callback
    }

    _destroy(_error: Error | null, callback: (error?: Error | null) => void): void {
        callback()
    }
}

function asClientChannel(channel: Duplex): ClientSessionChannel {
    return channel as unknown as ClientSessionChannel
}

describe("RFC 4819 public-key subsystem client", () => {
    test("validates a finite positive request timeout before initialization", async () => {
        for (const requestTimeout of [null, 0, -1, Number.NaN, Number.POSITIVE_INFINITY]) {
            const fixture = new PublicKeySubsystemServerFixture(() => undefined)
            await expect(
                PublicKeySubsystemClient.connect(asClientChannel(fixture), {
                    requestTimeout: requestTimeout as number,
                }),
            ).rejects.toThrow("Public-key subsystem request timeout must be a positive number")
            fixture.destroy()
        }
        const fixture = new PublicKeySubsystemServerFixture(() => undefined)
        await expect(
            PublicKeySubsystemClient.connect(asClientChannel(fixture), null as never),
        ).rejects.toThrow("Public-key subsystem client options must be an object")
        fixture.destroy()
    })

    test("closes a session that does not answer initialization", async () => {
        const fixture = new PublicKeySubsystemServerFixture(() => undefined)

        await expect(
            PublicKeySubsystemClient.connect(asClientChannel(fixture), { requestTimeout: 20 }),
        ).rejects.toThrow("Timed out waiting for public-key subsystem initialization")
        expect(fixture.destroyed).toBe(true)
    })

    test("bounds an initialization frame blocked by channel flow control", async () => {
        const channel = new BlockedPublicKeySubsystemChannel()

        await expect(
            PublicKeySubsystemClient.connect(asClientChannel(channel), { requestTimeout: 20 }),
        ).rejects.toThrow("Timed out waiting for public-key subsystem initialization")
        expect(channel.destroyed).toBe(true)
    })

    test("closes a session that does not acknowledge a request", async () => {
        const fixture = new PublicKeySubsystemServerFixture((packet) => {
            if (packet.type === "version") fixture.send({ type: "version", version: 2 })
        })
        const client = await PublicKeySubsystemClient.connect(asClientChannel(fixture), {
            requestTimeout: 20,
        })

        await expect(client.list()).rejects.toThrow(
            "Timed out waiting for public-key subsystem request reply",
        )
        expect(fixture.destroyed).toBe(true)
    })

    test("exchanges version 2 before exposing the client", async () => {
        const received: PublicKeySubsystemPacket[] = []
        const fixture = new PublicKeySubsystemServerFixture((packet) => {
            received.push(packet)
            if (packet.type === "version") fixture.send({ type: "version", version: 2 })
        })

        const client = await PublicKeySubsystemClient.connect(asClientChannel(fixture))
        expect(client.protocolVersion).toBe(2)
        expect(received).toEqual([{ type: "version", version: 2 }])
        fixture.destroy()
    })

    test("adds a key with copied attributes and waits for the status response", async () => {
        let addPacket: PublicKeySubsystemPacket | undefined
        const fixture = new PublicKeySubsystemServerFixture((packet) => {
            if (packet.type === "version") {
                fixture.send({ type: "version", version: 2 })
            } else if (packet.type === "add") {
                addPacket = packet
                queueMicrotask(() =>
                    fixture.send({
                        type: "status",
                        code: PublicKeySubsystemStatusCode.Success,
                        description: "",
                        languageTag: "",
                    }),
                )
            }
        })
        const client = await PublicKeySubsystemClient.connect(asClientChannel(fixture))
        const value = Buffer.from("laptop")
        const request = client.add(PublicKey.parse(RFC_8709_KEY), {
            overwrite: true,
            attributes: [{ name: "comment", value, critical: false }],
        })
        value.fill(0)
        await request

        expect(addPacket).toEqual({
            type: "add",
            algorithm: "ssh-ed25519",
            keyBlob: RFC_8709_KEY,
            overwrite: true,
            attributes: [{ name: "comment", value: Buffer.from("laptop"), critical: false }],
        })
        fixture.destroy()
    })

    test("rejects malformed add options before sending a request", async () => {
        let addRequests = 0
        const fixture = new PublicKeySubsystemServerFixture((packet) => {
            if (packet.type === "version") {
                fixture.send({ type: "version", version: 2 })
            } else if (packet.type === "add") {
                addRequests++
            }
        })
        const client = await PublicKeySubsystemClient.connect(asClientChannel(fixture))
        const key = PublicKey.parse(RFC_8709_KEY)
        const cases: readonly [unknown, string][] = [
            [null, "Public-key subsystem add options must be an object"],
            [{ overwrite: null }, "Public-key subsystem overwrite must be a boolean"],
            [{ attributes: null }, "Public-key subsystem attributes must be an array"],
            [{ attributes: [null] }, "Public-key subsystem attribute must be an object"],
            [
                { attributes: [{ name: "comment", value: "x", critical: null }] },
                "Public-key subsystem critical attribute flag must be a boolean",
            ],
        ]

        for (const [options, message] of cases) {
            await expect(client.add(key, options as never)).rejects.toThrow(message)
        }
        expect(addRequests).toBe(0)
        fixture.destroy()
    })

    test("removes a key and exposes the server status failure", async () => {
        let removePacket: PublicKeySubsystemPacket | undefined
        const fixture = new PublicKeySubsystemServerFixture((packet) => {
            if (packet.type === "version") {
                fixture.send({ type: "version", version: 2 })
            } else if (packet.type === "remove") {
                removePacket = packet
                fixture.send({
                    type: "status",
                    code: PublicKeySubsystemStatusCode.KeyNotFound,
                    description: "missing",
                    languageTag: "en",
                })
            }
        })
        const client = await PublicKeySubsystemClient.connect(asClientChannel(fixture))
        let received: unknown
        try {
            await client.remove(PublicKey.parse(RFC_8709_KEY))
        } catch (error) {
            received = error
        }

        expect(removePacket).toEqual({
            type: "remove",
            algorithm: "ssh-ed25519",
            keyBlob: RFC_8709_KEY,
        })
        expect(received).toBeInstanceOf(PublicKeySubsystemStatusError)
        expect(received).toMatchObject({
            code: PublicKeySubsystemStatusCode.KeyNotFound,
            message: "missing",
            languageTag: "en",
        })
        fixture.destroy()
    })

    test("collects listed keys until the final success status", async () => {
        const fixture = new PublicKeySubsystemServerFixture((packet) => {
            if (packet.type === "version") {
                fixture.send({ type: "version", version: 2 })
            } else if (packet.type === "list") {
                fixture.send({
                    type: "publickey",
                    algorithm: "ssh-ed25519",
                    keyBlob: RFC_8709_KEY,
                    attributes: [{ name: "comment", value: Buffer.from("workstation") }],
                })
                fixture.send({
                    type: "status",
                    code: PublicKeySubsystemStatusCode.Success,
                    description: "",
                    languageTag: "",
                })
            }
        })
        const client = await PublicKeySubsystemClient.connect(asClientChannel(fixture))
        const keys = await client.list()

        expect(keys).toHaveLength(1)
        expect(keys[0]!.key.equals(PublicKey.parse(RFC_8709_KEY))).toBe(true)
        expect(keys[0]!.attributes).toEqual([
            { name: "comment", value: Buffer.from("workstation") },
        ])
        fixture.destroy()
    })

    test("queues concurrent operations and lists server attributes", async () => {
        const requests: string[] = []
        const success = (): void => {
            fixture.send({
                type: "status",
                code: PublicKeySubsystemStatusCode.Success,
                description: "",
                languageTag: "",
            })
        }
        const fixture = new PublicKeySubsystemServerFixture((packet) => {
            if (packet.type === "version") {
                fixture.send({ type: "version", version: 2 })
            } else if (packet.type === "list") {
                requests.push(packet.type)
                queueMicrotask(success)
            } else if (packet.type === "listattributes") {
                requests.push(packet.type)
                fixture.send({ type: "attribute", name: "shell", compulsory: true })
                success()
            }
        })
        const client = await PublicKeySubsystemClient.connect(asClientChannel(fixture))
        const list = client.list()
        const attributes = client.listAttributes()

        expect(await list).toEqual([])
        expect(await attributes).toEqual([{ name: "shell", compulsory: true }])
        expect(requests).toEqual(["list", "listattributes"])
        fixture.destroy()
    })

    test("reports an unsupported negotiated version before closing", async () => {
        let response: PublicKeySubsystemPacket | undefined
        const fixture = new PublicKeySubsystemServerFixture((packet) => {
            if (packet.type === "version") {
                fixture.send({ type: "version", version: 1 })
            } else {
                response = packet
            }
        })

        await expect(PublicKeySubsystemClient.connect(asClientChannel(fixture))).rejects.toThrow(
            "Unsupported public-key subsystem version 1",
        )
        expect(response).toMatchObject({
            type: "status",
            code: PublicKeySubsystemStatusCode.VersionNotSupported,
        })
        expect(fixture.destroyed).toBe(true)
    })

    test("bounds a peer-controlled multi-packet response", async () => {
        const fixture = new PublicKeySubsystemServerFixture((packet) => {
            if (packet.type === "version") {
                fixture.send({ type: "version", version: 2 })
            } else if (packet.type === "listattributes") {
                for (let index = 0; index <= MAX_PUBLIC_KEY_SUBSYSTEM_RESPONSES; index++) {
                    fixture.send({
                        type: "attribute",
                        name: `a${index}@example.test`,
                        compulsory: false,
                    })
                }
            }
        })
        const client = await PublicKeySubsystemClient.connect(asClientChannel(fixture))

        await expect(client.listAttributes()).rejects.toThrow(
            "response exceeds the collection limit",
        )
        expect(fixture.destroyed).toBe(true)
    })

    test("rejects malformed standard attributes before sending add", async () => {
        let addRequests = 0
        const fixture = new PublicKeySubsystemServerFixture((packet) => {
            if (packet.type === "version") {
                fixture.send({ type: "version", version: 2 })
            } else if (packet.type === "add") {
                addRequests++
                fixture.send({
                    type: "status",
                    code: PublicKeySubsystemStatusCode.Success,
                    description: "",
                    languageTag: "",
                })
            }
        })
        const client = await PublicKeySubsystemClient.connect(asClientChannel(fixture))

        await expect(
            client.add(PublicKey.parse(RFC_8709_KEY), {
                attributes: [{ name: "comment-language", value: "en" }],
            }),
        ).rejects.toThrow("comment-language must immediately follow comment")
        expect(addRequests).toBe(0)
        fixture.destroy()
    })

    test("rejects a pending request when the subsystem channel closes", async () => {
        const fixture = new PublicKeySubsystemServerFixture((packet) => {
            if (packet.type === "version") {
                fixture.send({ type: "version", version: 2 })
            } else if (packet.type === "list") {
                queueMicrotask(() => fixture.destroy())
            }
        })
        const client = await PublicKeySubsystemClient.connect(asClientChannel(fixture))

        await expect(client.list()).rejects.toThrow("Public-key subsystem channel closed")
    })

    test("closes after a listed key algorithm disagrees with its key blob", async () => {
        const fixture = new PublicKeySubsystemServerFixture((packet) => {
            if (packet.type === "version") {
                fixture.send({ type: "version", version: 2 })
            } else if (packet.type === "list") {
                fixture.send({
                    type: "publickey",
                    algorithm: "ssh-rsa",
                    keyBlob: RFC_8709_KEY,
                    attributes: [],
                })
                fixture.send({
                    type: "status",
                    code: PublicKeySubsystemStatusCode.Success,
                    description: "",
                    languageTag: "",
                })
            }
        })
        const client = await PublicKeySubsystemClient.connect(asClientChannel(fixture))

        await expect(client.list()).rejects.toThrow("algorithm does not match its key blob")
        expect(fixture.destroyed).toBe(true)
    })
})
