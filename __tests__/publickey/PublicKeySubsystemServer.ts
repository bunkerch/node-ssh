import { describe, expect, test } from "bun:test"
import { once } from "node:events"
import { Duplex } from "node:stream"
import type Shell from "../../src/channels/Session/Shell.js"
import {
    decodePublicKeySubsystemPacket,
    encodePublicKeySubsystemPacket,
    PublicKeySubsystemStatusCode,
    type PublicKeySubsystemPacket,
} from "../../src/publickey/PublicKeySubsystemCodec.js"
import PublicKeySubsystemServer from "../../src/publickey/PublicKeySubsystemServer.js"
import PublicKey from "../../src/utils/PublicKey.js"

const RFC_8709_KEY = Buffer.from(
    "0000000b7373682d6564323535313900000020" +
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "hex",
)

class PublicKeySubsystemClientFixture extends Duplex {
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

function asShell(stream: PublicKeySubsystemClientFixture): Shell {
    return stream as unknown as Shell
}

describe("RFC 4819 public-key subsystem server", () => {
    test("awaits add policy before acknowledging a supported critical attribute", async () => {
        let statusResolve!: (packet: PublicKeySubsystemPacket) => void
        const status = new Promise<PublicKeySubsystemPacket>((resolve) => {
            statusResolve = resolve
        })
        const fixture = new PublicKeySubsystemClientFixture((packet) => {
            if (packet.type === "version") {
                queueMicrotask(() => fixture.send({ type: "version", version: 2 }))
            } else if (packet.type === "status") {
                statusResolve(packet)
            }
        })
        const server = new PublicKeySubsystemServer(asShell(fixture), {
            attributes: [{ name: "comment", compulsory: false }],
        })
        let release!: () => void
        const policy = new Promise<void>((resolve) => {
            release = resolve
        })
        let startedResolve!: () => void
        const started = new Promise<void>((resolve) => {
            startedResolve = resolve
        })
        server.hooker.hook("add", async (_hook, context, controller) => {
            expect(context.key.equals(PublicKey.parse(RFC_8709_KEY))).toBe(true)
            expect(context.attributes).toEqual([
                { name: "comment", value: Buffer.from("laptop"), critical: true },
            ])
            startedResolve()
            await policy
            controller.success = true
        })

        await once(server, "ready")
        fixture.send({
            type: "add",
            algorithm: "ssh-ed25519",
            keyBlob: RFC_8709_KEY,
            overwrite: false,
            attributes: [{ name: "comment", value: Buffer.from("laptop"), critical: true }],
        })
        await started
        let settled = false
        void status.then(() => {
            settled = true
        })
        await Promise.resolve()
        expect(settled).toBe(false)
        release()

        expect(await status).toMatchObject({
            type: "status",
            code: PublicKeySubsystemStatusCode.Success,
        })
        server.destroy()
    })

    test("routes remove requests through awaited policy", async () => {
        let statusResolve!: (packet: PublicKeySubsystemPacket) => void
        const status = new Promise<PublicKeySubsystemPacket>((resolve) => {
            statusResolve = resolve
        })
        const fixture = new PublicKeySubsystemClientFixture((packet) => {
            if (packet.type === "version") {
                queueMicrotask(() => fixture.send({ type: "version", version: 2 }))
            } else if (packet.type === "status") {
                statusResolve(packet)
            }
        })
        const server = new PublicKeySubsystemServer(asShell(fixture))
        server.hooker.hook("remove", async (_hook, context, controller) => {
            await Promise.resolve()
            expect(context.key.equals(PublicKey.parse(RFC_8709_KEY))).toBe(true)
            controller.success = true
        })

        await once(server, "ready")
        fixture.send({
            type: "remove",
            algorithm: "ssh-ed25519",
            keyBlob: RFC_8709_KEY,
        })

        expect(await status).toMatchObject({
            type: "status",
            code: PublicKeySubsystemStatusCode.Success,
        })
        server.destroy()
    })

    test("streams listed keys before the final success status", async () => {
        const responses: PublicKeySubsystemPacket[] = []
        let completeResolve!: () => void
        const complete = new Promise<void>((resolve) => {
            completeResolve = resolve
        })
        const fixture = new PublicKeySubsystemClientFixture((packet) => {
            if (packet.type === "version") {
                queueMicrotask(() => fixture.send({ type: "version", version: 2 }))
            } else {
                responses.push(packet)
                if (packet.type === "status") completeResolve()
            }
        })
        const server = new PublicKeySubsystemServer(asShell(fixture))
        server.hooker.hook("list", async (_hook, controller) => {
            await Promise.resolve()
            controller.keys = [
                {
                    key: PublicKey.parse(RFC_8709_KEY),
                    attributes: [{ name: "comment", value: Buffer.from("desktop") }],
                },
            ]
            controller.success = true
        })

        await once(server, "ready")
        fixture.send({ type: "list" })
        await complete

        expect(responses).toEqual([
            {
                type: "publickey",
                algorithm: "ssh-ed25519",
                keyBlob: RFC_8709_KEY,
                attributes: [{ name: "comment", value: Buffer.from("desktop") }],
            },
            {
                type: "status",
                code: PublicKeySubsystemStatusCode.Success,
                description: "",
                languageTag: "",
            },
        ])
        server.destroy()
    })

    test("lists configured attribute capabilities and compulsory policy", async () => {
        const responses: PublicKeySubsystemPacket[] = []
        let completeResolve!: () => void
        const complete = new Promise<void>((resolve) => {
            completeResolve = resolve
        })
        const fixture = new PublicKeySubsystemClientFixture((packet) => {
            if (packet.type === "version") {
                queueMicrotask(() => fixture.send({ type: "version", version: 2 }))
            } else {
                responses.push(packet)
                if (packet.type === "status") completeResolve()
            }
        })
        const server = new PublicKeySubsystemServer(asShell(fixture), {
            attributes: [{ name: "comment" }, { name: "shell", compulsory: true }],
        })

        await once(server, "ready")
        fixture.send({ type: "listattributes" })
        await complete

        expect(responses).toEqual([
            { type: "attribute", name: "comment", compulsory: false },
            { type: "attribute", name: "shell", compulsory: true },
            {
                type: "status",
                code: PublicKeySubsystemStatusCode.Success,
                description: "",
                languageTag: "",
            },
        ])
        server.destroy()
    })

    test("acknowledges an unknown request without closing the subsystem", async () => {
        const responses: PublicKeySubsystemPacket[] = []
        let completeResolve!: () => void
        const complete = new Promise<void>((resolve) => {
            completeResolve = resolve
        })
        const fixture = new PublicKeySubsystemClientFixture((packet) => {
            if (packet.type === "version") {
                queueMicrotask(() => fixture.send({ type: "version", version: 2 }))
            } else {
                responses.push(packet)
                if (responses.length === 1) {
                    queueMicrotask(() => fixture.send({ type: "listattributes" }))
                } else if (responses.length === 2) {
                    completeResolve()
                }
            }
        })
        const server = new PublicKeySubsystemServer(asShell(fixture))

        await once(server, "ready")
        fixture.send({ type: "unknown", name: "query@example.test", data: Buffer.from("x") })
        await complete

        expect(responses).toEqual([
            {
                type: "status",
                code: PublicKeySubsystemStatusCode.RequestNotSupported,
                description: "Unsupported public-key subsystem request query@example.test",
                languageTag: "",
            },
            {
                type: "status",
                code: PublicKeySubsystemStatusCode.Success,
                description: "",
                languageTag: "",
            },
        ])
        expect(fixture.destroyed).toBe(false)
        server.destroy()
    })

    test("rejects unsupported critical attributes before application policy", async () => {
        let statusResolve!: (packet: PublicKeySubsystemPacket) => void
        const status = new Promise<PublicKeySubsystemPacket>((resolve) => {
            statusResolve = resolve
        })
        const fixture = new PublicKeySubsystemClientFixture((packet) => {
            if (packet.type === "version") {
                queueMicrotask(() => fixture.send({ type: "version", version: 2 }))
            } else if (packet.type === "status") {
                statusResolve(packet)
            }
        })
        const server = new PublicKeySubsystemServer(asShell(fixture), {
            attributes: [{ name: "comment" }],
        })
        let policyCalls = 0
        server.hooker.hook("add", (_hook, _context, controller) => {
            policyCalls++
            controller.success = true
        })

        await once(server, "ready")
        fixture.send({
            type: "add",
            algorithm: "ssh-ed25519",
            keyBlob: RFC_8709_KEY,
            overwrite: false,
            attributes: [{ name: "unknown@example.test", value: Buffer.alloc(0), critical: true }],
        })

        expect(await status).toMatchObject({
            type: "status",
            code: PublicKeySubsystemStatusCode.AttributeNotSupported,
        })
        expect(policyCalls).toBe(0)
        server.destroy()
    })

    test("rejects a comment-language attribute that does not follow a comment", async () => {
        let statusResolve!: (packet: PublicKeySubsystemPacket) => void
        const status = new Promise<PublicKeySubsystemPacket>((resolve) => {
            statusResolve = resolve
        })
        const fixture = new PublicKeySubsystemClientFixture((packet) => {
            if (packet.type === "version") {
                queueMicrotask(() => fixture.send({ type: "version", version: 2 }))
            } else if (packet.type === "status") {
                statusResolve(packet)
            }
        })
        const server = new PublicKeySubsystemServer(asShell(fixture), {
            attributes: [{ name: "comment" }, { name: "comment-language" }],
        })
        let policyCalls = 0
        server.hooker.hook("add", (_hook, _context, controller) => {
            policyCalls++
            controller.success = true
        })

        await once(server, "ready")
        fixture.send({
            type: "add",
            algorithm: "ssh-ed25519",
            keyBlob: RFC_8709_KEY,
            overwrite: false,
            attributes: [{ name: "comment-language", value: Buffer.from("en"), critical: false }],
        })

        expect(await status).toMatchObject({
            type: "status",
            code: PublicKeySubsystemStatusCode.AttributeNotSupported,
        })
        expect(policyCalls).toBe(0)
        server.destroy()
    })

    test("contains a rejected async policy hook and reports general failure", async () => {
        let statusResolve!: (packet: PublicKeySubsystemPacket) => void
        const status = new Promise<PublicKeySubsystemPacket>((resolve) => {
            statusResolve = resolve
        })
        const fixture = new PublicKeySubsystemClientFixture((packet) => {
            if (packet.type === "version") {
                queueMicrotask(() => fixture.send({ type: "version", version: 2 }))
            } else if (packet.type === "status") {
                statusResolve(packet)
            }
        })
        const server = new PublicKeySubsystemServer(asShell(fixture))
        server.hooker.hook("remove", async () => {
            await Promise.resolve()
            throw new Error("storage unavailable")
        })

        await once(server, "ready")
        fixture.send({
            type: "remove",
            algorithm: "ssh-ed25519",
            keyBlob: RFC_8709_KEY,
        })

        expect(await status).toEqual({
            type: "status",
            code: PublicKeySubsystemStatusCode.GeneralFailure,
            description: "Public-key subsystem remove handler failed",
            languageTag: "",
        })
        expect(fixture.destroyed).toBe(false)
        server.destroy()
    })

    test("closes when a client pipelines requests before acknowledgement", async () => {
        const fixture = new PublicKeySubsystemClientFixture((packet) => {
            if (packet.type === "version") {
                queueMicrotask(() => fixture.send({ type: "version", version: 2 }))
            }
        })
        fixture.on("error", () => undefined)
        const server = new PublicKeySubsystemServer(asShell(fixture))

        await once(server, "ready")
        const failed = once(server, "error")
        fixture.send({ type: "list" })
        fixture.send({ type: "listattributes" })
        const [error] = await failed

        expect(error.message).toContain("request before acknowledgement")
        expect(fixture.destroyed).toBe(true)
    })
})
