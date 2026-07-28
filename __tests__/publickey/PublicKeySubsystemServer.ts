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

class ClosablePublicKeySubsystemServerShell extends PublicKeySubsystemClientFixture {
    closeCalls = 0

    close(): this {
        this.closeCalls++
        return this
    }

    finishClose(error?: Error): void {
        this.destroy(error)
    }
}

class BlockedPublicKeySubsystemServerShell extends Duplex {
    _read(): void {
        void this.readable
    }

    _write(
        _chunk: Buffer,
        _encoding: BufferEncoding,
        _callback: (error?: Error | null) => void,
    ): void {
        void _callback
    }
}

function asShell(stream: PublicKeySubsystemClientFixture): Shell {
    return stream as unknown as Shell
}

describe("RFC 4819 and RFC 7076 public-key subsystem server", () => {
    test("advertises RFC 7076 version 3 and negotiates an RFC 4819 version-2 peer", async () => {
        const packets: PublicKeySubsystemPacket[] = []
        const fixture = new PublicKeySubsystemClientFixture((packet) => {
            packets.push(packet)
            if (packet.type === "version") {
                queueMicrotask(() => fixture.send({ type: "version", version: 2 }))
            }
        })
        const server = new PublicKeySubsystemServer(asShell(fixture))

        expect(await once(server, "ready")).toEqual([2])
        expect(server.protocolVersion).toBe(3)
        expect(server.negotiatedProtocolVersion).toBe(2)
        expect(packets).toEqual([{ type: "version", version: 3 }])
        server.destroy()
    })

    test("rejects malformed capability configuration before version exchange", () => {
        const packets: PublicKeySubsystemPacket[] = []
        const fixture = new PublicKeySubsystemClientFixture((packet) => packets.push(packet))
        const cases: readonly [unknown, string][] = [
            [null, "Public-key subsystem server options must be an object"],
            [{ attributes: null }, "Public-key subsystem server attributes must be an array"],
            [{ attributes: [null] }, "Public-key subsystem supported attribute must be an object"],
            [
                { attributes: [{ name: null }] },
                "Public-key subsystem supported attribute name must be a string",
            ],
            [
                { attributes: [{ name: "shell", compulsory: null }] },
                "Public-key subsystem compulsory attribute flag must be a boolean",
            ],
            [
                { closeTimeout: null },
                "Public-key subsystem server close timeout must be a positive number",
            ],
            [
                { requestTimeout: null },
                "Public-key subsystem server request timeout must be a positive number",
            ],
        ]

        for (const [options, message] of cases) {
            expect(() => new PublicKeySubsystemServer(asShell(fixture), options as never)).toThrow(
                message,
            )
        }
        expect(packets).toEqual([])
        fixture.destroy()
    })

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

    test("delivers RFC 7076 namespace key operations to awaited policy", async () => {
        let resolveStatus: ((packet: PublicKeySubsystemPacket) => void) | undefined
        const nextStatus = () =>
            new Promise<PublicKeySubsystemPacket>((resolve) => {
                resolveStatus = resolve
            })
        const fixture = new PublicKeySubsystemClientFixture((packet) => {
            if (packet.type === "version") {
                queueMicrotask(() => fixture.send({ type: "version", version: 3 }))
            } else if (packet.type === "status") {
                resolveStatus?.(packet)
                resolveStatus = undefined
            }
        })
        const server = new PublicKeySubsystemServer(asShell(fixture))
        const operations: string[] = []
        server.hooker.hook("add", async (_hook, context, controller) => {
            await Promise.resolve()
            expect(context.namespace).toBe("ssh")
            operations.push("add")
            controller.success = true
        })
        server.hooker.hook("remove", async (_hook, context, controller) => {
            await Promise.resolve()
            expect(context.namespace).toBe("ssh")
            operations.push("remove")
            controller.success = true
        })
        server.hooker.hook("list", async (_hook, controller, context) => {
            await Promise.resolve()
            expect(context.namespace).toBe("ssh")
            operations.push("list")
            controller.success = true
        })

        await once(server, "ready")
        const namespace = [
            {
                name: "namespace",
                value: Buffer.from("ssh"),
                critical: true,
            },
        ]
        let status = nextStatus()
        fixture.send({
            type: "add",
            algorithm: "ssh-ed25519",
            keyBlob: RFC_8709_KEY,
            overwrite: false,
            attributes: namespace,
        })
        expect(await status).toMatchObject({ code: PublicKeySubsystemStatusCode.Success })

        status = nextStatus()
        fixture.send({
            type: "remove",
            algorithm: "ssh-ed25519",
            keyBlob: RFC_8709_KEY,
            attributes: namespace,
        })
        expect(await status).toMatchObject({ code: PublicKeySubsystemStatusCode.Success })

        status = nextStatus()
        fixture.send({ type: "list", attributes: namespace })
        expect(await status).toMatchObject({ code: PublicKeySubsystemStatusCode.Success })
        expect(operations).toEqual(["add", "remove", "list"])
        server.destroy()
    })

    test("uses the RFC 7076 default namespace and authorization failure", async () => {
        let statusResolve!: (packet: PublicKeySubsystemPacket) => void
        const status = new Promise<PublicKeySubsystemPacket>((resolve) => {
            statusResolve = resolve
        })
        const fixture = new PublicKeySubsystemClientFixture((packet) => {
            if (packet.type === "version") {
                queueMicrotask(() => fixture.send({ type: "version", version: 3 }))
            } else if (packet.type === "status") {
                statusResolve(packet)
            }
        })
        const server = new PublicKeySubsystemServer(asShell(fixture))
        server.hooker.hook("add", (_hook, context, controller) => {
            expect(context.namespace).toBe("ssh")
            controller.success = false
        })
        await once(server, "ready")

        fixture.send({
            type: "add",
            algorithm: "ssh-ed25519",
            keyBlob: RFC_8709_KEY,
            overwrite: false,
            attributes: [],
        })

        expect(await status).toMatchObject({
            code: PublicKeySubsystemStatusCode.ActionNotAuthorized,
        })
        server.destroy()
    })

    test("awaits RFC 7076 certificate and namespace policy", async () => {
        let resolveExchange: ((packets: readonly PublicKeySubsystemPacket[]) => void) | undefined
        let exchangePackets: PublicKeySubsystemPacket[] = []
        const fixture = new PublicKeySubsystemClientFixture((packet) => {
            if (packet.type === "version") {
                queueMicrotask(() => fixture.send({ type: "version", version: 3 }))
                return
            }
            exchangePackets.push(packet)
            if (packet.type === "status") {
                const packets = exchangePackets
                exchangePackets = []
                resolveExchange?.(packets)
                resolveExchange = undefined
            }
        })
        const server = new PublicKeySubsystemServer(asShell(fixture))
        const release = Promise.withResolvers<void>()
        let addStartedResolve!: () => void
        const addStarted = new Promise<void>((resolve) => {
            addStartedResolve = resolve
        })
        const operations: string[] = []
        server.hooker.hook("addCertificate", async (_hook, context, controller) => {
            expect(context).toEqual({
                format: "X509",
                certificate: Buffer.from([1, 2, 3]),
                overwrite: true,
                namespace: "ssh",
                attributes: [
                    {
                        name: "namespace",
                        value: Buffer.from("ssh"),
                        critical: true,
                    },
                ],
            })
            addStartedResolve()
            await release.promise
            operations.push("add")
            controller.success = true
        })
        server.hooker.hook("removeCertificate", async (_hook, context, controller) => {
            await Promise.resolve()
            expect(context.namespace).toBe("ssh")
            operations.push("remove")
            controller.success = true
        })
        server.hooker.hook("listCertificates", async (_hook, controller) => {
            await Promise.resolve()
            operations.push("list-certificates")
            controller.certificates = [
                {
                    format: "X509",
                    certificate: Buffer.from([4, 5, 6]),
                    namespace: "ssh",
                },
            ]
            controller.success = true
        })
        server.hooker.hook("listNamespaces", async (_hook, controller) => {
            await Promise.resolve()
            operations.push("list-namespaces")
            controller.namespaces = ["ssh", "ssl"]
            controller.success = true
        })

        const exchange = (packet: PublicKeySubsystemPacket) => {
            const response = new Promise<readonly PublicKeySubsystemPacket[]>((resolve) => {
                resolveExchange = resolve
            })
            fixture.send(packet)
            return response
        }

        await once(server, "ready")
        let response = exchange({
            type: "add-certificate",
            format: "X509",
            certificateBlob: Buffer.from([1, 2, 3]),
            overwrite: true,
            attributes: [
                {
                    name: "namespace",
                    value: Buffer.from("ssh"),
                    critical: true,
                },
            ],
        })
        await addStarted
        expect(exchangePackets).toEqual([])
        release.resolve()
        expect(await response).toEqual([
            {
                type: "status",
                code: PublicKeySubsystemStatusCode.Success,
                description: "",
                languageTag: "",
            },
        ])

        response = exchange({
            type: "remove-certificate",
            format: "X509",
            certificateBlob: Buffer.from([1, 2, 3]),
            attributes: [{ name: "namespace", value: Buffer.from("ssh") }],
        })
        expect((await response).at(-1)).toMatchObject({
            code: PublicKeySubsystemStatusCode.Success,
        })

        response = exchange({ type: "list-certificates" })
        expect(await response).toEqual([
            {
                type: "certificate",
                format: "X509",
                certificateBlob: Buffer.from([4, 5, 6]),
                attributes: [{ name: "namespace", value: Buffer.from("ssh") }],
            },
            {
                type: "status",
                code: PublicKeySubsystemStatusCode.Success,
                description: "",
                languageTag: "",
            },
        ])

        response = exchange({ type: "list-namespaces" })
        expect(await response).toEqual([
            { type: "namespace", name: "ssh" },
            { type: "namespace", name: "ssl" },
            {
                type: "status",
                code: PublicKeySubsystemStatusCode.Success,
                description: "",
                languageTag: "",
            },
        ])
        expect(operations).toEqual(["add", "remove", "list-certificates", "list-namespaces"])
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

    test("writes an application-defined full-width failure status", async () => {
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
        server.hooker.hook("remove", (_hook, _context, controller) => {
            controller.failureCode = 0x0102_0304
            controller.description = "private failure"
        })

        await once(server, "ready")
        fixture.send({
            type: "remove",
            algorithm: "ssh-ed25519",
            keyBlob: RFC_8709_KEY,
        })

        expect(await status).toEqual({
            type: "status",
            code: 0x0102_0304,
            description: "private failure",
            languageTag: "",
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
            { type: "attribute", name: "namespace", compulsory: false },
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
                } else if (
                    packet.type === "status" &&
                    packet.code === PublicKeySubsystemStatusCode.Success
                ) {
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
                type: "attribute",
                name: "namespace",
                compulsory: false,
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

    test("closes when a request layout contradicts negotiated version 3", async () => {
        const fixture = new PublicKeySubsystemClientFixture((packet) => {
            if (packet.type === "version") {
                queueMicrotask(() => fixture.send({ type: "version", version: 3 }))
            }
        })
        fixture.on("error", () => undefined)
        const server = new PublicKeySubsystemServer(asShell(fixture))

        await once(server, "ready")
        const failed = once(server, "error")
        fixture.send({ type: "list" })
        const [error] = await failed

        expect(error.message).toContain("layout does not match negotiated version")
        expect(fixture.destroyed).toBe(true)
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

    test("coalesces close calls and awaits the underlying channel", async () => {
        const fixture = new ClosablePublicKeySubsystemServerShell(() => undefined)
        const server = new PublicKeySubsystemServer(asShell(fixture))
        let closeEvents = 0
        server.on("close", () => closeEvents++)

        const closing = server.close()
        expect(server.close()).toBe(closing)
        expect(server[Symbol.asyncDispose]()).toBe(closing)
        expect(fixture.closeCalls).toBe(1)
        expect(closeEvents).toBe(1)

        let settled = false
        void closing.then(() => {
            settled = true
        })
        await Promise.resolve()
        expect(settled).toBe(false)

        fixture.finishClose()
        await closing
        expect(settled).toBe(true)
        expect(closeEvents).toBe(1)
    })

    test("does not write a late policy response after graceful close starts", async () => {
        const packets: PublicKeySubsystemPacket[] = []
        const fixture = new ClosablePublicKeySubsystemServerShell((packet) => {
            packets.push(packet)
            if (packet.type === "version") {
                queueMicrotask(() => fixture.send({ type: "version", version: 2 }))
            }
        })
        const server = new PublicKeySubsystemServer(asShell(fixture))
        let release!: () => void
        const policy = new Promise<void>((resolve) => {
            release = resolve
        })
        let startedResolve!: () => void
        const started = new Promise<void>((resolve) => {
            startedResolve = resolve
        })
        server.hooker.hook("remove", async (_hook, _context, controller) => {
            startedResolve()
            await policy
            controller.success = true
        })

        await once(server, "ready")
        fixture.send({
            type: "remove",
            algorithm: "ssh-ed25519",
            keyBlob: RFC_8709_KEY,
        })
        await started

        const closing = server.close()
        release()
        await Promise.resolve()
        await Promise.resolve()

        expect(packets).toEqual([{ type: "version", version: 3 }])
        expect(fixture.destroyed).toBe(false)
        fixture.finishClose()
        await closing
    })

    test("bounds server shutdown when the peer does not close its channel", async () => {
        const fixture = new ClosablePublicKeySubsystemServerShell(() => undefined)
        const server = new PublicKeySubsystemServer(asShell(fixture), { closeTimeout: 20 })

        await expect(server.close()).rejects.toThrow(
            "Timed out waiting for public-key subsystem server channel to close",
        )
        expect(fixture.destroyed).toBe(true)
        expect(fixture.closeCalls).toBe(1)
    })

    test("bounds a version response blocked by channel flow control", async () => {
        const fixture = new BlockedPublicKeySubsystemServerShell()
        const server = new PublicKeySubsystemServer(fixture as unknown as Shell, {
            requestTimeout: 20,
        })
        const failed = once(server, "error")

        const [error] = await failed
        expect(error.message).toBe(
            "Timed out waiting for public-key subsystem server initialization response",
        )
        expect(fixture.destroyed).toBe(true)
    })
})
