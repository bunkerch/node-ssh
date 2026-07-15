import { describe, expect, test } from "bun:test"
import { Duplex } from "node:stream"
import type Shell from "../../src/channels/Session/Shell.js"
import { decodeSFTPPacket, encodeSFTPPacket } from "../../src/sftp/codec.js"
import SFTPServer from "../../src/sftp/SFTPServer.js"
import { MAX_SFTP_PACKET_LENGTH, SFTPPacketType, SFTPStatusCode } from "../../src/sftp/constants.js"
import type { SFTPPacket, SFTPRequestPacket } from "../../src/sftp/types.js"

class SFTPClientFixture extends Duplex {
    readonly responses: SFTPPacket[] = []
    deferWrites = false
    private deferredWrite?: (error?: Error | null) => void

    _read(): void {
        void this.readable
    }

    _write(
        chunk: Buffer,
        _encoding: BufferEncoding,
        callback: (error?: Error | null) => void,
    ): void {
        try {
            this.responses.push(decodeSFTPPacket(chunk))
            if (this.deferWrites) this.deferredWrite = callback
            else callback()
        } catch (error) {
            callback(error instanceof Error ? error : new Error(String(error)))
        }
    }

    send(packet: SFTPPacket): void {
        this.push(encodeSFTPPacket(packet))
    }

    releaseWrite(error?: Error): void {
        const callback = this.deferredWrite
        if (!callback) throw new Error("No SFTP response write is deferred")
        this.deferredWrite = undefined
        callback(error)
    }
}

function asShell(client: SFTPClientFixture): Shell {
    return client as unknown as Shell
}

const flush = (): Promise<void> => new Promise((resolve) => setImmediate(resolve))

describe("SFTP server request engine", () => {
    test("rejects malformed server options during construction", () => {
        const fixture = new SFTPClientFixture()
        try {
            expect(() => new SFTPServer(asShell(fixture), null as never)).toThrow(
                "SFTP server options must be an object",
            )
            expect(() => new SFTPServer(asShell(fixture), { extensions: null as never })).toThrow(
                "SFTP server extensions must be an array",
            )
            expect(
                () =>
                    new SFTPServer(asShell(fixture), {
                        openSSHSymlinkArguments: null as never,
                    }),
            ).toThrow("SFTP OpenSSH symlink argument option must be a boolean")
            expect(
                () => new SFTPServer(asShell(fixture), { maxConcurrentRequests: null as never }),
            ).toThrow("SFTP maximum concurrent requests must be between")
            expect(
                () => new SFTPServer(asShell(fixture), { maxOpenHandles: null as never }),
            ).toThrow("SFTP maximum open handles must be a non-negative safe integer")
            expect(
                () => new SFTPServer(asShell(fixture), { maxReadLength: null as never }),
            ).toThrow("SFTP maximum read length must be between")
            expect(
                () =>
                    new SFTPServer(asShell(fixture), {
                        maxWriteLength: MAX_SFTP_PACKET_LENGTH,
                    }),
            ).toThrow("SFTP maximum write length must be between")
            expect(
                () => new SFTPServer(asShell(fixture), { advertiseLimits: null as never }),
            ).toThrow("SFTP advertise-limits option must be a boolean")
            expect(
                () =>
                    new SFTPServer(asShell(fixture), {
                        maxOpenHandles: 0,
                        advertiseLimits: true,
                    }),
            ).toThrow("SFTP limits cannot advertise a zero-handle server capacity")
            expect(
                () =>
                    new SFTPServer(asShell(fixture), {
                        extensions: [
                            { name: "limits@openssh.com", data: Buffer.from("1", "ascii") },
                        ],
                    }),
            ).toThrow("SFTP limits extension is already provided by the server")
        } finally {
            fixture.destroy()
        }
    })

    test("advertises, answers, and enforces the server limits extension", async () => {
        const fixture = new SFTPClientFixture()
        const server = new SFTPServer(asShell(fixture), {
            maxOpenHandles: 7,
            maxReadLength: 2,
            maxWriteLength: 3,
        })
        const hooks: string[] = []
        server.hooker.hook("READ", () => {
            hooks.push("READ")
        })
        server.hooker.hook("WRITE", () => {
            hooks.push("WRITE")
        })
        server.hooker.hook("EXTENDED", () => {
            hooks.push("EXTENDED")
        })

        fixture.send({ type: SFTPPacketType.Init, version: 3, extensions: [] })
        fixture.send({
            type: SFTPPacketType.Extended,
            requestId: 1,
            request: "limits@openssh.com",
            data: Buffer.alloc(0),
        })
        fixture.send({
            type: SFTPPacketType.Extended,
            requestId: 2,
            request: "limits@openssh.com",
            data: Buffer.from([0]),
        })
        fixture.send({
            type: SFTPPacketType.Read,
            requestId: 3,
            handle: Buffer.from("h"),
            offset: 0n,
            length: 3,
        })
        fixture.send({
            type: SFTPPacketType.Write,
            requestId: 4,
            handle: Buffer.from("h"),
            offset: 0n,
            data: Buffer.alloc(4),
        })
        await flush()

        expect(server.maxReadLength).toBe(2)
        expect(server.maxWriteLength).toBe(3)
        expect(server.extensions).toContainEqual({
            name: "limits@openssh.com",
            data: Buffer.from("1", "ascii"),
        })
        expect(hooks).toEqual([])
        expect(fixture.responses[1]).toEqual({
            type: SFTPPacketType.ExtendedReply,
            requestId: 1,
            data: Buffer.from(
                "0000000000040000000000000000000200000000000000030000000000000007",
                "hex",
            ),
        })
        expect(
            fixture.responses
                .filter((packet) => packet.type === SFTPPacketType.Status)
                .map((packet) => ({ requestId: packet.requestId, code: packet.code })),
        ).toEqual([
            { requestId: 2, code: SFTPStatusCode.BadMessage },
            { requestId: 3, code: SFTPStatusCode.Failure },
            { requestId: 4, code: SFTPStatusCode.Failure },
        ])
        fixture.destroy()
    })

    test("allows the built-in limits extension to be suppressed or application-owned", () => {
        const disabledFixture = new SFTPClientFixture()
        const disabled = new SFTPServer(asShell(disabledFixture), { maxOpenHandles: 0 })
        expect(disabled.extensions).toEqual([])
        disabledFixture.destroy()

        const applicationFixture = new SFTPClientFixture()
        const application = new SFTPServer(asShell(applicationFixture), {
            advertiseLimits: false,
            extensions: [{ name: "limits@openssh.com", data: Buffer.from("9", "ascii") }],
        })
        expect(application.extensions).toEqual([
            { name: "limits@openssh.com", data: Buffer.from("9", "ascii") },
        ])
        applicationFixture.destroy()
    })

    test("bounds pending and active baseline handles and recovers capacity on close", async () => {
        const fixture = new SFTPClientFixture()
        const server = new SFTPServer(asShell(fixture), { maxOpenHandles: 1 })
        let releaseFirst!: () => void
        const firstPending = new Promise<void>((resolve) => {
            releaseFirst = resolve
        })
        let opens = 0
        server.hooker.hook("OPEN", async (_hook, request) => {
            opens++
            if (request.filename.equals(Buffer.from("first"))) await firstPending
            await server.handle(request.requestId, Buffer.from(request.filename))
        })
        server.hooker.hook("CLOSE", async (_hook, request) => {
            await server.status(request.requestId, SFTPStatusCode.Ok)
        })

        fixture.send({ type: SFTPPacketType.Init, version: 3, extensions: [] })
        fixture.send({
            type: SFTPPacketType.Open,
            requestId: 1,
            filename: Buffer.from("first"),
            flags: 1,
            attributes: {},
        })
        fixture.send({
            type: SFTPPacketType.Open,
            requestId: 2,
            filename: Buffer.from("second"),
            flags: 1,
            attributes: {},
        })
        await flush()

        expect(server.maxOpenHandles).toBe(1)
        expect(opens).toBe(1)
        expect(fixture.responses[1]).toMatchObject({
            type: SFTPPacketType.Status,
            requestId: 2,
            code: SFTPStatusCode.Failure,
            message: "SFTP open handle limit reached",
        })

        releaseFirst()
        await flush()
        expect(fixture.responses[2]).toEqual({
            type: SFTPPacketType.Handle,
            requestId: 1,
            handle: Buffer.from("first"),
        })
        fixture.send({ type: SFTPPacketType.Close, requestId: 3, handle: Buffer.from("first") })
        await flush()
        fixture.send({
            type: SFTPPacketType.Open,
            requestId: 4,
            filename: Buffer.from("second"),
            flags: 1,
            attributes: {},
        })
        await flush()

        expect(opens).toBe(2)
        expect(fixture.responses.at(-1)).toEqual({
            type: SFTPPacketType.Handle,
            requestId: 4,
            handle: Buffer.from("second"),
        })
        fixture.destroy()
    })

    test("rejects reuse of a live baseline handle", async () => {
        const fixture = new SFTPClientFixture()
        const server = new SFTPServer(asShell(fixture), { maxOpenHandles: 2 })
        let opens = 0
        server.hooker.hook("OPEN", async (_hook, request) => {
            opens++
            await server.handle(request.requestId, Buffer.from("shared"))
        })

        fixture.send({ type: SFTPPacketType.Init, version: 3, extensions: [] })
        fixture.send({
            type: SFTPPacketType.Open,
            requestId: 1,
            filename: Buffer.from("first"),
            flags: 1,
            attributes: {},
        })
        await flush()
        fixture.send({
            type: SFTPPacketType.Open,
            requestId: 2,
            filename: Buffer.from("second"),
            flags: 1,
            attributes: {},
        })
        await flush()

        expect(opens).toBe(2)
        expect(fixture.responses[1]).toEqual({
            type: SFTPPacketType.Handle,
            requestId: 1,
            handle: Buffer.from("shared"),
        })
        expect(fixture.responses[2]).toMatchObject({
            type: SFTPPacketType.Status,
            requestId: 2,
            code: SFTPStatusCode.Failure,
            message: "SFTP request handler failed",
        })
        fixture.destroy()
    })

    test("does not count a committed handle as pending while its hook finishes", async () => {
        const fixture = new SFTPClientFixture()
        const server = new SFTPServer(asShell(fixture), { maxOpenHandles: 2 })
        let finishFirst!: () => void
        const firstFinishing = new Promise<void>((resolve) => {
            finishFirst = resolve
        })
        let opens = 0
        server.hooker.hook("OPEN", async (_hook, request) => {
            opens++
            await server.handle(request.requestId, Buffer.from(request.filename))
            if (request.filename.equals(Buffer.from("first"))) await firstFinishing
        })

        fixture.send({ type: SFTPPacketType.Init, version: 3, extensions: [] })
        fixture.send({
            type: SFTPPacketType.Open,
            requestId: 1,
            filename: Buffer.from("first"),
            flags: 1,
            attributes: {},
        })
        await flush()
        fixture.send({
            type: SFTPPacketType.Open,
            requestId: 2,
            filename: Buffer.from("second"),
            flags: 1,
            attributes: {},
        })
        await flush()

        expect(opens).toBe(2)
        expect(fixture.responses[2]).toEqual({
            type: SFTPPacketType.Handle,
            requestId: 2,
            handle: Buffer.from("second"),
        })
        finishFirst()
        await flush()
        fixture.destroy()
    })

    test("rejects an invalid advertised extension name during construction", () => {
        const fixture = new SFTPClientFixture()
        try {
            expect(
                () =>
                    new SFTPServer(asShell(fixture), {
                        extensions: [{ name: "invalid extension", data: Buffer.alloc(0) }],
                    }),
            ).toThrow("SFTP extension name must be 1 to 64 printable US-ASCII characters")
        } finally {
            fixture.destroy()
        }
    })

    test("rejects non-buffer advertised extension data during construction", () => {
        const fixture = new SFTPClientFixture()
        try {
            expect(
                () =>
                    new SFTPServer(asShell(fixture), {
                        extensions: [{ name: "x@test", data: "1" as never }],
                    }),
            ).toThrow("SFTP extension data must be a buffer")
        } finally {
            fixture.destroy()
        }
    })

    test("owns advertised extension metadata before the version exchange", async () => {
        const fixture = new SFTPClientFixture()
        const data = Buffer.from("1")
        const extensions = [{ name: "x@test", data }]
        const server = new SFTPServer(asShell(fixture), { extensions })

        extensions[0]!.name = "changed@test"
        data[0] = 0x32
        extensions.push({ name: "added@test", data: Buffer.from("3") })
        const exposed = server.extensions
        exposed[0]!.data[0] = 0x33
        fixture.send({ type: SFTPPacketType.Init, version: 3, extensions: [] })
        await flush()

        expect(server.extensions).toEqual([
            { name: "x@test", data: Buffer.from("1") },
            { name: "limits@openssh.com", data: Buffer.from("1") },
        ])
        expect(Object.isFrozen(exposed)).toBe(true)
        expect(Object.isFrozen(exposed[0])).toBe(true)
        expect(fixture.responses).toEqual([
            {
                type: SFTPPacketType.Version,
                version: 3,
                extensions: [
                    { name: "x@test", data: Buffer.from("1") },
                    { name: "limits@openssh.com", data: Buffer.from("1") },
                ],
            },
        ])
        fixture.destroy()
    })

    test("negotiates v3 and handles pipelined requests concurrently", async () => {
        const fixture = new SFTPClientFixture()
        const server = new SFTPServer(asShell(fixture), {
            extensions: [{ name: "x@test", data: Buffer.from("1") }],
        })
        const events: string[] = []
        let finishRead!: () => void
        const readReady = new Promise<void>((resolve) => {
            finishRead = resolve
        })
        server.hooker.hook("READ", async (_hook, request) => {
            events.push("READ")
            await readReady
            await server.data(request.requestId, Buffer.from("abc"))
        })
        server.hooker.hook("WRITE", async (_hook, request) => {
            await Promise.resolve()
            events.push("WRITE")
            await server.status(request.requestId, SFTPStatusCode.Ok)
        })

        fixture.send({ type: SFTPPacketType.Init, version: 6, extensions: [] })
        await flush()
        expect(fixture.responses).toEqual([
            {
                type: SFTPPacketType.Version,
                version: 3,
                extensions: [
                    { name: "x@test", data: Buffer.from("1") },
                    { name: "limits@openssh.com", data: Buffer.from("1") },
                ],
            },
        ])
        fixture.send({
            type: SFTPPacketType.Read,
            requestId: 7,
            handle: Buffer.from("h"),
            offset: 0n,
            length: 3,
        })
        fixture.send({
            type: SFTPPacketType.Write,
            requestId: 8,
            handle: Buffer.from("other"),
            offset: 3n,
            data: Buffer.from("def"),
        })
        await flush()
        expect(events).toEqual(["READ", "WRITE"])
        expect(fixture.responses.slice(1)).toEqual([
            {
                type: SFTPPacketType.Status,
                requestId: 8,
                code: SFTPStatusCode.Ok,
                message: "No error",
                languageTag: "",
            },
        ])
        finishRead()
        await flush()
        expect(events).toEqual(["READ", "WRITE"])
        expect(fixture.responses.slice(1)).toEqual([
            {
                type: SFTPPacketType.Status,
                requestId: 8,
                code: SFTPStatusCode.Ok,
                message: "No error",
                languageTag: "",
            },
            { type: SFTPPacketType.Data, requestId: 7, data: Buffer.from("abc") },
        ])
        fixture.destroy()
    })

    test("serializes pipelined operations for the same handle", async () => {
        const fixture = new SFTPClientFixture()
        const server = new SFTPServer(asShell(fixture), { maxConcurrentRequests: 2 })
        const events: string[] = []
        let finishRead!: () => void
        const readPending = new Promise<void>((resolve) => {
            finishRead = resolve
        })
        server.hooker.hook("READ", async (_hook, request) => {
            events.push("READ:start")
            await readPending
            await server.data(request.requestId, Buffer.from("abc"))
            events.push("READ:end")
        })
        server.hooker.hook("WRITE", async (_hook, request) => {
            events.push("WRITE")
            await server.status(request.requestId, SFTPStatusCode.Ok)
        })

        fixture.send({ type: SFTPPacketType.Init, version: 3, extensions: [] })
        fixture.send({
            type: SFTPPacketType.Read,
            requestId: 9,
            handle: Buffer.from("shared"),
            offset: 0n,
            length: 3,
        })
        fixture.send({
            type: SFTPPacketType.Write,
            requestId: 10,
            handle: Buffer.from("shared"),
            offset: 0n,
            data: Buffer.from("replacement"),
        })
        await flush()

        expect(events).toEqual(["READ:start"])
        finishRead()
        await flush()
        expect(events).toEqual(["READ:start", "READ:end", "WRITE"])
        expect(
            fixture.responses
                .slice(1)
                .map((packet) => ("requestId" in packet ? packet.requestId : undefined)),
        ).toEqual([9, 10])
        fixture.destroy()
    })

    test("associates returned handles with their paths for request ordering", async () => {
        const fixture = new SFTPClientFixture()
        const server = new SFTPServer(asShell(fixture), { maxConcurrentRequests: 2 })
        const events: string[] = []
        let finishRead!: () => void
        const readPending = new Promise<void>((resolve) => {
            finishRead = resolve
        })
        server.hooker.hook("OPEN", async (_hook, request) => {
            await server.handle(request.requestId, Buffer.from("file-handle"))
        })
        server.hooker.hook("READ", async (_hook, request) => {
            events.push("READ:start")
            await readPending
            await server.data(request.requestId, Buffer.from("x"))
            events.push("READ:end")
        })
        server.hooker.hook("SETSTAT", async (_hook, request) => {
            events.push("SETSTAT")
            await server.status(request.requestId, SFTPStatusCode.Ok)
        })

        fixture.send({ type: SFTPPacketType.Init, version: 3, extensions: [] })
        fixture.send({
            type: SFTPPacketType.Open,
            requestId: 11,
            filename: Buffer.from("same-file"),
            flags: 1,
            attributes: {},
        })
        await flush()
        fixture.send({
            type: SFTPPacketType.Read,
            requestId: 12,
            handle: Buffer.from("file-handle"),
            offset: 0n,
            length: 1,
        })
        fixture.send({
            type: SFTPPacketType.SetStat,
            requestId: 13,
            path: Buffer.from("same-file"),
            attributes: { permissions: 0o600 },
        })
        await flush()

        expect(events).toEqual(["READ:start"])
        finishRead()
        await flush()
        expect(events).toEqual(["READ:start", "READ:end", "SETSTAT"])
        fixture.destroy()
    })

    test("discards path ordering metadata after a failed close", async () => {
        const fixture = new SFTPClientFixture()
        const server = new SFTPServer(asShell(fixture), { maxConcurrentRequests: 2 })
        const events: string[] = []
        let finishRead!: () => void
        const readPending = new Promise<void>((resolve) => {
            finishRead = resolve
        })
        server.hooker.hook("OPEN", async (_hook, request) => {
            await server.handle(request.requestId, Buffer.from("reused-handle"))
        })
        server.hooker.hook("CLOSE", async (_hook, request) => {
            await server.status(request.requestId, SFTPStatusCode.Failure, "flush failed")
        })
        server.hooker.hook("READ", async (_hook, request) => {
            events.push("READ:start")
            await readPending
            await server.data(request.requestId, Buffer.from("x"))
            events.push("READ:end")
        })
        server.hooker.hook("SETSTAT", async (_hook, request) => {
            events.push("SETSTAT")
            await server.status(request.requestId, SFTPStatusCode.Ok)
        })

        fixture.send({ type: SFTPPacketType.Init, version: 3, extensions: [] })
        fixture.send({
            type: SFTPPacketType.Open,
            requestId: 14,
            filename: Buffer.from("old-path"),
            flags: 1,
            attributes: {},
        })
        await flush()
        fixture.send({
            type: SFTPPacketType.Close,
            requestId: 15,
            handle: Buffer.from("reused-handle"),
        })
        await flush()
        fixture.send({
            type: SFTPPacketType.Open,
            requestId: 16,
            filename: Buffer.from("new-path"),
            flags: 1,
            attributes: {},
        })
        await flush()
        fixture.send({
            type: SFTPPacketType.Read,
            requestId: 17,
            handle: Buffer.from("reused-handle"),
            offset: 0n,
            length: 1,
        })
        fixture.send({
            type: SFTPPacketType.SetStat,
            requestId: 18,
            path: Buffer.from("old-path"),
            attributes: { permissions: 0o600 },
        })
        await flush()

        expect(events).toEqual(["READ:start", "SETSTAT"])
        finishRead()
        await flush()
        expect(events).toEqual(["READ:start", "SETSTAT", "READ:end"])
        fixture.destroy()
    })

    test("does not let a later shared-path request overtake a blocked rename", async () => {
        const fixture = new SFTPClientFixture()
        const server = new SFTPServer(asShell(fixture), { maxConcurrentRequests: 2 })
        const events: string[] = []
        let finishFirst!: () => void
        const firstPending = new Promise<void>((resolve) => {
            finishFirst = resolve
        })
        server.hooker.hook("STAT", async (_hook, request) => {
            const path = request.path.toString()
            events.push(`STAT:${path}:start`)
            if (path === "first") await firstPending
            await server.attributes(request.requestId, {})
            events.push(`STAT:${path}:end`)
        })
        server.hooker.hook("RENAME", async (_hook, request) => {
            events.push("RENAME")
            await server.status(request.requestId, SFTPStatusCode.Ok)
        })

        fixture.send({ type: SFTPPacketType.Init, version: 3, extensions: [] })
        fixture.send({ type: SFTPPacketType.Stat, requestId: 14, path: Buffer.from("first") })
        fixture.send({
            type: SFTPPacketType.Rename,
            requestId: 15,
            firstPath: Buffer.from("first"),
            secondPath: Buffer.from("second"),
        })
        fixture.send({ type: SFTPPacketType.Stat, requestId: 16, path: Buffer.from("second") })
        await flush()

        expect(events).toEqual(["STAT:first:start"])
        finishFirst()
        await flush()
        expect(events).toEqual([
            "STAT:first:start",
            "STAT:first:end",
            "RENAME",
            "STAT:second:start",
            "STAT:second:end",
        ])
        fixture.destroy()
    })

    test("treats opaque extended requests as ordering barriers", async () => {
        const fixture = new SFTPClientFixture()
        const server = new SFTPServer(asShell(fixture), { maxConcurrentRequests: 3 })
        const events: string[] = []
        let finishFirst!: () => void
        const firstPending = new Promise<void>((resolve) => {
            finishFirst = resolve
        })
        let finishExtension!: () => void
        const extensionPending = new Promise<void>((resolve) => {
            finishExtension = resolve
        })
        server.hooker.hook("STAT", async (_hook, request) => {
            const path = request.path.toString()
            events.push(`STAT:${path}`)
            if (path === "first") await firstPending
            await server.attributes(request.requestId, {})
        })
        server.hooker.hook("EXTENDED", async (_hook, request) => {
            events.push("EXTENDED")
            await extensionPending
            await server.extendedReply(request.requestId, Buffer.alloc(0))
        })

        fixture.send({ type: SFTPPacketType.Init, version: 3, extensions: [] })
        fixture.send({ type: SFTPPacketType.Stat, requestId: 17, path: Buffer.from("first") })
        fixture.send({
            type: SFTPPacketType.Extended,
            requestId: 18,
            request: "ordered@example.com",
            data: Buffer.alloc(0),
        })
        fixture.send({ type: SFTPPacketType.Stat, requestId: 19, path: Buffer.from("second") })
        await flush()

        expect(events).toEqual(["STAT:first"])
        finishFirst()
        await flush()
        expect(events).toEqual(["STAT:first", "EXTENDED"])
        finishExtension()
        await flush()
        expect(events).toEqual(["STAT:first", "EXTENDED", "STAT:second"])
        fixture.destroy()
    })

    test("awaits response writes before releasing a configured concurrency slot", async () => {
        const fixture = new SFTPClientFixture()
        const server = new SFTPServer(asShell(fixture), { maxConcurrentRequests: 1 })
        const events: string[] = []
        server.hooker.hook("STAT", async (_hook, request) => {
            events.push("STAT:start")
            await server.attributes(request.requestId, { size: 3n })
            events.push("STAT:written")
        })
        server.hooker.hook("LSTAT", async (_hook, request) => {
            events.push("LSTAT")
            await server.attributes(request.requestId, { size: 4n })
        })

        fixture.send({ type: SFTPPacketType.Init, version: 3, extensions: [] })
        await flush()
        fixture.deferWrites = true
        fixture.send({ type: SFTPPacketType.Stat, requestId: 11, path: Buffer.from("one") })
        await flush()

        expect(events).toEqual(["STAT:start"])
        expect(fixture.responses.at(-1)).toMatchObject({
            type: SFTPPacketType.Attrs,
            requestId: 11,
        })
        fixture.send({ type: SFTPPacketType.LStat, requestId: 12, path: Buffer.from("two") })
        await flush()
        expect(events).toEqual(["STAT:start"])
        fixture.releaseWrite()
        await flush()
        expect(events).toEqual(["STAT:start", "STAT:written", "LSTAT"])
        fixture.releaseWrite()
        await flush()
        fixture.destroy()
    })

    test("bounds concurrent request handlers while retaining pipelined work", async () => {
        const fixture = new SFTPClientFixture()
        const server = new SFTPServer(asShell(fixture), { maxConcurrentRequests: 2 })
        const started: number[] = []
        const releases = new Map<number, () => void>()
        server.hooker.hook("STAT", async (_hook, request) => {
            started.push(request.requestId)
            await new Promise<void>((resolve) => releases.set(request.requestId, resolve))
            await server.attributes(request.requestId, { size: BigInt(request.requestId) })
        })

        fixture.send({ type: SFTPPacketType.Init, version: 3, extensions: [] })
        for (const requestId of [21, 22, 23]) {
            fixture.send({
                type: SFTPPacketType.Stat,
                requestId,
                path: Buffer.from(`file-${requestId}`),
            })
        }
        await flush()

        expect(started).toEqual([21, 22])
        releases.get(22)?.()
        await flush()
        expect(started).toEqual([21, 22, 23])
        releases.get(23)?.()
        releases.get(21)?.()
        await flush()
        expect(
            fixture.responses
                .filter((packet) => packet.type === SFTPPacketType.Attrs)
                .map((packet) => packet.requestId),
        ).toEqual([22, 23, 21])
        fixture.destroy()
    })

    test("validates the SFTP handler concurrency bound", () => {
        for (const value of [0, 1025, 1.5, Number.NaN]) {
            const fixture = new SFTPClientFixture()
            try {
                expect(
                    () =>
                        new SFTPServer(asShell(fixture), {
                            maxConcurrentRequests: value,
                        }),
                ).toThrow("between 1 and 1024")
            } finally {
                fixture.destroy()
            }
        }

        const fixture = new SFTPClientFixture()
        const server = new SFTPServer(asShell(fixture), { maxConcurrentRequests: 3 })
        expect(server.maxConcurrentRequests).toBe(3)
        expect(Reflect.set(server, "maxConcurrentRequests", 1024)).toBe(false)
        expect(server.maxConcurrentRequests).toBe(3)
        fixture.destroy()
    })

    test("rejects an awaited response when the channel write fails", async () => {
        const fixture = new SFTPClientFixture()
        const server = new SFTPServer(asShell(fixture))
        let response: Promise<void> | undefined
        server.hooker.hook("STAT", (_hook, request) => {
            response = server.attributes(request.requestId, { size: 3n })
            return response
        })

        fixture.send({ type: SFTPPacketType.Init, version: 3, extensions: [] })
        await flush()
        fixture.deferWrites = true
        fixture.send({ type: SFTPPacketType.Stat, requestId: 13, path: Buffer.from("one") })
        await flush()
        if (!response) throw new Error("SFTP response did not start")
        fixture.releaseWrite(new Error("response transport failed"))

        await expect(response).rejects.toThrow("response transport failed")
        await flush()
        expect(fixture.destroyed).toBe(true)
    })

    test("isolates passive request observation from awaited handlers", async () => {
        const fixture = new SFTPClientFixture()
        const server = new SFTPServer(asShell(fixture))
        let observed: Readonly<SFTPRequestPacket> | undefined
        let topLevelMutationRejected = false
        let handledFilename: Buffer | undefined
        let handledAttribute: Buffer | undefined
        let handledWrite: Buffer | undefined
        server.on("requestReceived", (request) => {
            if (request.type === SFTPPacketType.Open) {
                observed = request
                topLevelMutationRejected = !Reflect.set(request, "requestId", 99)
                request.filename.fill(0x78)
                request.attributes.extended![0]!.type.fill(0x78)
                request.attributes.extended![0]!.data.fill(0x78)
            } else if (request.type === SFTPPacketType.Write) {
                request.handle.fill(0x78)
                request.data.fill(0x78)
            }
        })
        server.hooker.hook("OPEN", async (_hook, request) => {
            handledFilename = Buffer.from(request.filename)
            handledAttribute = Buffer.concat([
                request.attributes.extended![0]!.type,
                request.attributes.extended![0]!.data,
            ])
            await server.handle(request.requestId, Buffer.from("handle"))
        })
        server.hooker.hook("WRITE", async (_hook, request) => {
            handledWrite = Buffer.concat([request.handle, request.data])
            await server.status(request.requestId, SFTPStatusCode.Ok)
        })

        fixture.send({ type: SFTPPacketType.Init, version: 3, extensions: [] })
        fixture.send({
            type: SFTPPacketType.Open,
            requestId: 17,
            filename: Buffer.from("authorized.txt"),
            flags: 1,
            attributes: {
                permissions: 0o600,
                extended: [{ type: Buffer.from("policy@test"), data: Buffer.from("allowed") }],
            },
        })
        fixture.send({
            type: SFTPPacketType.Write,
            requestId: 18,
            handle: Buffer.from("handle"),
            offset: 0n,
            data: Buffer.from("file contents"),
        })

        await flush()
        if (!observed || observed.type !== SFTPPacketType.Open) {
            throw new Error("SFTP request observation was not published")
        }
        expect(Object.isFrozen(observed)).toBe(true)
        expect(Object.isFrozen(observed.attributes)).toBe(true)
        expect(Object.isFrozen(observed.attributes.extended)).toBe(true)
        expect(Object.isFrozen(observed.attributes.extended![0])).toBe(true)
        expect(topLevelMutationRejected).toBe(true)
        expect(handledFilename).toEqual(Buffer.from("authorized.txt"))
        expect(handledAttribute).toEqual(Buffer.from("policy@testallowed"))
        expect(handledWrite).toEqual(Buffer.from("handlefile contents"))
        expect(fixture.responses[1]).toEqual({
            type: SFTPPacketType.Handle,
            requestId: 17,
            handle: Buffer.from("handle"),
        })
        expect(fixture.responses[2]).toMatchObject({
            type: SFTPPacketType.Status,
            requestId: 18,
            code: SFTPStatusCode.Ok,
        })
        fixture.destroy()
    })

    test("returns operation unsupported when no request handler exists", async () => {
        const fixture = new SFTPClientFixture()
        new SFTPServer(asShell(fixture))
        fixture.send({ type: SFTPPacketType.Init, version: 3, extensions: [] })
        fixture.send({
            type: SFTPPacketType.Stat,
            requestId: 1,
            path: Buffer.from("missing"),
        })
        await flush()
        expect(fixture.responses[1]).toEqual({
            type: SFTPPacketType.Status,
            requestId: 1,
            code: SFTPStatusCode.OperationUnsupported,
            message: "Operation unsupported",
            languageTag: "",
        })
        fixture.destroy()
    })

    test("allows an extension to define an empty NAME response", async () => {
        const fixture = new SFTPClientFixture()
        const server = new SFTPServer(asShell(fixture))
        server.hooker.hook("EXTENDED", async (_hook, request) => {
            expect(request.request).toBe("empty-names@example.test")
            expect(request.data).toEqual(Buffer.from("query"))
            await server.name(request.requestId, [])
        })

        fixture.send({ type: SFTPPacketType.Init, version: 3, extensions: [] })
        fixture.send({
            type: SFTPPacketType.Extended,
            requestId: 2,
            request: "empty-names@example.test",
            data: Buffer.from("query"),
        })
        await flush()

        expect(fixture.responses[1]).toEqual({
            type: SFTPPacketType.Name,
            requestId: 2,
            names: [],
        })
        fixture.destroy()
    })

    test("awaits a SETSTAT handler with an exact uint64 size", async () => {
        const fixture = new SFTPClientFixture()
        const server = new SFTPServer(asShell(fixture))
        let release!: () => void
        const pending = new Promise<void>((resolve) => {
            release = resolve
        })
        let receivedSize: bigint | undefined
        server.hooker.hook("SETSTAT", async (_hook, request) => {
            receivedSize = request.attributes.size
            await pending
            await server.status(request.requestId, SFTPStatusCode.Ok)
        })

        fixture.send({ type: SFTPPacketType.Init, version: 3, extensions: [] })
        fixture.send({
            type: SFTPPacketType.SetStat,
            requestId: 42,
            path: Buffer.from("large-file"),
            attributes: { size: 4_294_967_297n },
        })
        await flush()
        expect(receivedSize).toBe(4_294_967_297n)
        expect(fixture.responses).toHaveLength(1)

        release()
        await flush()
        expect(fixture.responses[1]).toMatchObject({
            type: SFTPPacketType.Status,
            requestId: 42,
            code: SFTPStatusCode.Ok,
        })
        fixture.destroy()
    })

    test("enforces response type, size, cardinality, and exactly-once rules", async () => {
        const fixture = new SFTPClientFixture()
        const server = new SFTPServer(asShell(fixture))
        let requestId = -1
        let finishRead!: () => void
        const keepHandlerActive = new Promise<void>((resolve) => {
            finishRead = resolve
        })
        server.hooker.hook("READ", async (_hook, request) => {
            requestId = request.requestId
            await keepHandlerActive
        })
        fixture.send({ type: SFTPPacketType.Init, version: 3, extensions: [] })
        fixture.send({
            type: SFTPPacketType.Read,
            requestId: 2,
            handle: Buffer.from("h"),
            offset: 0n,
            length: 2,
        })
        await flush()
        expect(() => server.data(requestId, Buffer.alloc(0))).toThrow("must not be empty")
        expect(() => server.data(requestId, Buffer.from("too long"))).toThrow("exceeds")
        expect(() => server.handle(requestId, Buffer.from("h"))).toThrow("HANDLE")
        expect(() => server.name(requestId, [])).toThrow("at least one")
        expect(() => server.status(requestId, SFTPStatusCode.Ok)).toThrow("data response")
        await server.status(requestId, SFTPStatusCode.Failure, "read failed")
        finishRead()
        await flush()
        expect(() => server.status(requestId, SFTPStatusCode.Failure)).toThrow("not awaiting")
        fixture.destroy()
    })

    test("rejects malformed response buffers without claiming the request", async () => {
        const fixture = new SFTPClientFixture()
        const server = new SFTPServer(asShell(fixture))
        const errors: string[] = []
        const rejectLocally = async (
            requestId: number,
            response: () => Promise<void>,
        ): Promise<void> => {
            try {
                await response()
            } catch (error) {
                errors.push(error instanceof Error ? error.message : String(error))
            }
            await server.status(requestId, SFTPStatusCode.Failure, "invalid local response")
        }
        server.hooker.hook("OPEN", (_hook, request) =>
            rejectLocally(request.requestId, () => server.handle(request.requestId, "h" as never)),
        )
        server.hooker.hook("READ", (_hook, request) =>
            rejectLocally(request.requestId, () => server.data(request.requestId, "x" as never)),
        )
        server.hooker.hook("READDIR", (_hook, request) =>
            rejectLocally(request.requestId, () =>
                server.name(request.requestId, {
                    filename: "entry" as never,
                    longname: Buffer.from("entry"),
                    attributes: {},
                }),
            ),
        )
        server.hooker.hook("STAT", (_hook, request) =>
            rejectLocally(request.requestId, () =>
                server.attributes(request.requestId, {
                    extended: [{ type: "type" as never, data: Buffer.from("data") }],
                }),
            ),
        )
        server.hooker.hook("EXTENDED", (_hook, request) =>
            rejectLocally(request.requestId, () =>
                server.extendedReply(request.requestId, Buffer.alloc(MAX_SFTP_PACKET_LENGTH)),
            ),
        )

        fixture.send({ type: SFTPPacketType.Init, version: 3, extensions: [] })
        fixture.send({
            type: SFTPPacketType.Open,
            requestId: 40,
            filename: Buffer.from("file"),
            flags: 1,
            attributes: {},
        })
        fixture.send({
            type: SFTPPacketType.Read,
            requestId: 41,
            handle: Buffer.from("h"),
            offset: 0n,
            length: 1,
        })
        fixture.send({
            type: SFTPPacketType.ReadDir,
            requestId: 42,
            handle: Buffer.from("h"),
        })
        fixture.send({ type: SFTPPacketType.Stat, requestId: 43, path: Buffer.from("file") })
        fixture.send({
            type: SFTPPacketType.Extended,
            requestId: 44,
            request: "query@example.test",
            data: Buffer.alloc(0),
        })
        await flush()

        expect(errors).toEqual([
            "SFTP response handle must be a buffer",
            "SFTP DATA must be a buffer",
            "SFTP name filename must be a buffer",
            "SFTP extended attribute type must be a buffer",
            `SFTP packet length exceeds ${MAX_SFTP_PACKET_LENGTH} bytes`,
        ])
        expect(
            fixture.responses
                .filter((packet) => packet.type === SFTPPacketType.Status)
                .map((packet) => ({ requestId: packet.requestId, message: packet.message })),
        ).toEqual(
            [40, 41, 42, 43, 44].map((requestId) => ({
                requestId,
                message: "invalid local response",
            })),
        )
        fixture.destroy()
    })

    test("rejects a second response as soon as the first response starts", async () => {
        const fixture = new SFTPClientFixture()
        const server = new SFTPServer(asShell(fixture))
        let firstResponse: Promise<void> | undefined
        let duplicateError: Error | undefined
        server.hooker.hook("STAT", (_hook, request) => {
            firstResponse = server.attributes(request.requestId, { size: 3n })
            try {
                void server.attributes(request.requestId, { size: 4n })
            } catch (error) {
                duplicateError = error instanceof Error ? error : new Error(String(error))
            }
            return firstResponse
        })

        fixture.send({ type: SFTPPacketType.Init, version: 3, extensions: [] })
        await flush()
        fixture.deferWrites = true
        fixture.send({ type: SFTPPacketType.Stat, requestId: 24, path: Buffer.from("one") })
        await flush()

        expect(duplicateError?.message).toBe("SFTP request 24 already has a response")
        expect(fixture.responses.filter((packet) => "requestId" in packet)).toHaveLength(1)
        fixture.releaseWrite()
        await firstResponse
        fixture.destroy()
    })

    test("queues a reused identifier until its previous handler has finished", async () => {
        const fixture = new SFTPClientFixture()
        const server = new SFTPServer(asShell(fixture), { maxConcurrentRequests: 2 })
        let releaseCleanup!: () => void
        const cleanupReleased = new Promise<void>((resolve) => {
            releaseCleanup = resolve
        })
        let reportFirstResponse!: () => void
        const firstResponseWritten = new Promise<void>((resolve) => {
            reportFirstResponse = resolve
        })
        let reportStaleAttempt!: () => void
        const staleAttempted = new Promise<void>((resolve) => {
            reportStaleAttempt = resolve
        })
        let releaseSecond!: () => void
        const secondReleased = new Promise<void>((resolve) => {
            releaseSecond = resolve
        })
        let secondStarted = false
        let thirdStarted = false
        let staleError: Error | undefined
        server.hooker.hook("STAT", async (_hook, request) => {
            const first = request.path.equals(Buffer.from("first"))
            if (first) {
                await server.attributes(request.requestId, { size: 1n })
                reportFirstResponse()
                await cleanupReleased
                try {
                    await server.attributes(request.requestId, { size: 99n })
                } catch (error) {
                    staleError = error instanceof Error ? error : new Error(String(error))
                }
                reportStaleAttempt()
            } else if (request.path.equals(Buffer.from("second"))) {
                secondStarted = true
                await secondReleased
                await server.attributes(request.requestId, { size: 2n })
            } else {
                thirdStarted = true
                await server.attributes(request.requestId, { size: 3n })
            }
        })

        fixture.send({ type: SFTPPacketType.Init, version: 3, extensions: [] })
        fixture.send({ type: SFTPPacketType.Stat, requestId: 30, path: Buffer.from("first") })
        await firstResponseWritten
        fixture.send({ type: SFTPPacketType.Stat, requestId: 30, path: Buffer.from("second") })
        fixture.send({ type: SFTPPacketType.Stat, requestId: 31, path: Buffer.from("third") })
        await flush()

        const startedBeforeCleanup = secondStarted
        const unrelatedStartedBeforeCleanup = thirdStarted
        releaseCleanup()
        await staleAttempted
        await flush()
        const startedAfterCleanup = secondStarted
        releaseSecond()
        await flush()

        expect({
            startedBeforeCleanup,
            unrelatedStartedBeforeCleanup,
            startedAfterCleanup,
            staleError: staleError?.message,
            sizes: fixture.responses
                .filter((packet) => packet.type === SFTPPacketType.Attrs)
                .map((packet) => packet.attributes.size),
        }).toEqual({
            startedBeforeCleanup: false,
            unrelatedStartedBeforeCleanup: true,
            startedAfterCleanup: true,
            staleError: "SFTP request 30 is not awaiting a response",
            sizes: [1n, 3n, 2n],
        })
        fixture.destroy()
    })

    test("normalizes the published OpenSSH symlink argument reversal", () => {
        const standardFixture = new SFTPClientFixture()
        const standard = new SFTPServer(asShell(standardFixture))
        const opensshFixture = new SFTPClientFixture()
        const openssh = new SFTPServer(asShell(opensshFixture), {
            openSSHSymlinkArguments: true,
        })
        const request = {
            type: SFTPPacketType.SymLink as const,
            requestId: 1,
            firstPath: Buffer.from("first"),
            secondPath: Buffer.from("second"),
        }
        const standardPaths = standard.symlinkPaths(request)
        const opensshPaths = openssh.symlinkPaths(request)
        expect(standardPaths).toEqual({
            linkPath: Buffer.from("first"),
            targetPath: Buffer.from("second"),
        })
        expect(opensshPaths).toEqual({
            targetPath: Buffer.from("first"),
            linkPath: Buffer.from("second"),
        })
        standardPaths.linkPath.fill(0x78)
        opensshPaths.targetPath.fill(0x78)
        expect(request).toEqual({
            type: SFTPPacketType.SymLink,
            requestId: 1,
            firstPath: Buffer.from("first"),
            secondPath: Buffer.from("second"),
        })
        standardFixture.destroy()
        opensshFixture.destroy()
    })

    test("closes on duplicate outstanding ids and malformed initialization", async () => {
        const duplicateFixture = new SFTPClientFixture()
        const duplicateServer = new SFTPServer(asShell(duplicateFixture))
        const errors: Error[] = []
        duplicateServer.on("error", (error) => errors.push(error))
        duplicateServer.hooker.hook("READ", () => undefined)
        duplicateFixture.send({ type: SFTPPacketType.Init, version: 3, extensions: [] })
        const read = {
            type: SFTPPacketType.Read as const,
            requestId: 3,
            handle: Buffer.from("h"),
            offset: 0n,
            length: 1,
        }
        duplicateFixture.send(read)
        duplicateFixture.send(read)
        await flush()
        expect(errors.map((error) => error.message)).toEqual([
            "Duplicate outstanding SFTP request id 3",
        ])
        expect(duplicateFixture.destroyed).toBe(true)

        const versionFixture = new SFTPClientFixture()
        const versionServer = new SFTPServer(asShell(versionFixture))
        const versionErrors: Error[] = []
        versionServer.on("error", (error) => versionErrors.push(error))
        versionFixture.send({ type: SFTPPacketType.Init, version: 2, extensions: [] })
        await flush()
        expect(versionErrors[0]?.message).toBe("Unsupported SFTP client version 2")
        expect(versionFixture.destroyed).toBe(true)
    })

    test("bounds the total active and queued request set", async () => {
        const fixture = new SFTPClientFixture()
        const server = new SFTPServer(asShell(fixture), { maxConcurrentRequests: 1 })
        const errors: Error[] = []
        server.on("error", (error) => errors.push(error))
        server.hooker.hook("STAT", async () => new Promise<void>(() => undefined))

        fixture.send({ type: SFTPPacketType.Init, version: 3, extensions: [] })
        for (let requestId = 0; requestId <= 1024; requestId++) {
            fixture.send({
                type: SFTPPacketType.Stat,
                requestId,
                path: Buffer.from("file"),
            })
        }
        await flush()

        expect(errors.map((error) => error.message)).toEqual([
            "SFTP outstanding requests exceed 1024",
        ])
        expect(fixture.destroyed).toBe(true)
    })

    test("awaits handlers and converts rejected or missing responses to failures", async () => {
        const fixture = new SFTPClientFixture()
        const server = new SFTPServer(asShell(fixture))
        const hookErrors: string[] = []
        server.hooker.on("uncaughtException", (_event, error) => hookErrors.push(error.message))
        server.hooker.hook("STAT", async () => {
            await Promise.resolve()
            throw new Error("stat backend failed")
        })
        server.hooker.hook("LSTAT", async () => {
            await Promise.resolve()
        })

        fixture.send({ type: SFTPPacketType.Init, version: 3, extensions: [] })
        fixture.send({ type: SFTPPacketType.Stat, requestId: 4, path: Buffer.from("one") })
        fixture.send({ type: SFTPPacketType.LStat, requestId: 5, path: Buffer.from("two") })
        await flush()

        expect(hookErrors).toEqual(["stat backend failed"])
        expect(
            fixture.responses
                .slice(1)
                .toSorted((left, right) =>
                    "requestId" in left && "requestId" in right
                        ? left.requestId - right.requestId
                        : 0,
                ),
        ).toEqual([
            {
                type: SFTPPacketType.Status,
                requestId: 4,
                code: SFTPStatusCode.Failure,
                message: "SFTP request handler failed",
                languageTag: "",
            },
            {
                type: SFTPPacketType.Status,
                requestId: 5,
                code: SFTPStatusCode.Failure,
                message: "SFTP request handler returned without a response",
                languageTag: "",
            },
        ])
        fixture.destroy()
    })
})
