import { describe, expect, test } from "bun:test"
import { Duplex } from "node:stream"
import type Shell from "../../src/channels/Session/Shell.js"
import { decodeSFTPPacket, encodeSFTPPacket } from "../../src/sftp/codec.js"
import SFTPServer from "../../src/sftp/SFTPServer.js"
import { SFTPPacketType, SFTPStatusCode } from "../../src/sftp/constants.js"
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

    test("owns advertised extension metadata before the version exchange", async () => {
        const fixture = new SFTPClientFixture()
        const data = Buffer.from("1")
        const extensions = [{ name: "x@test", data }]
        new SFTPServer(asShell(fixture), { extensions })

        extensions[0]!.name = "changed@test"
        data[0] = 0x32
        extensions.push({ name: "added@test", data: Buffer.from("3") })
        fixture.send({ type: SFTPPacketType.Init, version: 3, extensions: [] })
        await flush()

        expect(fixture.responses).toEqual([
            {
                type: SFTPPacketType.Version,
                version: 3,
                extensions: [{ name: "x@test", data: Buffer.from("1") }],
            },
        ])
        fixture.destroy()
    })

    test("negotiates v3 and serializes requests until each has one response", async () => {
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
                extensions: [{ name: "x@test", data: Buffer.from("1") }],
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
            handle: Buffer.from("h"),
            offset: 3n,
            data: Buffer.from("def"),
        })
        await flush()
        expect(events).toEqual(["READ"])
        finishRead()
        await flush()
        expect(events).toEqual(["READ", "WRITE"])
        expect(fixture.responses.slice(1)).toEqual([
            { type: SFTPPacketType.Data, requestId: 7, data: Buffer.from("abc") },
            {
                type: SFTPPacketType.Status,
                requestId: 8,
                code: SFTPStatusCode.Ok,
                message: "No error",
                languageTag: "",
            },
        ])
        fixture.destroy()
    })

    test("awaits response writes before resolving handlers or dispatching the next request", async () => {
        const fixture = new SFTPClientFixture()
        const server = new SFTPServer(asShell(fixture))
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
        expect(() => server.data(requestId, Buffer.from("too long"))).toThrow("exceeds")
        expect(() => server.handle(requestId, Buffer.from("h"))).toThrow("HANDLE")
        expect(() => server.name(requestId, [])).toThrow("at least one")
        expect(() => server.status(requestId, SFTPStatusCode.Ok)).toThrow("data response")
        await server.status(requestId, SFTPStatusCode.Failure, "read failed")
        finishRead()
        expect(() => server.status(requestId, SFTPStatusCode.Failure)).toThrow("not awaiting")
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
        expect(standard.symlinkPaths(request)).toEqual({
            linkPath: Buffer.from("first"),
            targetPath: Buffer.from("second"),
        })
        expect(openssh.symlinkPaths(request)).toEqual({
            targetPath: Buffer.from("first"),
            linkPath: Buffer.from("second"),
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
        expect(fixture.responses.slice(1)).toEqual([
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
