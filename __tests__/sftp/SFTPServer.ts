import { describe, expect, test } from "bun:test"
import { Duplex } from "node:stream"
import type Shell from "../../src/channels/Session/Shell.js"
import { decodeSFTPPacket, encodeSFTPPacket } from "../../src/sftp/codec.js"
import SFTPServer from "../../src/sftp/SFTPServer.js"
import { SFTPPacketType, SFTPStatusCode } from "../../src/sftp/constants.js"
import type { SFTPPacket } from "../../src/sftp/types.js"

class SFTPClientFixture extends Duplex {
    readonly responses: SFTPPacket[] = []

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
            callback()
        } catch (error) {
            callback(error instanceof Error ? error : new Error(String(error)))
        }
    }

    send(packet: SFTPPacket): void {
        this.push(encodeSFTPPacket(packet))
    }
}

function asShell(client: SFTPClientFixture): Shell {
    return client as unknown as Shell
}

const flush = (): Promise<void> => new Promise((resolve) => setImmediate(resolve))

describe("SFTP server request engine", () => {
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
            server.data(request.requestId, Buffer.from("abc"))
        })
        server.hooker.hook("WRITE", async (_hook, request) => {
            await Promise.resolve()
            events.push("WRITE")
            server.status(request.requestId, SFTPStatusCode.Ok)
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
            server.status(request.requestId, SFTPStatusCode.Ok)
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
        server.status(requestId, SFTPStatusCode.Failure, "read failed")
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
