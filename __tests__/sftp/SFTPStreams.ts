import { describe, expect, test } from "bun:test"
import { once } from "node:events"
import type SFTPClient from "../../src/sftp/SFTPClient.js"
import { SFTPStatusCode } from "../../src/sftp/constants.js"
import { SFTPReadStream, SFTPWriteStream } from "../../src/sftp/streams.js"
import type { SFTPAttributes } from "../../src/sftp/types.js"

class StreamSFTPFixture {
    readonly maxReadLength = 4
    readonly files = new Map<string, Buffer>([
        ["source", Buffer.from("abcdefghijklmnopqrstuvwxyz")],
    ])
    readonly reads: { length: number; offset: bigint }[] = []
    readonly writes: { data: Buffer; offset: bigint }[] = []
    beforeOpen: Promise<void> = Promise.resolve()
    closeCount = 0

    async open(path: string | Buffer, flags: string | number): Promise<Buffer> {
        await this.beforeOpen
        const name = path.toString()
        if (typeof flags === "string" && flags.includes("w")) this.files.set(name, Buffer.alloc(0))
        this.files.set(name, this.files.get(name) ?? Buffer.alloc(0))
        return Buffer.from(name)
    }

    async read(handle: Buffer, length: number, offset: bigint): Promise<Buffer> {
        this.reads.push({ length, offset })
        const file = this.files.get(handle.toString())!
        const position = Number(offset)
        if (position >= file.length) throw { code: SFTPStatusCode.EOF }
        return file.subarray(position, position + Math.min(length, 3))
    }

    async write(handle: Buffer, data: Buffer, offset: bigint): Promise<void> {
        this.writes.push({ data: Buffer.from(data), offset })
        const name = handle.toString()
        const file = this.files.get(name)!
        const position = Number(offset)
        const next = Buffer.alloc(Math.max(file.length, position + data.length))
        file.copy(next)
        data.copy(next, position)
        this.files.set(name, next)
    }

    async fstat(handle: Buffer): Promise<SFTPAttributes> {
        return { size: BigInt(this.files.get(handle.toString())!.length) }
    }

    async close(): Promise<void> {
        this.closeCount++
    }
}

function asSFTP(fixture: StreamSFTPFixture): SFTPClient {
    return fixture as unknown as SFTPClient
}

describe("SFTP streams", () => {
    test("reads an inclusive range with short replies and closes exactly once", async () => {
        const fixture = new StreamSFTPFixture()
        const stream = new SFTPReadStream(asSFTP(fixture), "source", {
            start: 2n,
            end: 8n,
            highWaterMark: 4,
        })
        const closed = once(stream, "close")
        const chunks: Buffer[] = []
        for await (const chunk of stream) chunks.push(chunk as Buffer)
        await closed

        expect(Buffer.concat(chunks).toString()).toBe("cdefghi")
        expect(stream.bytesRead).toBe(7n)
        expect(fixture.reads).toEqual([
            { length: 4, offset: 2n },
            { length: 4, offset: 5n },
            { length: 1, offset: 8n },
        ])
        expect(fixture.closeCount).toBe(1)
        expect(stream.isClosed).toBe(true)
    })

    test("keeps a supplied read handle open when autoClose is false", async () => {
        const fixture = new StreamSFTPFixture()
        const handle = Buffer.from("source")
        const expectedHandle = Buffer.from(handle)
        const stream = new SFTPReadStream(asSFTP(fixture), "ignored", {
            handle,
            autoClose: false,
            start: 24,
        })
        handle.fill(0x78)
        const chunks: Buffer[] = []
        for await (const chunk of stream) chunks.push(chunk as Buffer)

        expect(Buffer.concat(chunks).toString()).toBe("yz")
        expect(stream.handle).not.toBe(handle)
        expect(stream.handle).toEqual(expectedHandle)
        expect(stream.destroyed).toBe(false)
        expect(fixture.closeCount).toBe(0)
    })

    test("owns a buffered path before an asynchronous open", async () => {
        const fixture = new StreamSFTPFixture()
        let continueOpen!: () => void
        fixture.beforeOpen = new Promise<void>((resolve) => {
            continueOpen = resolve
        })
        const path = Buffer.from("source")
        const expectedPath = Buffer.from(path)
        const stream = new SFTPReadStream(asSFTP(fixture), path, { start: 24 })

        path.fill(0x78)
        continueOpen()
        const chunks: Buffer[] = []
        for await (const chunk of stream) chunks.push(chunk as Buffer)

        expect(Buffer.concat(chunks).toString()).toBe("yz")
        expect(stream.path).not.toBe(path)
        expect(stream.path).toEqual(expectedPath)
    })

    test("does not expose its live read handle through the open event", async () => {
        const fixture = new StreamSFTPFixture()
        const stream = new SFTPReadStream(asSFTP(fixture), "source", {
            start: 24,
            autoClose: false,
        })
        stream.once("open", (handle: Buffer) => handle.fill(0x78))
        const chunks: Buffer[] = []
        for await (const chunk of stream) chunks.push(chunk as Buffer)

        expect(Buffer.concat(chunks).toString()).toBe("yz")
        expect(stream.handle).toEqual(Buffer.from("source"))
        await stream.close()
    })

    test("explicitly closes a read handle after the stream was destroyed", async () => {
        const fixture = new StreamSFTPFixture()
        const stream = new SFTPReadStream(asSFTP(fixture), "ignored", {
            handle: Buffer.from("source"),
            autoClose: false,
        })
        stream.destroy()
        await once(stream, "close")

        const outcome = await Promise.race([
            stream.close().then(() => "closed"),
            new Promise<string>((resolve) => setTimeout(() => resolve("timed out"), 50)),
        ])

        expect(outcome).toBe("closed")
        expect(fixture.closeCount).toBe(1)
        expect(stream.isClosed).toBe(true)
    })

    test("serializes writes, honors append offsets, and supports explicit close", async () => {
        const fixture = new StreamSFTPFixture()
        fixture.files.set("destination", Buffer.from("prefix:"))
        const stream = new SFTPWriteStream(asSFTP(fixture), "destination", {
            flags: "a",
            autoClose: false,
        })
        await once(stream, "ready")
        stream.write("one")
        stream.write(Buffer.from("-two"))
        await stream.close()

        expect(fixture.files.get("destination")!.toString()).toBe("prefix:one-two")
        expect(fixture.writes).toEqual([
            { data: Buffer.from("one"), offset: 7n },
            { data: Buffer.from("-two"), offset: 10n },
        ])
        expect(stream.bytesWritten).toBe(7n)
        expect(fixture.closeCount).toBe(1)
    })

    test("owns a supplied write handle", async () => {
        const fixture = new StreamSFTPFixture()
        fixture.files.set("destination", Buffer.alloc(0))
        const handle = Buffer.from("destination")
        const expectedHandle = Buffer.from(handle)
        const stream = new SFTPWriteStream(asSFTP(fixture), "ignored", {
            handle,
            autoClose: false,
        })

        handle.fill(0x78)
        const finished = once(stream, "finish")
        stream.end("payload")
        await finished

        expect(fixture.files.get("destination")!.toString()).toBe("payload")
        expect(stream.handle).not.toBe(handle)
        expect(stream.handle).toEqual(expectedHandle)
        stream.destroy()
        await once(stream, "close")
    })

    test("owns a buffered write path and does not expose its live opened handle", async () => {
        const fixture = new StreamSFTPFixture()
        let continueOpen!: () => void
        fixture.beforeOpen = new Promise<void>((resolve) => {
            continueOpen = resolve
        })
        const path = Buffer.from("destination")
        const expectedPath = Buffer.from(path)
        const stream = new SFTPWriteStream(asSFTP(fixture), path, { autoClose: false })
        stream.once("open", (handle: Buffer) => handle.fill(0x78))

        path.fill(0x78)
        continueOpen()
        const finished = once(stream, "finish")
        stream.end("payload")
        await finished

        expect(fixture.files.get("destination")!.toString()).toBe("payload")
        expect(stream.path).not.toBe(path)
        expect(stream.path).toEqual(expectedPath)
        expect(stream.handle).toEqual(Buffer.from("destination"))
        stream.destroy()
        await once(stream, "close")
    })

    test("explicitly closes a write handle after the stream was destroyed", async () => {
        const fixture = new StreamSFTPFixture()
        const stream = new SFTPWriteStream(asSFTP(fixture), "ignored", {
            handle: Buffer.from("destination"),
            autoClose: false,
        })
        stream.destroy()
        await once(stream, "close")

        const outcome = await Promise.race([
            stream.close().then(() => "closed"),
            new Promise<string>((resolve) => setTimeout(() => resolve("timed out"), 50)),
        ])

        expect(outcome).toBe("closed")
        expect(fixture.closeCount).toBe(1)
        expect(stream.isClosed).toBe(true)
    })

    test("rejects invalid ranges before opening a remote handle", () => {
        const fixture = new StreamSFTPFixture()
        expect(() => new SFTPReadStream(asSFTP(fixture), "source", { start: 5, end: 4 })).toThrow(
            "start must not exceed end",
        )
        expect(() => new SFTPWriteStream(asSFTP(fixture), "destination", { start: -1 })).toThrow(
            "must be a uint64",
        )
    })

    test("rejects invalid paths and supplied handles at construction", () => {
        const fixture = new StreamSFTPFixture()
        expect(() => new SFTPReadStream(asSFTP(fixture), 42 as never)).toThrow(
            "path must be a string or buffer",
        )
        expect(
            () =>
                new SFTPReadStream(asSFTP(fixture), "source", {
                    handle: "source" as never,
                }),
        ).toThrow("handle must be a buffer")
        expect(
            () =>
                new SFTPWriteStream(asSFTP(fixture), "destination", {
                    handle: Buffer.alloc(257),
                }),
        ).toThrow("handle must not exceed 256 bytes")
    })
})
