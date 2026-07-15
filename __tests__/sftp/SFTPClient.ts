import { describe, expect, test } from "bun:test"
import { Duplex } from "node:stream"
import type ClientSessionChannel from "../../src/channels/ClientSessionChannel.js"
import { decodeSFTPPacket, encodeSFTPPacket } from "../../src/sftp/codec.js"
import SFTPClient, { SFTPStatusError, sftpOpenFlags } from "../../src/sftp/SFTPClient.js"
import {
    SFTP_VERSION,
    SFTPOpenFlags,
    SFTPPacketType,
    SFTPStatusCode,
} from "../../src/sftp/constants.js"
import type { SFTPPacket } from "../../src/sftp/types.js"

class SFTPServerFixture extends Duplex {
    constructor(private readonly receivePacket: (packet: SFTPPacket) => void) {
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
            this.receivePacket(decodeSFTPPacket(chunk))
            callback()
        } catch (error) {
            callback(error instanceof Error ? error : new Error(String(error)))
        }
    }

    send(packet: SFTPPacket): void {
        this.push(encodeSFTPPacket(packet))
    }
}

class BlockedSFTPChannel extends Duplex {
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

describe("SFTP client request engine", () => {
    test("validates a finite positive request timeout before initialization", async () => {
        for (const requestTimeout of [null, 0, -1, Number.NaN, Number.POSITIVE_INFINITY]) {
            const fixture = new SFTPServerFixture(() => undefined)
            await expect(
                SFTPClient.connect(asClientChannel(fixture), false, {
                    requestTimeout: requestTimeout as number,
                }),
            ).rejects.toThrow("SFTP request timeout must be a positive number")
            fixture.destroy()
        }
        const fixture = new SFTPServerFixture(() => undefined)
        await expect(
            SFTPClient.connect(asClientChannel(fixture), false, null as never),
        ).rejects.toThrow("SFTP client options must be an object")
        fixture.destroy()
        const flagFixture = new SFTPServerFixture(() => undefined)
        await expect(
            SFTPClient.connect(asClientChannel(flagFixture), null as never),
        ).rejects.toThrow("SFTP OpenSSH compatibility flag must be a boolean")
        flagFixture.destroy()
    })

    test("closes a session that does not answer initialization", async () => {
        const fixture = new SFTPServerFixture(() => undefined)

        await expect(
            SFTPClient.connect(asClientChannel(fixture), false, { requestTimeout: 20 }),
        ).rejects.toThrow("Timed out waiting for SFTP initialization")
        expect(fixture.destroyed).toBe(true)
    })

    test("bounds an initialization frame blocked by channel flow control", async () => {
        const channel = new BlockedSFTPChannel()

        await expect(
            SFTPClient.connect(asClientChannel(channel), false, {
                requestTimeout: 20,
            }),
        ).rejects.toThrow("Timed out waiting for SFTP initialization")
        expect(channel.destroyed).toBe(true)
    })

    test("closes a session that does not answer a tagged request", async () => {
        const fixture = new SFTPServerFixture((packet) => {
            if (packet.type === SFTPPacketType.Init) {
                fixture.send({ type: SFTPPacketType.Version, version: 3, extensions: [] })
            }
        })
        const client = await SFTPClient.connect(asClientChannel(fixture), false, {
            requestTimeout: 20,
        })

        await expect(client.stat("unanswered")).rejects.toThrow(
            "Timed out waiting for SFTP request 0 reply",
        )
        expect(fixture.destroyed).toBe(true)
    })

    test("an explicit abort rejects every pending request with its cause", async () => {
        const fixture = new SFTPServerFixture((packet) => {
            if (packet.type === SFTPPacketType.Init) {
                fixture.send({ type: SFTPPacketType.Version, version: 3, extensions: [] })
            }
        })
        const client = await SFTPClient.connect(asClientChannel(fixture))
        const requests = [client.stat("pending"), client.open("pending", "r")]
        const cause = new Error("application aborted SFTP")

        client.destroy(cause)
        const results = await Promise.allSettled(requests)

        expect(
            results.map((result) => ({
                status: result.status,
                sameCause: result.status === "rejected" && result.reason === cause,
            })),
        ).toEqual([
            { status: "rejected", sameCause: true },
            { status: "rejected", sameCause: true },
        ])
        await expect(client.stat("after-abort")).rejects.toThrow("SFTP session is closed")
        expect(fixture.destroyed).toBe(true)
    })

    test("rejects an invalid write limit before sending a request", async () => {
        let writeRequests = 0
        const fixture = new SFTPServerFixture((packet) => {
            if (packet.type === SFTPPacketType.Init) {
                fixture.send({ type: SFTPPacketType.Version, version: 3, extensions: [] })
            } else if (packet.type === SFTPPacketType.Write) {
                writeRequests++
                fixture.send({
                    type: SFTPPacketType.Status,
                    requestId: packet.requestId,
                    code: SFTPStatusCode.Failure,
                    message: "write reached server",
                    languageTag: "",
                })
            }
        })

        const client = await SFTPClient.connect(asClientChannel(fixture))
        client.maxWriteLength = 0
        let error: unknown
        try {
            await client.write(Buffer.from("handle"), Buffer.from("data"), 0)
        } catch (caught) {
            error = caught
        }

        expect({
            error: error instanceof Error ? `${error.name}: ${error.message}` : error,
            writeRequests,
        }).toEqual({
            error: "RangeError: SFTP maximum write length must be a positive safe integer",
            writeRequests: 0,
        })
        fixture.destroy()
    })

    test("rejects an invalid fast-transfer limit before opening the remote file", async () => {
        const requests: SFTPPacketType[] = []
        const fixture = new SFTPServerFixture((packet) => {
            if (packet.type === SFTPPacketType.Init) {
                fixture.send({ type: SFTPPacketType.Version, version: 3, extensions: [] })
                return
            }
            requests.push(packet.type)
            if (packet.type === SFTPPacketType.Stat) {
                fixture.send({
                    type: SFTPPacketType.Attrs,
                    requestId: packet.requestId,
                    attributes: { size: 4n },
                })
            } else if (packet.type === SFTPPacketType.Open) {
                fixture.send({
                    type: SFTPPacketType.Handle,
                    requestId: packet.requestId,
                    handle: Buffer.from("handle"),
                })
            } else if (packet.type === SFTPPacketType.Close) {
                fixture.send({
                    type: SFTPPacketType.Status,
                    requestId: packet.requestId,
                    code: SFTPStatusCode.Ok,
                    message: "",
                    languageTag: "",
                })
            }
        })

        const client = await SFTPClient.connect(asClientChannel(fixture))
        client.maxReadLength = 0
        let error: unknown
        try {
            await client.fastGet("remote", "")
        } catch (caught) {
            error = caught
        }

        expect({
            error: error instanceof Error ? `${error.name}: ${error.message}` : error,
            requests,
        }).toEqual({
            error: "RangeError: SFTP maximum transfer length must be a positive safe integer",
            requests: [SFTPPacketType.Stat],
        })
        fixture.destroy()
    })

    test("rejects an invalid read limit instead of truncating readFile", async () => {
        const requests: SFTPPacketType[] = []
        const fixture = new SFTPServerFixture((packet) => {
            if (packet.type === SFTPPacketType.Init) {
                fixture.send({ type: SFTPPacketType.Version, version: 3, extensions: [] })
                return
            }
            requests.push(packet.type)
            if (packet.type === SFTPPacketType.Open) {
                fixture.send({
                    type: SFTPPacketType.Handle,
                    requestId: packet.requestId,
                    handle: Buffer.from("handle"),
                })
            } else if (packet.type === SFTPPacketType.FStat) {
                fixture.send({
                    type: SFTPPacketType.Attrs,
                    requestId: packet.requestId,
                    attributes: { size: 4n },
                })
            } else if (packet.type === SFTPPacketType.Close) {
                fixture.send({
                    type: SFTPPacketType.Status,
                    requestId: packet.requestId,
                    code: SFTPStatusCode.Ok,
                    message: "",
                    languageTag: "",
                })
            }
        })

        const client = await SFTPClient.connect(asClientChannel(fixture))
        client.maxReadLength = 0
        let contents: Buffer | undefined
        let error: unknown
        try {
            contents = await client.readFile("remote")
        } catch (caught) {
            error = caught
        }

        expect({
            contents,
            error: error instanceof Error ? `${error.name}: ${error.message}` : error,
            requests,
        }).toEqual({
            contents: undefined,
            error: "RangeError: SFTP maximum read length must be a positive safe integer",
            requests: [SFTPPacketType.Open, SFTPPacketType.FStat, SFTPPacketType.Close],
        })
        fixture.destroy()
    })

    test("encoding failures do not exhaust pending request slots", async () => {
        const requests: SFTPPacketType[] = []
        const fixture = new SFTPServerFixture((packet) => {
            if (packet.type === SFTPPacketType.Init) {
                fixture.send({ type: SFTPPacketType.Version, version: 3, extensions: [] })
                return
            }
            requests.push(packet.type)
            if (packet.type === SFTPPacketType.Stat) {
                fixture.send({
                    type: SFTPPacketType.Attrs,
                    requestId: packet.requestId,
                    attributes: { size: 1n },
                })
            }
        })

        const client = await SFTPClient.connect(asClientChannel(fixture))
        const invalidHandle = Buffer.alloc(257)
        let expectedFailures = 0
        for (let attempt = 0; attempt < 1024; attempt++) {
            try {
                await client.close(invalidHandle)
            } catch (error) {
                if (error instanceof Error && error.message === "SFTP handle exceeds 256 bytes") {
                    expectedFailures++
                }
            }
        }
        let size: bigint | undefined
        let statError: unknown
        try {
            size = (await client.stat("remote")).size
        } catch (error) {
            statError = error
        }

        expect({
            expectedFailures,
            requests,
            size,
            statError: statError instanceof Error ? statError.message : statError,
        }).toEqual({
            expectedFailures: 1024,
            requests: [SFTPPacketType.Stat],
            size: 1n,
            statError: undefined,
        })
        fixture.destroy()
    })

    test("validates every handle boundary even when an operation emits no packet", async () => {
        const requests: SFTPPacketType[] = []
        const fixture = new SFTPServerFixture((packet) => {
            if (packet.type === SFTPPacketType.Init) {
                fixture.send({
                    type: SFTPPacketType.Version,
                    version: 3,
                    extensions: [
                        { name: "fstatvfs@openssh.com", data: Buffer.from("2") },
                        { name: "fsync@openssh.com", data: Buffer.from("1") },
                        { name: "copy-data", data: Buffer.from("1") },
                    ],
                })
                return
            }
            requests.push(packet.type)
            if ("requestId" in packet) {
                fixture.send({
                    type: SFTPPacketType.Status,
                    requestId: packet.requestId,
                    code: SFTPStatusCode.Ok,
                    message: "",
                    languageTag: "",
                })
            }
        })
        const client = await SFTPClient.connect(asClientChannel(fixture))
        const oversized = Buffer.alloc(257)
        const valid = Buffer.from("handle")
        const operations: readonly [string, () => Promise<unknown>][] = [
            ["close", () => client.close(oversized)],
            ["zero-length read", () => client.read(oversized, 0, 0)],
            ["empty write", () => client.write(oversized, Buffer.alloc(0), 0)],
            ["fstat", () => client.fstat(oversized)],
            ["fsetstat", () => client.fsetstat(oversized, {})],
            ["ftruncate", () => client.ftruncate(oversized, 0)],
            ["readdir", () => client.readdir(oversized)],
            ["fchmod", () => client.fchmod(oversized, 0o600)],
            ["fchown", () => client.fchown(oversized, 1, 2)],
            ["futimes", () => client.futimes(oversized, 1, 2)],
            ["fstatvfs", () => client.opensshFStatVFS(oversized)],
            ["fsync", () => client.opensshFSync(oversized)],
            ["copy-data source", () => client.copyData(oversized, 0, 0, valid, 0)],
            ["copy-data destination", () => client.copyData(valid, 0, 0, oversized, 0)],
        ]
        const outcomes: Record<string, string | undefined> = {}
        for (const [name, operation] of operations) {
            try {
                await operation()
            } catch (error) {
                outcomes[name] = error instanceof Error ? error.message : String(error)
            }
        }
        try {
            await client.close("handle" as never)
        } catch (error) {
            outcomes["non-buffer handle"] = error instanceof Error ? error.message : String(error)
        }
        try {
            await client.write(valid, "data" as never, 0)
        } catch (error) {
            outcomes["non-buffer data"] = error instanceof Error ? error.message : String(error)
        }
        try {
            await client.read(valid, 0, -1)
        } catch (error) {
            outcomes["zero-length read position"] =
                error instanceof Error ? error.message : String(error)
        }

        expect(outcomes).toEqual({
            close: "SFTP handle exceeds 256 bytes",
            "zero-length read": "SFTP handle exceeds 256 bytes",
            "empty write": "SFTP handle exceeds 256 bytes",
            fstat: "SFTP handle exceeds 256 bytes",
            fsetstat: "SFTP handle exceeds 256 bytes",
            ftruncate: "SFTP handle exceeds 256 bytes",
            readdir: "SFTP handle exceeds 256 bytes",
            fchmod: "SFTP handle exceeds 256 bytes",
            fchown: "SFTP handle exceeds 256 bytes",
            futimes: "SFTP handle exceeds 256 bytes",
            fstatvfs: "SFTP handle exceeds 256 bytes",
            fsync: "SFTP handle exceeds 256 bytes",
            "copy-data source": "SFTP handle exceeds 256 bytes",
            "copy-data destination": "SFTP handle exceeds 256 bytes",
            "non-buffer handle": "SFTP handle must be a buffer",
            "non-buffer data": "SFTP write data must be a buffer",
            "zero-length read position":
                "Numeric SFTP position must be a non-negative safe integer",
        })
        expect(requests).toEqual([])
        fixture.destroy()
    })

    test("rejects invalid UTF-8 string paths before writing a request", async () => {
        let requests = 0
        const fixture = new SFTPServerFixture((packet) => {
            if (packet.type === SFTPPacketType.Init) {
                fixture.send({ type: SFTPPacketType.Version, version: 3, extensions: [] })
            } else {
                requests++
            }
        })

        const client = await SFTPClient.connect(asClientChannel(fixture))
        await expect(client.stat("\ud800")).rejects.toThrow("SFTP path is not valid UTF-8 text")
        expect(requests).toBe(0)
        fixture.destroy()
    })

    test("sends negotiated application extensions with explicit response contracts", async () => {
        const requests: { name: string; data: Buffer }[] = []
        const fixture = new SFTPServerFixture((packet) => {
            if (packet.type === SFTPPacketType.Init) {
                fixture.send({
                    type: SFTPPacketType.Version,
                    version: 3,
                    extensions: [{ name: "query@example.test", data: Buffer.from("2") }],
                })
                return
            }
            if (packet.type !== SFTPPacketType.Extended) return
            requests.push({ name: packet.request, data: Buffer.from(packet.data) })
            if (requests.length === 1) {
                fixture.send({
                    type: SFTPPacketType.ExtendedReply,
                    requestId: packet.requestId,
                    data: Buffer.from("answer"),
                })
            } else {
                fixture.send({
                    type: SFTPPacketType.Status,
                    requestId: packet.requestId,
                    code: SFTPStatusCode.Ok,
                    message: "",
                    languageTag: "",
                })
            }
        })

        const client = await SFTPClient.connect(asClientChannel(fixture))
        const requestData = Buffer.from("question")
        const replyPromise = client.extended("query@example.test", requestData, { version: "2" })
        requestData.fill(0)
        const reply = await replyPromise
        expect(reply).toMatchObject({
            type: SFTPPacketType.ExtendedReply,
            data: Buffer.from("answer"),
        })
        const status = await client.extended("query@example.test", Buffer.from("notify"), {
            expectedTypes: [SFTPPacketType.Status],
        })
        expect(status.type).toBe(SFTPPacketType.Status)
        expect(requests).toEqual([
            { name: "query@example.test", data: Buffer.from("question") },
            { name: "query@example.test", data: Buffer.from("notify") },
        ])
        await expect(client.extended("missing@example.test")).rejects.toThrow(
            "does not advertise missing@example.test",
        )
        await expect(
            client.extended("query@example.test", Buffer.alloc(0), { version: "1" }),
        ).rejects.toThrow("does not advertise query@example.test version 1")
        await expect(
            client.extended("query@example.test", Buffer.alloc(0), { expectedTypes: [] }),
        ).rejects.toThrow("at least one response type")
        expect(requests).toHaveLength(2)
        await expect(client.extended("query@example.test")).rejects.toThrow(
            "successful STATUS instead of response data",
        )
        expect(fixture.destroyed).toBe(true)
    })

    test("provides whole-file helpers without leaking handles on success or limits", async () => {
        const files = new Map<string, Buffer>()
        const openHandles = new Set<string>()
        const status = (requestId: number, code = SFTPStatusCode.Ok): void => {
            fixture.send({
                type: SFTPPacketType.Status,
                requestId,
                code,
                message: "",
                languageTag: "",
            })
        }
        const fixture = new SFTPServerFixture((packet) => {
            if (packet.type === SFTPPacketType.Init) {
                fixture.send({ type: SFTPPacketType.Version, version: 3, extensions: [] })
            } else if (packet.type === SFTPPacketType.Open) {
                const path = packet.filename.toString()
                if ((packet.flags & SFTPOpenFlags.Truncate) !== 0) files.set(path, Buffer.alloc(0))
                if (!files.has(path) && (packet.flags & SFTPOpenFlags.Create) === 0) {
                    status(packet.requestId, SFTPStatusCode.NoSuchFile)
                    return
                }
                files.set(path, files.get(path) ?? Buffer.alloc(0))
                openHandles.add(path)
                fixture.send({
                    type: SFTPPacketType.Handle,
                    requestId: packet.requestId,
                    handle: Buffer.from(path),
                })
            } else if (packet.type === SFTPPacketType.FStat) {
                const file = files.get(packet.handle.toString())!
                fixture.send({
                    type: SFTPPacketType.Attrs,
                    requestId: packet.requestId,
                    attributes: { size: BigInt(file.length) },
                })
            } else if (packet.type === SFTPPacketType.Read) {
                const file = files.get(packet.handle.toString())!
                const offset = Number(packet.offset)
                if (offset >= file.length) status(packet.requestId, SFTPStatusCode.EOF)
                else {
                    fixture.send({
                        type: SFTPPacketType.Data,
                        requestId: packet.requestId,
                        data: file.subarray(offset, offset + Math.min(packet.length, 2)),
                    })
                }
            } else if (packet.type === SFTPPacketType.Write) {
                const path = packet.handle.toString()
                const current = files.get(path)!
                const offset = Number(packet.offset)
                const next = Buffer.alloc(Math.max(current.length, offset + packet.data.length))
                current.copy(next)
                packet.data.copy(next, offset)
                files.set(path, next)
                status(packet.requestId)
            } else if (packet.type === SFTPPacketType.Close) {
                openHandles.delete(packet.handle.toString())
                status(packet.requestId)
            } else if (packet.type === SFTPPacketType.Stat) {
                const file = files.get(packet.path.toString())
                if (file === undefined) status(packet.requestId, SFTPStatusCode.NoSuchFile)
                else {
                    fixture.send({
                        type: SFTPPacketType.Attrs,
                        requestId: packet.requestId,
                        attributes: { size: BigInt(file.length) },
                    })
                }
            }
        })

        const client = await SFTPClient.connect(asClientChannel(fixture))
        await client.writeFile("notes", "alpha")
        await client.appendFile("notes", "-beta")
        expect(await client.readFile("notes", "utf8")).toBe("alpha-beta")
        expect(await client.exists("notes")).toBe(true)
        expect(await client.exists("missing")).toBe(false)
        await expect(client.readFile("notes", { maxBytes: 5 })).rejects.toThrow(
            "exceeds the 5-byte read limit",
        )
        expect(openHandles.size).toBe(0)
        fixture.destroy()
    })

    test("negotiates advertised OpenSSH limits from a literal extension payload", async () => {
        const fixture = new SFTPServerFixture((packet) => {
            if (packet.type === SFTPPacketType.Init) {
                fixture.send({
                    type: SFTPPacketType.Version,
                    version: 3,
                    extensions: [{ name: "limits@openssh.com", data: Buffer.from("1", "ascii") }],
                })
            } else if (packet.type === SFTPPacketType.Extended) {
                expect(packet.request).toBe("limits@openssh.com")
                expect(packet.data).toEqual(Buffer.alloc(0))
                fixture.send({
                    type: SFTPPacketType.ExtendedReply,
                    requestId: packet.requestId,
                    data: Buffer.from(
                        "0000000000040000000000000002000000000000000100000000000000000000",
                        "hex",
                    ),
                })
            }
        })

        const client = await SFTPClient.connect(asClientChannel(fixture))
        expect(client.limits).toEqual({
            maximumPacketLength: 262144n,
            maximumReadLength: 131072n,
            maximumWriteLength: 65536n,
            maximumOpenHandles: 0n,
        })
        expect(client.maxReadLength).toBe(131072)
        expect(client.maxWriteLength).toBe(65536)
        expect(client.maxOpenHandles).toBe(Number.POSITIVE_INFINITY)
        fixture.destroy()
    })

    test("does not exceed the advertised active-handle limit", async () => {
        const openedPaths: string[] = []
        let firstRequestId: number | undefined
        const fixture = new SFTPServerFixture((packet) => {
            if (packet.type === SFTPPacketType.Init) {
                fixture.send({
                    type: SFTPPacketType.Version,
                    version: 3,
                    extensions: [{ name: "limits@openssh.com", data: Buffer.from("1") }],
                })
            } else if (packet.type === SFTPPacketType.Extended) {
                fixture.send({
                    type: SFTPPacketType.ExtendedReply,
                    requestId: packet.requestId,
                    data: Buffer.from(
                        "0000000000000000000000000000000000000000000000000000000000000001",
                        "hex",
                    ),
                })
            } else if (packet.type === SFTPPacketType.Open) {
                const path = packet.filename.toString()
                openedPaths.push(path)
                if (path === "one") {
                    firstRequestId = packet.requestId
                } else {
                    fixture.send({
                        type: SFTPPacketType.Handle,
                        requestId: packet.requestId,
                        handle: Buffer.from(path),
                    })
                }
            } else if (packet.type === SFTPPacketType.Close) {
                fixture.send({
                    type: SFTPPacketType.Status,
                    requestId: packet.requestId,
                    code: SFTPStatusCode.Ok,
                    message: "",
                    languageTag: "",
                })
            }
        })

        const client = await SFTPClient.connect(asClientChannel(fixture))
        const firstPromise = client.open("one", "r")
        let secondError: unknown
        try {
            await client.open("two", "r")
        } catch (error) {
            secondError = error
        }
        if (firstRequestId === undefined) throw new Error("First OPEN was not sent")
        fixture.send({
            type: SFTPPacketType.Handle,
            requestId: firstRequestId,
            handle: Buffer.from("one"),
        })
        const firstHandle = await firstPromise
        await client.close(firstHandle)
        const thirdHandle = await client.open("three", "r")

        expect({
            firstHandle,
            openedPaths,
            secondError:
                secondError instanceof Error
                    ? `${secondError.name}: ${secondError.message}`
                    : secondError,
            thirdHandle,
        }).toEqual({
            firstHandle: Buffer.from("one"),
            openedPaths: ["one", "three"],
            secondError: "Error: SFTP server permits at most 1 active handle",
            thirdHandle: Buffer.from("three"),
        })
        fixture.destroy()
    })

    test("gates OpenSSH requests by exact advertised version and preserves wire paths", async () => {
        const requests: string[] = []
        const fixture = new SFTPServerFixture((packet) => {
            if (packet.type === SFTPPacketType.Init) {
                fixture.send({
                    type: SFTPPacketType.Version,
                    version: 3,
                    extensions: [
                        { name: "posix-rename@openssh.com", data: Buffer.from("1") },
                        { name: "expand-path@openssh.com", data: Buffer.from("1") },
                        { name: "fsync@openssh.com", data: Buffer.from("2") },
                    ],
                })
                return
            }
            if (packet.type !== SFTPPacketType.Extended) return
            requests.push(packet.request)
            if (packet.request === "posix-rename@openssh.com") {
                expect(packet.data).toEqual(
                    Buffer.from("000000036f6c64000000086e65772d6e616d65", "hex"),
                )
                fixture.send({
                    type: SFTPPacketType.Status,
                    requestId: packet.requestId,
                    code: SFTPStatusCode.Ok,
                    message: "",
                    languageTag: "",
                })
            } else if (packet.request === "expand-path@openssh.com") {
                expect(packet.data).toEqual(Buffer.from("000000017e", "hex"))
                fixture.send({
                    type: SFTPPacketType.Name,
                    requestId: packet.requestId,
                    names: [
                        {
                            filename: Buffer.from("/home/test"),
                            longname: Buffer.from("/home/test"),
                            attributes: {},
                        },
                    ],
                })
            }
        })

        const client = await SFTPClient.connect(asClientChannel(fixture))
        await client.opensshPosixRename("old", "new-name")
        expect(await client.opensshExpandPath("~")).toBe("/home/test")
        expect(await client.opensshExpandPath("~", "buffer")).toEqual(Buffer.from("/home/test"))
        await expect(client.opensshFSync(Buffer.from("handle"))).rejects.toThrow(
            "does not advertise fsync@openssh.com version 1",
        )
        expect(requests).toEqual([
            "posix-rename@openssh.com",
            "expand-path@openssh.com",
            "expand-path@openssh.com",
        ])
        fixture.destroy()
    })

    test("preserves opaque canonical paths and symlink targets on request", async () => {
        const fixture = new SFTPServerFixture((packet) => {
            if (packet.type === SFTPPacketType.Init) {
                fixture.send({ type: SFTPPacketType.Version, version: 3, extensions: [] })
                return
            }
            if (
                packet.type !== SFTPPacketType.RealPath &&
                packet.type !== SFTPPacketType.ReadLink
            ) {
                return
            }
            fixture.send({
                type: SFTPPacketType.Name,
                requestId: packet.requestId,
                names: [
                    { filename: Buffer.from([0xff]), longname: Buffer.alloc(0), attributes: {} },
                ],
            })
        })

        const client = await SFTPClient.connect(asClientChannel(fixture))
        await expect(client.realpath(".")).rejects.toThrow(
            "SFTP returned filename is not valid UTF-8 text",
        )
        expect(await client.realpath(Buffer.from("."), "buffer")).toEqual(Buffer.from([0xff]))
        await expect(client.readlink("link")).rejects.toThrow(
            "SFTP returned filename is not valid UTF-8 text",
        )
        expect(await client.readlink(Buffer.from("link"), "buffer")).toEqual(Buffer.from([0xff]))
        fixture.destroy()
    })

    test("rejects malformed advertised limits instead of silently downgrading", async () => {
        const fixture = new SFTPServerFixture((packet) => {
            if (packet.type === SFTPPacketType.Init) {
                fixture.send({
                    type: SFTPPacketType.Version,
                    version: 3,
                    extensions: [{ name: "limits@openssh.com", data: Buffer.from("1", "ascii") }],
                })
            } else if (packet.type === SFTPPacketType.Extended) {
                fixture.send({
                    type: SFTPPacketType.ExtendedReply,
                    requestId: packet.requestId,
                    data: Buffer.alloc(31),
                })
            }
        })

        await expect(SFTPClient.connect(asClientChannel(fixture))).rejects.toThrow(
            "Truncated maximum open handles",
        )
        expect(fixture.destroyed).toBe(true)
    })

    test("negotiates v3 and matches concurrent responses by request id", async () => {
        const stats: SFTPPacket[] = []
        const fixture = new SFTPServerFixture((packet) => {
            if (packet.type === SFTPPacketType.Init) {
                fixture.send({
                    type: SFTPPacketType.Version,
                    version: SFTP_VERSION,
                    extensions: [
                        { name: "x@test", data: Buffer.from("1") },
                        { name: "x@test", data: Buffer.from("2") },
                        { name: "binary@test", data: Buffer.from([0xb2]) },
                    ],
                })
                return
            }
            if (packet.type !== SFTPPacketType.Stat) return
            stats.push(packet)
            if (stats.length !== 2) return
            const [first, second] = stats
            if (!("requestId" in first!) || !("requestId" in second!)) return
            fixture.send({
                type: SFTPPacketType.Attrs,
                requestId: second.requestId,
                attributes: { size: 2n },
            })
            fixture.send({
                type: SFTPPacketType.Attrs,
                requestId: first.requestId,
                attributes: { size: 1n },
            })
        })

        const client = await SFTPClient.connect(asClientChannel(fixture))
        expect(client.extensions).toEqual([
            { name: "x@test", data: Buffer.from("1") },
            { name: "x@test", data: Buffer.from("2") },
            { name: "binary@test", data: Buffer.from([0xb2]) },
        ])
        const exposedExtensions = client.extensions
        exposedExtensions[1]!.data.fill(0x39)
        expect(client.extensions).toEqual([
            { name: "x@test", data: Buffer.from("1") },
            { name: "x@test", data: Buffer.from("2") },
            { name: "binary@test", data: Buffer.from([0xb2]) },
        ])
        expect(Object.isFrozen(exposedExtensions)).toBe(true)
        expect(Object.isFrozen(exposedExtensions[0])).toBe(true)
        expect(client.supportsExtension("x@test", "2")).toBe(true)
        expect(client.supportsExtension("binary@test", "2")).toBe(false)
        const [first, second] = await Promise.all([client.stat("first"), client.stat("second")])
        expect(first.size).toBe(1n)
        expect(second.size).toBe(2n)
        fixture.destroy()
    })

    test("turns status failures into typed errors", async () => {
        const fixture = new SFTPServerFixture((packet) => {
            if (packet.type === SFTPPacketType.Init) {
                fixture.send({ type: SFTPPacketType.Version, version: 3, extensions: [] })
            } else if ("requestId" in packet) {
                fixture.send({
                    type: SFTPPacketType.Status,
                    requestId: packet.requestId,
                    code: SFTPStatusCode.PermissionDenied,
                    message: "not allowed",
                    languageTag: "en",
                })
            }
        })
        const client = await SFTPClient.connect(asClientChannel(fixture))
        let received: unknown
        try {
            await client.stat("private")
        } catch (error) {
            received = error
        }
        expect(received).toBeInstanceOf(SFTPStatusError)
        expect(received).toMatchObject({
            code: SFTPStatusCode.PermissionDenied,
            requestId: 0,
            languageTag: "en",
            message: "not allowed",
        })
        fixture.destroy()
    })

    test("truncates paths and handles with exact uint64 sizes", async () => {
        const requests: SFTPPacket[] = []
        const fixture = new SFTPServerFixture((packet) => {
            if (packet.type === SFTPPacketType.Init) {
                fixture.send({ type: SFTPPacketType.Version, version: 3, extensions: [] })
                return
            }
            requests.push(packet)
            if ("requestId" in packet) {
                fixture.send({
                    type: SFTPPacketType.Status,
                    requestId: packet.requestId,
                    code: SFTPStatusCode.Ok,
                    message: "",
                    languageTag: "",
                })
            }
        })
        const client = await SFTPClient.connect(asClientChannel(fixture))

        await client.truncate(Buffer.from("file"), 4_294_967_297n)
        await client.ftruncate(Buffer.from([0x00, 0xff]), Number.MAX_SAFE_INTEGER)

        expect(requests).toEqual([
            {
                type: SFTPPacketType.SetStat,
                requestId: 0,
                path: Buffer.from("file"),
                attributes: { size: 4_294_967_297n },
            },
            {
                type: SFTPPacketType.FSetStat,
                requestId: 1,
                handle: Buffer.from([0x00, 0xff]),
                attributes: { size: BigInt(Number.MAX_SAFE_INTEGER) },
            },
        ])
        expect(() => client.truncate("file", -1)).toThrow("non-negative safe integer")
        expect(() => client.ftruncate(Buffer.from("h"), 0x1_0000_0000_0000_0000n)).toThrow("uint64")
        fixture.destroy()
    })

    test("rejects the active request and closes on a mismatched response", async () => {
        const fixture = new SFTPServerFixture((packet) => {
            if (packet.type === SFTPPacketType.Init) {
                fixture.send({ type: SFTPPacketType.Version, version: 3, extensions: [] })
            } else if ("requestId" in packet) {
                fixture.send({
                    type: SFTPPacketType.Status,
                    requestId: packet.requestId,
                    code: SFTPStatusCode.Ok,
                    message: "",
                    languageTag: "",
                })
            }
        })
        const client = await SFTPClient.connect(asClientChannel(fixture))
        await expect(client.stat("wrong-response")).rejects.toThrow(
            "successful STATUS instead of response data",
        )
        expect(fixture.destroyed).toBe(true)
    })

    test("rejects unsupported protocol versions during initialization", async () => {
        const fixture = new SFTPServerFixture((packet) => {
            if (packet.type === SFTPPacketType.Init) {
                fixture.send({ type: SFTPPacketType.Version, version: 4, extensions: [] })
            }
        })
        await expect(SFTPClient.connect(asClientChannel(fixture))).rejects.toThrow(
            "Unsupported SFTP protocol version 4",
        )
        expect(fixture.destroyed).toBe(true)
    })

    test("validates open flags instead of emitting invalid v3 combinations", () => {
        expect(sftpOpenFlags("wx")).toBe(
            SFTPOpenFlags.Write |
                SFTPOpenFlags.Create |
                SFTPOpenFlags.Truncate |
                SFTPOpenFlags.Exclusive,
        )
        expect(() => sftpOpenFlags("sync")).toThrow("Unknown SFTP open flags")
        expect(() => sftpOpenFlags(0x40)).toThrow("unknown bits")
        expect(() => sftpOpenFlags(SFTPOpenFlags.Truncate)).toThrow("require create")
    })
})
