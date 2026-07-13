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

function asClientChannel(channel: SFTPServerFixture): ClientSessionChannel {
    return channel as unknown as ClientSessionChannel
}

describe("SFTP client request engine", () => {
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
        await expect(client.opensshFSync(Buffer.from("handle"))).rejects.toThrow(
            "does not advertise fsync@openssh.com version 1",
        )
        expect(requests).toEqual(["posix-rename@openssh.com", "expand-path@openssh.com"])
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
        ])
        expect(client.supportsExtension("x@test", "2")).toBe(true)
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
