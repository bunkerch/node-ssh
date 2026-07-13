import { describe, expect, test } from "bun:test"
import {
    decodeSFTPPacket,
    encodeSFTPAttributes,
    encodeSFTPPacket,
    MAX_SFTP_PACKET_LENGTH,
    SFTPAttributeFlags,
    SFTPOpenFlags,
    SFTPPacketParser,
    SFTPPacketType,
    SFTPProtocolError,
    SFTPStatusCode,
} from "../../src/index.js"

const hex = (value: string): Buffer => Buffer.from(value.replaceAll(/\s/gu, ""), "hex")

const INIT = hex(`
    00000019 01 00000003
    0000000b 76656e646f724074657374
    00000001 31
`)

const OPEN = hex(`
    00000045 03 01020304
    00000005 612e747874
    00000003
    8000000f
    0102030405060708
    000003e8 000003e9
    000081a4
    00000001 00000002
    00000001
    00000006 784074657374
    00000001 ff
`)

const READ = hex(`
    00000016 05 00000005
    00000001 68
    0000000100000002
    00008000
`)

const WRITE = hex(`
    00000019 06 00000006
    00000001 68
    0000000000000000
    00000003 616263
`)

const STATUS = hex(`
    00000015 65 00000009 00000002
    00000002 6e6f
    00000002 656e
`)

const NAME = hex(`
    00000019 68 0000000a 00000001
    00000001 66
    00000003 2d2066
    00000000
`)

describe("SFTP v3 fixed packet vectors", () => {
    test("parses and serializes initialization extensions without losing duplicates", () => {
        const packet = decodeSFTPPacket(INIT)
        expect(packet).toEqual({
            type: SFTPPacketType.Init,
            version: 3,
            extensions: [{ name: "vendor@test", data: Buffer.from("1") }],
        })
        expect(encodeSFTPPacket(packet)).toEqual(INIT)

        const duplicateExtensions = hex(`
            00000023 02 00000003
            00000006 784074657374 00000001 31
            00000006 784074657374 00000001 32
        `)
        const version = decodeSFTPPacket(duplicateExtensions)
        expect(version).toMatchObject({
            type: SFTPPacketType.Version,
            extensions: [
                { name: "x@test", data: Buffer.from("1") },
                { name: "x@test", data: Buffer.from("2") },
            ],
        })
        expect(encodeSFTPPacket(version)).toEqual(duplicateExtensions)
    })

    test("preserves exact uint64 values and all v3 attributes", () => {
        const packet = decodeSFTPPacket(OPEN)
        expect(packet).toEqual({
            type: SFTPPacketType.Open,
            requestId: 0x0102_0304,
            filename: Buffer.from("a.txt"),
            flags: SFTPOpenFlags.Read | SFTPOpenFlags.Write,
            attributes: {
                size: 0x0102_0304_0506_0708n,
                uid: 1000,
                gid: 1001,
                permissions: 0o100644,
                accessTime: 1,
                modificationTime: 2,
                extended: [{ type: Buffer.from("x@test"), data: Buffer.from([0xff]) }],
            },
        })
        expect(encodeSFTPPacket(packet)).toEqual(OPEN)
    })

    test("parses and serializes fixed read and write requests", () => {
        expect(decodeSFTPPacket(READ)).toEqual({
            type: SFTPPacketType.Read,
            requestId: 5,
            handle: Buffer.from("h"),
            offset: 0x1_0000_0002n,
            length: 32768,
        })
        expect(encodeSFTPPacket(decodeSFTPPacket(READ))).toEqual(READ)
        expect(decodeSFTPPacket(WRITE)).toEqual({
            type: SFTPPacketType.Write,
            requestId: 6,
            handle: Buffer.from("h"),
            offset: 0n,
            data: Buffer.from("abc"),
        })
        expect(encodeSFTPPacket(decodeSFTPPacket(WRITE))).toEqual(WRITE)
    })

    test("covers every handle, path, attribute, and two-path request layout", () => {
        for (const type of [
            SFTPPacketType.Close,
            SFTPPacketType.FStat,
            SFTPPacketType.ReadDir,
        ] as const) {
            const vector = hex(
                `0000000a ${type.toString(16).padStart(2, "0")} 00000007 00000001 68`,
            )
            expect(encodeSFTPPacket(decodeSFTPPacket(vector))).toEqual(vector)
        }
        for (const type of [
            SFTPPacketType.LStat,
            SFTPPacketType.OpenDir,
            SFTPPacketType.Remove,
            SFTPPacketType.RmDir,
            SFTPPacketType.RealPath,
            SFTPPacketType.Stat,
            SFTPPacketType.ReadLink,
        ] as const) {
            const vector = hex(
                `0000000a ${type.toString(16).padStart(2, "0")} 00000001 00000001 2f`,
            )
            expect(encodeSFTPPacket(decodeSFTPPacket(vector))).toEqual(vector)
        }
        for (const type of [SFTPPacketType.SetStat, SFTPPacketType.MkDir] as const) {
            const vector = hex(
                `0000000e ${type.toString(16).padStart(2, "0")} 00000001 00000001 2f 00000000`,
            )
            expect(encodeSFTPPacket(decodeSFTPPacket(vector))).toEqual(vector)
        }

        const fsetstat = hex(`0000000e 0a 00000001 00000001 68 00000000`)
        const rename = hex(`0000000f 12 00000001 00000001 61 00000001 62`)
        const symlink = hex(`0000000f 14 00000001 00000001 61 00000001 62`)
        for (const vector of [fsetstat, rename, symlink]) {
            expect(encodeSFTPPacket(decodeSFTPPacket(vector))).toEqual(vector)
        }
    })

    test("parses and serializes every standard response layout", () => {
        expect(decodeSFTPPacket(STATUS)).toEqual({
            type: SFTPPacketType.Status,
            requestId: 9,
            code: SFTPStatusCode.NoSuchFile,
            message: "no",
            languageTag: "en",
        })
        expect(encodeSFTPPacket(decodeSFTPPacket(STATUS))).toEqual(STATUS)

        const handle = hex(`0000000a 66 00000009 00000001 68`)
        const data = hex(`0000000c 67 00000009 00000003 616263`)
        const attrs = hex(`00000009 69 00000009 00000000`)
        for (const vector of [handle, data, NAME, attrs]) {
            expect(encodeSFTPPacket(decodeSFTPPacket(vector))).toEqual(vector)
        }
        expect(decodeSFTPPacket(NAME)).toEqual({
            type: SFTPPacketType.Name,
            requestId: 10,
            names: [
                {
                    filename: Buffer.from("f"),
                    longname: Buffer.from("- f"),
                    attributes: {},
                },
            ],
        })
    })

    test("preserves extension-specific payloads without interpreting them", () => {
        const request = hex(`00000011 c8 0000000b 00000006 784074657374 dead`)
        const reply = hex(`00000007 c9 0000000b dead`)
        expect(decodeSFTPPacket(request)).toEqual({
            type: SFTPPacketType.Extended,
            requestId: 11,
            request: "x@test",
            data: Buffer.from("dead", "hex"),
        })
        expect(decodeSFTPPacket(reply)).toEqual({
            type: SFTPPacketType.ExtendedReply,
            requestId: 11,
            data: Buffer.from("dead", "hex"),
        })
        expect(encodeSFTPPacket(decodeSFTPPacket(request))).toEqual(request)
        expect(encodeSFTPPacket(decodeSFTPPacket(reply))).toEqual(reply)
    })
})

describe("SFTP v3 bounded stream parser", () => {
    test("decodes coalesced packets at every fragmentation boundary", () => {
        const input = Buffer.concat([INIT, STATUS])
        for (let boundary = 0; boundary <= input.length; boundary++) {
            const parser = new SFTPPacketParser()
            const packets = [
                ...parser.push(input.subarray(0, boundary)),
                ...parser.push(input.subarray(boundary)),
            ]
            parser.end()
            expect(packets.map((packet) => packet.type)).toEqual([
                SFTPPacketType.Init,
                SFTPPacketType.Status,
            ])
        }
    })

    test("rejects zero, oversized, truncated, mismatched, and unknown frames", () => {
        expect(() => new SFTPPacketParser().push(hex(`00000000`))).toThrow("must include a type")
        const oversized = Buffer.alloc(4)
        oversized.writeUInt32BE(MAX_SFTP_PACKET_LENGTH + 1)
        expect(() => new SFTPPacketParser().push(oversized)).toThrow("exceeds")

        const parser = new SFTPPacketParser()
        parser.push(INIT.subarray(0, -1))
        expect(() => parser.end()).toThrow("Truncated SFTP stream")
        expect(() => decodeSFTPPacket(Buffer.concat([INIT, Buffer.from([0])]))).toThrow(
            "does not match",
        )
        expect(() => decodeSFTPPacket(hex(`00000001 ff`))).toThrow("Unknown SFTP packet type")
    })

    test("rejects trailing fields, unsupported flags, impossible counts, and long handles", () => {
        expect(() => decodeSFTPPacket(hex(`0000000b 04 00000001 00000001 68 ff`))).toThrow(
            "trailing",
        )
        expect(() =>
            decodeSFTPPacket(hex(`00000012 03 00000001 00000001 61 00000001 00000010`)),
        ).toThrow("Unsupported SFTP attribute flags")
        expect(() => decodeSFTPPacket(hex(`0000000d 68 00000001 ffffffff 00000000`))).toThrow(
            "name count",
        )
        expect(() => decodeSFTPPacket(hex(`0000000d 69 00000001 80000000 ffffffff`))).toThrow(
            "extended attribute count",
        )

        const longHandle = Buffer.alloc(4 + 1 + 4 + 4 + 257)
        longHandle.writeUInt32BE(longHandle.length - 4, 0)
        longHandle[4] = SFTPPacketType.Handle
        longHandle.writeUInt32BE(1, 5)
        longHandle.writeUInt32BE(257, 9)
        expect(() => decodeSFTPPacket(longHandle)).toThrow("handle exceeds 256 bytes")
    })

    test("requires paired attributes and bounded uint64 values", () => {
        expect(() => encodeSFTPAttributes({ uid: 1 })).toThrow("uid and gid")
        expect(() => encodeSFTPAttributes({ accessTime: 1 })).toThrow("access and modification")
        expect(() => encodeSFTPAttributes({ size: -1n })).toThrow("uint64")
        expect(() => encodeSFTPAttributes({ size: 0x1_0000_0000_0000_0000n })).toThrow("uint64")
        expect(SFTPAttributeFlags.Extended).toBe(0x8000_0000)
    })

    test("rejects outbound packets above the OpenSSH message ceiling", () => {
        expect(() =>
            encodeSFTPPacket({
                type: SFTPPacketType.Data,
                requestId: 1,
                data: Buffer.alloc(MAX_SFTP_PACKET_LENGTH),
            }),
        ).toThrow(SFTPProtocolError)
    })
})
