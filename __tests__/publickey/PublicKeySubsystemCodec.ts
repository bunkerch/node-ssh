import { describe, expect, test } from "bun:test"
import {
    decodePublicKeySubsystemPacket,
    encodePublicKeySubsystemPacket,
    MAX_PUBLIC_KEY_SUBSYSTEM_PACKET_LENGTH,
    PublicKeySubsystemPacketParser,
    PublicKeySubsystemProtocolError,
    PublicKeySubsystemStatusCode,
} from "../../src/publickey/PublicKeySubsystemCodec.js"

const hex = (value: string): Buffer => Buffer.from(value.replaceAll(/\s/gu, ""), "hex")

const VERSION = hex(`
    0000000f
    00000007 76657273696f6e
    00000002
`)

const ADD = hex(`
    00000034
    00000003 616464
    0000000b 7373682d65643235353139
    00000003 010203
    01
    00000001
    00000007 636f6d6d656e74
    00000002 6869
    00
`)

const STATUS = hex(`
    0000001e
    00000006 737461747573
    00000001
    00000006 64656e696564
    00000002 656e
`)

const EXTENDED_STATUS = hex(`
    00000016
    00000006 737461747573
    01020304
    00000000
    00000000
`)

const REMOVE = hex(`
    00000020
    00000006 72656d6f7665
    0000000b 7373682d65643235353139
    00000003 010203
`)

const LIST = hex(`00000008 00000004 6c697374`)
const LIST_ATTRIBUTES = hex(`00000012 0000000e 6c69737461747472696275746573`)

const PUBLIC_KEY = hex(`
    00000038
    00000009 7075626c69636b6579
    0000000b 7373682d65643235353139
    00000003 010203
    00000001
    00000007 636f6d6d656e74
    00000002 6869
`)

const ATTRIBUTE = hex(`
    00000017
    00000009 617474726962757465
    00000005 7368656c6c
    01
`)

const UNKNOWN = hex(`0000000d 00000007 6d797374657279 dead`)

describe("RFC 4819 public-key subsystem fixed packet vectors", () => {
    test("parses and serializes the version packet magic cookie", () => {
        const packet = decodePublicKeySubsystemPacket(VERSION)
        expect(packet).toEqual({ type: "version", version: 2 })
        expect(encodePublicKeySubsystemPacket(packet)).toEqual(VERSION)
        expect(VERSION.subarray(0, 15)).toEqual(hex(`0000000f 00000007 76657273696f6e`))
    })

    test("parses and serializes add attributes without interpreting opaque values", () => {
        const packet = decodePublicKeySubsystemPacket(ADD)
        expect(packet).toEqual({
            type: "add",
            algorithm: "ssh-ed25519",
            keyBlob: Buffer.from([1, 2, 3]),
            overwrite: true,
            attributes: [{ name: "comment", value: Buffer.from("hi"), critical: false }],
        })
        expect(encodePublicKeySubsystemPacket(packet)).toEqual(ADD)
    })

    test("parses and serializes localized status failures", () => {
        const packet = decodePublicKeySubsystemPacket(STATUS)
        expect(packet).toEqual({
            type: "status",
            code: PublicKeySubsystemStatusCode.AccessDenied,
            description: "denied",
            languageTag: "en",
        })
        expect(encodePublicKeySubsystemPacket(packet)).toEqual(STATUS)
    })

    test("preserves the complete RFC uint32 status-code field", () => {
        const packet = decodePublicKeySubsystemPacket(EXTENDED_STATUS)
        expect(packet).toEqual({
            type: "status",
            code: 0x0102_0304,
            description: "",
            languageTag: "",
        })
        expect(encodePublicKeySubsystemPacket(packet)).toEqual(EXTENDED_STATUS)
    })

    test("accepts every non-zero RFC boolean and serializes canonical true values", () => {
        const add = Buffer.from(ADD)
        add[33] = 2
        add[add.length - 1] = 0xff
        const addPacket = decodePublicKeySubsystemPacket(add)
        expect(addPacket).toMatchObject({
            type: "add",
            overwrite: true,
            attributes: [{ critical: true }],
        })
        const canonicalAdd = encodePublicKeySubsystemPacket(addPacket)
        expect(canonicalAdd[33]).toBe(1)
        expect(canonicalAdd[canonicalAdd.length - 1]).toBe(1)

        const attribute = Buffer.from(ATTRIBUTE)
        attribute[attribute.length - 1] = 0x80
        const attributePacket = decodePublicKeySubsystemPacket(attribute)
        expect(attributePacket).toEqual({ type: "attribute", name: "shell", compulsory: true })
        expect(encodePublicKeySubsystemPacket(attributePacket)).toEqual(ATTRIBUTE)
    })

    test("covers remove, list, publickey, and capability response layouts", () => {
        const cases = [
            [
                REMOVE,
                {
                    type: "remove",
                    algorithm: "ssh-ed25519",
                    keyBlob: Buffer.from([1, 2, 3]),
                },
            ],
            [LIST, { type: "list" }],
            [LIST_ATTRIBUTES, { type: "listattributes" }],
            [
                PUBLIC_KEY,
                {
                    type: "publickey",
                    algorithm: "ssh-ed25519",
                    keyBlob: Buffer.from([1, 2, 3]),
                    attributes: [{ name: "comment", value: Buffer.from("hi") }],
                },
            ],
            [ATTRIBUTE, { type: "attribute", name: "shell", compulsory: true }],
        ] as const

        for (const [vector, expected] of cases) {
            const packet = decodePublicKeySubsystemPacket(vector)
            expect(packet).toEqual(expected)
            expect(encodePublicKeySubsystemPacket(packet)).toEqual(vector)
        }
    })

    test("preserves unknown requests so servers can return a status without closing", () => {
        const packet = decodePublicKeySubsystemPacket(UNKNOWN)
        expect(packet).toEqual({
            type: "unknown",
            name: "mystery",
            data: Buffer.from("dead", "hex"),
        })
        expect(encodePublicKeySubsystemPacket(packet)).toEqual(UNKNOWN)
    })
})

describe("RFC 4819 bounded packet parser", () => {
    test("handles fragmentation and rejects malformed or unbounded frames", () => {
        const combined = Buffer.concat([VERSION, LIST, STATUS])
        for (let split = 0; split <= combined.length; split++) {
            const parser = new PublicKeySubsystemPacketParser()
            const packets = [
                ...parser.push(combined.subarray(0, split)),
                ...parser.push(combined.subarray(split)),
            ]
            expect(packets.map(({ type }) => type)).toEqual(["version", "list", "status"])
            parser.end()
        }

        const truncated = new PublicKeySubsystemPacketParser()
        expect(truncated.push(VERSION.subarray(0, -1))).toEqual([])
        expect(() => truncated.end()).toThrow(PublicKeySubsystemProtocolError)

        expect(() => decodePublicKeySubsystemPacket(hex(`00040001`))).toThrow(
            `exceeds ${MAX_PUBLIC_KEY_SUBSYSTEM_PACKET_LENGTH}`,
        )
        const impossibleCount = Buffer.from(ADD)
        impossibleCount.writeUInt32BE(0xffff_ffff, 34)
        expect(() => decodePublicKeySubsystemPacket(impossibleCount)).toThrow(
            "attribute count exceeds packet data",
        )

        expect(() =>
            encodePublicKeySubsystemPacket({
                type: "remove",
                algorithm: "ssh-ed25519",
                keyBlob: Buffer.alloc(MAX_PUBLIC_KEY_SUBSYSTEM_PACKET_LENGTH),
            }),
        ).toThrow(`exceeds ${MAX_PUBLIC_KEY_SUBSYSTEM_PACKET_LENGTH}`)
        expect(() =>
            encodePublicKeySubsystemPacket({
                type: "status",
                code: 0x1_0000_0000,
                description: "",
                languageTag: "",
            }),
        ).toThrow("status code must be a uint32")
    })
})
