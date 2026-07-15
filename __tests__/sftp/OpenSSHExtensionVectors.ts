import { describe, expect, test } from "bun:test"
import {
    decodeSFTPCopyDataExtension,
    decodeSFTPExtensionString,
    decodeSFTPHandleExtension,
    decodeSFTPLSetStatExtension,
    decodeSFTPLimits,
    decodeSFTPStatVFS,
    decodeSFTPTwoPathExtension,
    decodeSFTPUsersGroupsExtension,
    decodeSFTPUsersGroups,
    encodeSFTPCopyDataExtension,
    encodeSFTPExtensionString,
    encodeSFTPLSetStatExtension,
    encodeSFTPLimits,
    encodeSFTPStatVFS,
    encodeSFTPTwoPathExtension,
    encodeSFTPUsersGroups,
    encodeSFTPUsersGroupsExtension,
} from "../../src/sftp/openssh.js"

const hex = (value: string): Buffer => Buffer.from(value.replaceAll(/\s/gu, ""), "hex")

describe("OpenSSH SFTP extension fixed vectors", () => {
    test("encodes path, handle, and lsetstat payloads", () => {
        expect(encodeSFTPExtensionString(Buffer.from("/"))).toEqual(hex(`00000001 2f`))
        expect(encodeSFTPTwoPathExtension(Buffer.from("a"), Buffer.from("b"))).toEqual(
            hex(`00000001 61 00000001 62`),
        )
        expect(encodeSFTPLSetStatExtension(Buffer.from("/"), { permissions: 0o755 })).toEqual(
            hex(`00000001 2f 00000004 000001ed`),
        )
    })

    test("encodes exact uint64 copy-data and uint32 identity payloads", () => {
        expect(encodeSFTPCopyDataExtension(Buffer.from("h"), 1n, 2n, Buffer.from("d"), 3n)).toEqual(
            hex(`
                00000001 68
                0000000000000001
                0000000000000002
                00000001 64
                0000000000000003
            `),
        )
        expect(encodeSFTPUsersGroupsExtension([1, 0xffff_ffff], [])).toEqual(
            hex(`00000008 00000001 ffffffff 00000000`),
        )
    })

    test("decodes exact path, handle, attribute, copy, and identity request vectors", () => {
        expect(decodeSFTPExtensionString(hex(`00000001 2f`))).toEqual(Buffer.from("/"))
        expect(decodeSFTPHandleExtension(hex(`00000001 68`))).toEqual(Buffer.from("h"))
        expect(decodeSFTPTwoPathExtension(hex(`00000001 61 00000001 62`))).toEqual({
            firstPath: Buffer.from("a"),
            secondPath: Buffer.from("b"),
        })
        expect(decodeSFTPLSetStatExtension(hex(`00000001 2f 00000004 000001ed`))).toEqual({
            path: Buffer.from("/"),
            attributes: { permissions: 0o755 },
        })
        expect(
            decodeSFTPCopyDataExtension(
                hex(`
                    00000001 68
                    0000000000000001
                    0000000000000002
                    00000001 64
                    0000000000000003
                `),
            ),
        ).toEqual({
            sourceHandle: Buffer.from("h"),
            sourceOffset: 1n,
            length: 2n,
            destinationHandle: Buffer.from("d"),
            destinationOffset: 3n,
        })
        expect(decodeSFTPUsersGroupsExtension(hex(`00000008 00000001 ffffffff 00000000`))).toEqual({
            uids: [1, 0xffff_ffff],
            gids: [],
        })

        const encodedPaths = hex(`00000001 61 00000001 62`)
        const decodedPaths = decodeSFTPTwoPathExtension(encodedPaths)
        encodedPaths.fill(0)
        expect(decodedPaths).toEqual({
            firstPath: Buffer.from("a"),
            secondPath: Buffer.from("b"),
        })
    })

    test("decodes statvfs and limits replies without losing uint64 precision", () => {
        const statvfs = hex(`
            0000000000000001 0000000000000002 0000000000000003
            0000000000000004 0000000000000005 0000000000000006
            0000000000000007 0000000000000008 0000000000000009
            000000000000000a ffffffffffffffff
        `)
        expect(decodeSFTPStatVFS(statvfs)).toEqual({
            blockSize: 1n,
            fragmentSize: 2n,
            blocks: 3n,
            blocksFree: 4n,
            blocksAvailable: 5n,
            files: 6n,
            filesFree: 7n,
            filesAvailable: 8n,
            filesystemId: 9n,
            flags: 10n,
            maximumFilenameLength: 0xffff_ffff_ffff_ffffn,
        })
        expect(
            encodeSFTPStatVFS({
                blockSize: 1n,
                fragmentSize: 2n,
                blocks: 3n,
                blocksFree: 4n,
                blocksAvailable: 5n,
                files: 6n,
                filesFree: 7n,
                filesAvailable: 8n,
                filesystemId: 9n,
                flags: 10n,
                maximumFilenameLength: 0xffff_ffff_ffff_ffffn,
            }),
        ).toEqual(statvfs)
        expect(
            decodeSFTPLimits(
                hex(`
                    0000000000040000 000000000003f000
                    000000000003e000 0000000000000080
                `),
            ),
        ).toEqual({
            maximumPacketLength: 262144n,
            maximumReadLength: 258048n,
            maximumWriteLength: 253952n,
            maximumOpenHandles: 128n,
        })
        expect(
            encodeSFTPLimits({
                maximumPacketLength: 262144n,
                maximumReadLength: 258048n,
                maximumWriteLength: 253952n,
                maximumOpenHandles: 128n,
            }),
        ).toEqual(
            hex(`
                0000000000040000 000000000003f000
                000000000003e000 0000000000000080
            `),
        )
    })

    test("decodes nested user and group name strings", () => {
        const names = hex(`
            00000009 00000001 75 00000000
            00000005 00000001 67
        `)
        expect(decodeSFTPUsersGroups(names)).toEqual({ usernames: ["u", ""], groupNames: ["g"] })
        expect(encodeSFTPUsersGroups({ usernames: ["u", ""], groupNames: ["g"] })).toEqual(names)
        expect(() => decodeSFTPUsersGroups(hex(`00000005 00000001 ff 00000000`))).toThrow(
            "SFTP usernames entry is not valid UTF-8 text",
        )
    })

    test("rejects truncated, trailing, and out-of-range extension fields", () => {
        expect(() => decodeSFTPLimits(Buffer.alloc(31))).toThrow("Truncated")
        expect(() => decodeSFTPLimits(Buffer.alloc(33))).toThrow("trailing")
        expect(() =>
            encodeSFTPLimits({
                maximumPacketLength: -1n,
                maximumReadLength: 0n,
                maximumWriteLength: 0n,
                maximumOpenHandles: 0n,
            }),
        ).toThrow("uint64")
        expect(() => decodeSFTPStatVFS(Buffer.alloc(87))).toThrow("Truncated")
        expect(() =>
            encodeSFTPStatVFS({
                blockSize: -1n,
                fragmentSize: 0n,
                blocks: 0n,
                blocksFree: 0n,
                blocksAvailable: 0n,
                files: 0n,
                filesFree: 0n,
                filesAvailable: 0n,
                filesystemId: 0n,
                flags: 0n,
                maximumFilenameLength: 0n,
            }),
        ).toThrow("uint64")
        expect(() => decodeSFTPUsersGroups(hex(`00000004 ffffffff 00000000`))).toThrow("Truncated")
        expect(() => encodeSFTPUsersGroups({ usernames: ["\ud800"], groupNames: [] })).toThrow(
            "SFTP extension string is not valid UTF-8 text",
        )
        expect(() =>
            encodeSFTPCopyDataExtension(Buffer.alloc(0), -1n, 0n, Buffer.alloc(0), 0n),
        ).toThrow("uint64")
        expect(() => encodeSFTPUsersGroupsExtension([0x1_0000_0000], [])).toThrow("uint32")
        expect(() => decodeSFTPExtensionString(hex(`00000001 2f 00`))).toThrow("trailing")
        expect(() =>
            decodeSFTPHandleExtension(Buffer.concat([hex(`00000101`), Buffer.alloc(257)])),
        ).toThrow("extension handle exceeds 256 bytes")
        expect(() => decodeSFTPTwoPathExtension(hex(`00000001 61 00000002 62`))).toThrow(
            "Truncated",
        )
        expect(() => decodeSFTPLSetStatExtension(hex(`00000001 2f 00000010`))).toThrow(
            "Unsupported SFTP attribute flags",
        )
        expect(() =>
            decodeSFTPCopyDataExtension(
                Buffer.concat([hex(`00000101`), Buffer.alloc(257), Buffer.alloc(28)]),
            ),
        ).toThrow("source handle exceeds 256 bytes")
        expect(() => decodeSFTPUsersGroupsExtension(hex(`00000001 00 00000000`))).toThrow(
            "not a sequence of uint32",
        )
        expect(() => encodeSFTPExtensionString("\ud800")).toThrow(
            "SFTP extension string is not valid UTF-8 text",
        )
    })
})
