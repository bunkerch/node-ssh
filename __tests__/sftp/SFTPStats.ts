import { describe, expect, test } from "bun:test"
import { flagsToString, OPEN_MODE, STATUS_CODE, stringToFlags } from "../../src/sftp/SFTPClient.js"
import { SFTPStats, sftpNameEntry } from "../../src/sftp/SFTPStats.js"
import { SFTPStatusCode } from "../../src/sftp/constants.js"

describe("SFTP public compatibility values", () => {
    test("classifies every POSIX file type from fixed mode values", () => {
        expect(new SFTPStats({ permissions: 0o040755 }).isDirectory()).toBe(true)
        expect(new SFTPStats({ permissions: 0o100644 }).isFile()).toBe(true)
        expect(new SFTPStats({ permissions: 0o060600 }).isBlockDevice()).toBe(true)
        expect(new SFTPStats({ permissions: 0o020600 }).isCharacterDevice()).toBe(true)
        expect(new SFTPStats({ permissions: 0o120777 }).isSymbolicLink()).toBe(true)
        expect(new SFTPStats({ permissions: 0o010600 }).isFIFO()).toBe(true)
        expect(new SFTPStats({ permissions: 0o140600 }).isSocket()).toBe(true)
        const absent = new SFTPStats()
        expect([
            absent.isDirectory(),
            absent.isFile(),
            absent.isBlockDevice(),
            absent.isCharacterDevice(),
            absent.isSymbolicLink(),
            absent.isFIFO(),
            absent.isSocket(),
        ]).toEqual([false, false, false, false, false, false, false])
    })

    test("preserves exact v3 attributes and convenience aliases", () => {
        const stats = new SFTPStats({
            size: 0xffff_ffff_ffff_ffffn,
            uid: 1000,
            gid: 1001,
            permissions: 0o100640,
            accessTime: 1_700_000_000,
            modificationTime: 1_700_000_001,
        })
        expect(stats.size).toBe(0xffff_ffff_ffff_ffffn)
        expect(stats.mode).toBe(0o100640)
        expect(stats.atime).toBe(1_700_000_000)
        expect(stats.mtime).toBe(1_700_000_001)
    })

    test("owns extended attributes and name-entry buffers", () => {
        const type = Buffer.from("mime-type")
        const data = Buffer.from("text/plain")
        const filename = Buffer.from("document.txt")
        const longname = Buffer.from("-rw-r--r-- document.txt")
        const entry = sftpNameEntry({
            filename,
            longname,
            attributes: { extended: [{ type, data }] },
        })

        type.fill(0x78)
        data.fill(0x78)
        filename.fill(0x78)
        longname.fill(0x78)

        expect(entry).toEqual({
            filename: Buffer.from("document.txt"),
            longname: Buffer.from("-rw-r--r-- document.txt"),
            attributes: new SFTPStats({
                extended: [{ type: Buffer.from("mime-type"), data: Buffer.from("text/plain") }],
            }),
        })
        expect(Object.isFrozen(entry.attributes.extended)).toBe(true)
        expect(Object.isFrozen(entry.attributes.extended![0])).toBe(true)
    })

    test("converts canonical file flags and exports legacy constants", () => {
        expect(stringToFlags("r+")).toBe(OPEN_MODE.READ | OPEN_MODE.WRITE)
        expect(stringToFlags("invalid")).toBeNull()
        expect(flagsToString(OPEN_MODE.WRITE | OPEN_MODE.CREAT | OPEN_MODE.TRUNC)).toBe("w")
        expect(flagsToString(0xffff)).toBeNull()
        expect(STATUS_CODE.NO_SUCH_FILE).toBe(SFTPStatusCode.NoSuchFile)
        expect(STATUS_CODE.OP_UNSUPPORTED).toBe(SFTPStatusCode.OperationUnsupported)
    })
})
