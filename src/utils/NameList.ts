import { readNextBuffer } from "./Buffer.js"
import { decodeSSHName, encodeSSHName } from "./SSHName.js"

export function readNextNameList(raw: Buffer): [string[], Buffer] {
    let data: Buffer
    ;[data, raw] = readNextBuffer(raw)

    return [decodeSSHNameList(data), raw]
}

export function decodeSSHNameList(data: Buffer): string[] {
    if (data.length === 0) return []
    const names = data.toString("ascii").split(",")
    if (data.some((byte) => byte > 0x7f)) throw new Error("SSH name-list must be US-ASCII")
    for (const name of names) decodeSSHName(Buffer.from(name, "ascii"), "SSH name-list entry")
    if (new Set(names).size !== names.length) throw new Error("SSH name-list has duplicate names")
    return names
}

export function serializeNameList(names: string[]): Buffer {
    if (names.length == 0) {
        return Buffer.alloc(4)
    }
    if (new Set(names).size !== names.length) throw new Error("SSH name-list has duplicate names")
    const data = encodeSSHNameList(names)

    const length = Buffer.allocUnsafe(4)
    length.writeUInt32BE(data.length, 0)

    return Buffer.concat([length, data])
}

export function encodeSSHNameList(names: readonly string[]): Buffer {
    if (names.length === 0) return Buffer.alloc(0)
    if (new Set(names).size !== names.length) throw new Error("SSH name-list has duplicate names")
    return Buffer.concat(
        names.flatMap((name, index) => [
            ...(index === 0 ? [] : [Buffer.from(",")]),
            encodeSSHName(name, "SSH name-list entry"),
        ]),
    )
}
