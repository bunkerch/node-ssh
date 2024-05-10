import { readNextBuffer } from "./Buffer.js"

export function readNextNameList(raw: Buffer): [string[], Buffer] {
    let data: Buffer
    [data, raw] = readNextBuffer(raw)

    if(data.length == 0){
        return [[], raw]
    }

    const names = data.toString("utf8").split(",")
    return [names, raw]
}

export function serializeNameList(names: string[]): Buffer {
    if(names.length == 0){
        return Buffer.alloc(4)
    }
    const data = names.join(",")
    
    const length = Buffer.allocUnsafe(4)
    length.writeUInt32BE(data.length, 0)

    return Buffer.concat([length, Buffer.from(data)])
}