export function encodeBigIntBE(int: bigint): Buffer {
    const bytes = []
    while (int != 0n) {
        bytes.unshift(Number(int % 256n))
        int /= 256n
    }
    return Buffer.from(bytes)
}

export function encodeBigIntLE(int: bigint): Buffer {
    const bytes = []
    while (int != 0n) {
        bytes.push(Number(int % 256n))
        int /= 256n
    }
    return Buffer.from(bytes)
}

export function decodeBigIntBE(raw: Buffer): bigint {
    // TODO: Could potentially improve perfs with one big raw.readBigUInt64BE()
    // every 8 bytes instead of making one bigint per byte
    let int = 0n
    for (const byte of raw) {
        int = (int << 8n) + BigInt(byte)
    }

    return int
}
export function decodeBigIntLE(raw: Buffer): bigint {
    let int = 0n
    for (let i = raw.length - 1; i >= 0; i--) {
        int = (int << 8n) + BigInt(raw[i])
    }

    return int
}
