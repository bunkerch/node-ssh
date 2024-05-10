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
    let int = 0n
    for (let i = 0; i < raw.length; i++) {
        int = (int << 8n) + BigInt(raw[i])
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
