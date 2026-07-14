export function encodeSSHUTF8(value: string, field: string): Buffer {
    for (let index = 0; index < value.length; index++) {
        const codeUnit = value.charCodeAt(index)
        if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
            const next = value.charCodeAt(++index)
            if (next < 0xdc00 || next > 0xdfff) throw new Error(`${field} is not valid UTF-8 text`)
        } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
            throw new Error(`${field} is not valid UTF-8 text`)
        }
    }
    return Buffer.from(value, "utf8")
}

export function decodeSSHUTF8(value: Buffer, field: string): string {
    try {
        return new TextDecoder("utf-8", { fatal: true }).decode(value)
    } catch {
        throw new Error(`${field} is not valid UTF-8 text`)
    }
}

export function encodeSSHLanguageTag(value: string, field = "SSH language tag"): Buffer {
    validateSSHLanguageTag(value, field)
    return Buffer.from(value, "ascii")
}

export function decodeSSHLanguageTag(value: Buffer, field = "SSH language tag"): string {
    if (value.some((byte) => byte > 0x7f)) throw new Error(`${field} is not valid RFC 3066`)
    const decoded = value.toString("ascii")
    validateSSHLanguageTag(decoded, field)
    return decoded
}

export function validateSSHLanguageTag(value: string, field = "SSH language tag"): void {
    if (value.length > 0 && !/^[A-Za-z]{1,8}(?:-[A-Za-z0-9]{1,8})*$/u.test(value)) {
        throw new Error(`${field} is not valid RFC 3066`)
    }
}
