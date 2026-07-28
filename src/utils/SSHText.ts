export function encodeSSHUTF8(value: string, field: string): Buffer {
    for (let index = 0; index < value.length; index++) {
        const codeUnit = value.charCodeAt(index)
        if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
            const next = value.charCodeAt(++index)
            if (!Number.isInteger(next) || next < 0xdc00 || next > 0xdfff) {
                throw new Error(`${field} is not valid UTF-8 text`)
            }
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

// RFC 5646 section 2.1 fixes this complete list permanently.
const RFC5646_GRANDFATHERED_TAGS = new Set([
    "art-lojban",
    "cel-gaulish",
    "en-gb-oed",
    "i-ami",
    "i-bnn",
    "i-default",
    "i-enochian",
    "i-hak",
    "i-klingon",
    "i-lux",
    "i-mingo",
    "i-navajo",
    "i-pwn",
    "i-tao",
    "i-tay",
    "i-tsu",
    "no-bok",
    "no-nyn",
    "sgn-be-fr",
    "sgn-be-nl",
    "sgn-ch-de",
    "zh-guoyu",
    "zh-hakka",
    "zh-min",
    "zh-min-nan",
    "zh-xiang",
])

export function encodeRFC5646LanguageTag(value: string, field = "language tag"): Buffer {
    validateRFC5646LanguageTag(value, field)
    return Buffer.from(value, "ascii")
}

export function decodeRFC5646LanguageTag(value: Buffer, field = "language tag"): string {
    if (value.some((byte) => byte > 0x7f)) throw new Error(`${field} is not valid RFC 5646`)
    const decoded = value.toString("ascii")
    validateRFC5646LanguageTag(decoded, field)
    return decoded
}

export function validateRFC5646LanguageTag(value: string, field = "language tag"): void {
    const invalid = (): never => {
        throw new Error(`${field} is not valid RFC 5646`)
    }
    if (typeof value !== "string") invalid()
    if (value.length === 0) return

    const normalized = value.toLowerCase()
    if (RFC5646_GRANDFATHERED_TAGS.has(normalized)) return
    const subtags = value.split("-")
    if (subtags.some((subtag) => !isAlphanumeric(subtag, 1, 8))) invalid()

    let index = 0
    if (normalized.startsWith("x-")) {
        if (subtags.length < 2) invalid()
        return
    }

    const language = subtags[index++]!
    if (!isAlphabetic(language, 2, 8)) invalid()
    if (language.length <= 3 && isAlphabetic(subtags[index], 3, 3)) index++
    if (isAlphabetic(subtags[index], 4, 4)) index++
    if (isAlphabetic(subtags[index], 2, 2) || isNumeric(subtags[index], 3, 3)) index++

    const variants = new Set<string>()
    while (isVariant(subtags[index])) {
        const variant = subtags[index++]!.toLowerCase()
        if (variants.has(variant)) invalid()
        variants.add(variant)
    }

    const singletons = new Set<string>()
    while (isExtensionSingleton(subtags[index])) {
        const singleton = subtags[index++]!.toLowerCase()
        if (singletons.has(singleton)) invalid()
        singletons.add(singleton)
        const firstExtensionSubtag = index
        while (isAlphanumeric(subtags[index], 2, 8)) index++
        if (index === firstExtensionSubtag) invalid()
    }

    if (subtags[index]?.toLowerCase() === "x") {
        index++
        if (index === subtags.length) invalid()
        while (isAlphanumeric(subtags[index], 1, 8)) index++
    }
    if (index !== subtags.length) invalid()
}

function isAlphabetic(value: string | undefined, minimum: number, maximum: number): boolean {
    return (
        value !== undefined &&
        value.length >= minimum &&
        value.length <= maximum &&
        /^[A-Za-z]+$/u.test(value)
    )
}

function isNumeric(value: string | undefined, minimum: number, maximum: number): boolean {
    return (
        value !== undefined &&
        value.length >= minimum &&
        value.length <= maximum &&
        /^[0-9]+$/u.test(value)
    )
}

function isAlphanumeric(value: string | undefined, minimum: number, maximum: number): boolean {
    return (
        value !== undefined &&
        value.length >= minimum &&
        value.length <= maximum &&
        /^[A-Za-z0-9]+$/u.test(value)
    )
}

function isVariant(value: string | undefined): boolean {
    return (
        isAlphanumeric(value, 5, 8) || (value !== undefined && /^[0-9][A-Za-z0-9]{3}$/u.test(value))
    )
}

function isExtensionSingleton(value: string | undefined): boolean {
    return value !== undefined && /^[0-9A-WY-Za-wy-z]$/u.test(value)
}
