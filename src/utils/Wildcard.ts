/** Matches `*` and `?` against UTF-8 bytes using bounded NFA state. */
export function matchesWildcardBytes(
    pattern: string,
    value: string,
    asciiCaseInsensitive = false,
): boolean {
    const patternBytes = Buffer.from(pattern, "utf8")
    const valueBytes = Buffer.from(value, "utf8")
    let states = new Uint8Array(patternBytes.length + 1)
    let next = new Uint8Array(patternBytes.length + 1)
    states[0] = 1
    applyStarClosure(states, patternBytes)

    for (const originalByte of valueBytes) {
        next.fill(0)
        const byte = asciiCaseInsensitive ? asciiLowercaseByte(originalByte) : originalByte
        let active = false
        for (let index = 0; index < patternBytes.length; index++) {
            if (states[index] === 0) continue
            const originalExpected = patternBytes[index]!
            const expected = asciiCaseInsensitive
                ? asciiLowercaseByte(originalExpected)
                : originalExpected
            if (expected === 0x2a) next[index] = 1
            else if (expected === 0x3f || expected === byte) next[index + 1] = 1
        }
        applyStarClosure(next, patternBytes)
        for (const state of next) {
            if (state === 0) continue
            active = true
            break
        }
        if (!active) return false
        const previous = states
        states = next
        next = previous
    }
    return states[patternBytes.length] === 1
}

export function asciiLowercaseBytes(value: Buffer): Buffer {
    const lowered = Buffer.from(value)
    for (let index = 0; index < lowered.length; index++) {
        lowered[index] = asciiLowercaseByte(lowered[index]!)
    }
    return lowered
}

function asciiLowercaseByte(value: number): number {
    return value >= 0x41 && value <= 0x5a ? value + 0x20 : value
}

function applyStarClosure(states: Uint8Array, pattern: Uint8Array): void {
    for (let index = 0; index < pattern.length; index++) {
        if (states[index] === 1 && pattern[index] === 0x2a) states[index + 1] = 1
    }
}
