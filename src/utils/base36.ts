import assert from "assert"
import { randomInt } from "crypto"

const charset = "0123456789abcdefghijklmnopqrstuvwxyz"
assert(charset.length === 36, "base36 charset.length != 36")

export function encodeToBase36(n: bigint, length?: number) {
    let str = ""
    while (n != 0n) {
        // encode n to base36
        str = charset[Number(n % 36n)] + str
        n /= 36n
    }

    if (length) {
        assert(str.length <= length)

        // pad str
        str = str.padStart(length, charset[0])
    }

    return str
}

export function randomBase36(length: number) {
    const n = BigInt(randomInt(36 ** length))
    return encodeToBase36(n, length)
}
