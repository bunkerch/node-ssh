export function validateSSHName(value: string, field = "SSH name"): void {
    if (value.length === 0 || value.length > 64 || !/^[\x21-\x7e]+$/u.test(value)) {
        throw new Error(`${field} must be 1 to 64 printable US-ASCII characters`)
    }
    if (value.includes(",")) throw new Error(`${field} must not contain a comma`)

    const firstAt = value.indexOf("@")
    if (firstAt === -1) return
    if (firstAt === 0 || firstAt !== value.lastIndexOf("@")) {
        throw new Error(`${field} must contain at most one non-leading at-sign`)
    }
    validateDomainName(value.slice(firstAt + 1), field)
}

export function encodeSSHName(value: string, field = "SSH name"): Buffer {
    validateSSHName(value, field)
    return Buffer.from(value, "ascii")
}

export function decodeSSHName(value: Buffer, field = "SSH name"): string {
    if (value.some((byte) => byte > 0x7f)) {
        throw new Error(`${field} must be US-ASCII`)
    }
    const decoded = value.toString("ascii")
    validateSSHName(decoded, field)
    return decoded
}

function validateDomainName(value: string, field: string): void {
    const withoutRoot = value.endsWith(".") ? value.slice(0, -1) : value
    if (withoutRoot.length === 0 || withoutRoot.length > 253) {
        throw new Error(`${field} extension domain is invalid`)
    }
    const labels = withoutRoot.split(".")
    if (
        labels.some(
            (label) =>
                label.length === 0 ||
                label.length > 63 ||
                !/^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/u.test(label),
        )
    ) {
        throw new Error(`${field} extension domain is invalid`)
    }
}
