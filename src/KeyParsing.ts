import PrivateKey from "./utils/PrivateKey.js"
import PublicKey from "./utils/PublicKey.js"
import { parseRFC4716PublicKey, RFC4716_BEGIN_MARKER } from "./utils/RFC4716.js"
import { isPuTTYPrivateKey } from "./utils/PuTTYPrivateKey.js"
import { decodeSSHUTF8, encodeSSHUTF8 } from "./utils/SSHText.js"

export type ParsedKey = PrivateKey | PublicKey

const OPENSSH_PRIVATE_MAGIC = Buffer.from("openssh-key-v1\0", "ascii")
const PRIVATE_KEY_ARMOR = /^-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----/u
const PUBLIC_KEY_ARMOR = /^-----BEGIN (?:RSA )?PUBLIC KEY-----/u
const AUTHORIZED_KEY_LINE = /^\s*\S+\s+[A-Za-z0-9+/]+=*(?:\s|$)/u

type ClassifiedKeyInput =
    | Readonly<{ format: "text"; value: string }>
    | Readonly<{ format: "binary"; value: Buffer }>

function classifyKeyInput(data: string | Buffer): ClassifiedKeyInput {
    if (typeof data === "string") {
        encodeSSHUTF8(data, "Key input")
        return { format: "text", value: data }
    }

    // Latin-1 preserves every input byte while allowing format routing from ASCII framing.
    // Decode the complete input only after it is known to be text so raw SSH blobs stay opaque.
    const routingText = data.toString("latin1")
    if (
        routingText.startsWith(RFC4716_BEGIN_MARKER) ||
        PRIVATE_KEY_ARMOR.test(routingText) ||
        PUBLIC_KEY_ARMOR.test(routingText) ||
        AUTHORIZED_KEY_LINE.test(routingText)
    ) {
        return { format: "text", value: decodeSSHUTF8(data, "Key input") }
    }
    return { format: "binary", value: data }
}

export function parseKey(data: string | Buffer, passphrase?: string | Buffer): ParsedKey {
    const keys = parseKeys(data, passphrase)
    if (keys.length !== 1) {
        throw new Error("Private key container contains multiple keys; use parseKeys()")
    }
    return keys[0]
}

export function parseKeys(data: string | Buffer, passphrase?: string | Buffer): ParsedKey[] {
    if (isPuTTYPrivateKey(data)) {
        return [PrivateKey.fromPuTTY(data, passphrase)]
    }
    if (
        Buffer.isBuffer(data) &&
        data.subarray(0, OPENSSH_PRIVATE_MAGIC.length).equals(OPENSSH_PRIVATE_MAGIC)
    ) {
        return PrivateKey.parseAll(data, passphrase)
    }

    const input = classifyKeyInput(data)
    if (input.format === "binary") {
        if (passphrase !== undefined) {
            throw new TypeError("A passphrase is only valid for private keys")
        }
        return [PublicKey.parse(input.value)]
    }

    const text = input.value
    if (text.startsWith(RFC4716_BEGIN_MARKER)) {
        if (passphrase !== undefined) {
            throw new TypeError("A passphrase is only valid for private keys")
        }
        return [parseRFC4716PublicKey(text)]
    }
    if (PRIVATE_KEY_ARMOR.test(text)) {
        return PrivateKey.fromStringAll(text, passphrase)
    }
    if (PUBLIC_KEY_ARMOR.test(text)) {
        if (passphrase !== undefined) {
            throw new TypeError("A passphrase is only valid for private keys")
        }
        return [PublicKey.fromPEM(text)]
    }
    if (AUTHORIZED_KEY_LINE.test(text)) {
        if (passphrase !== undefined) {
            throw new TypeError("A passphrase is only valid for private keys")
        }
        return [PublicKey.parseString(text)]
    }
    if (passphrase !== undefined) {
        throw new TypeError("A passphrase is only valid for private keys")
    }
    return [PublicKey.parseString(text)]
}
