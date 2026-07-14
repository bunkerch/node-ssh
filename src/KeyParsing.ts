import PrivateKey from "./utils/PrivateKey.js"
import PublicKey from "./utils/PublicKey.js"
import { parseRFC4716PublicKey, RFC4716_BEGIN_MARKER } from "./utils/RFC4716.js"

export type ParsedKey = PrivateKey | PublicKey

const OPENSSH_PRIVATE_MAGIC = Buffer.from("openssh-key-v1\0", "ascii")

export function parseKey(data: string | Buffer, passphrase?: string | Buffer): ParsedKey {
    const keys = parseKeys(data, passphrase)
    if (keys.length !== 1) {
        throw new Error("Private key container contains multiple keys; use parseKeys()")
    }
    return keys[0]
}

export function parseKeys(data: string | Buffer, passphrase?: string | Buffer): ParsedKey[] {
    if (
        Buffer.isBuffer(data) &&
        data.subarray(0, OPENSSH_PRIVATE_MAGIC.length).equals(OPENSSH_PRIVATE_MAGIC)
    ) {
        return PrivateKey.parseAll(data, passphrase)
    }

    const text = Buffer.isBuffer(data) ? data.toString("utf8") : data
    if (text.startsWith(RFC4716_BEGIN_MARKER)) {
        if (passphrase !== undefined) {
            throw new TypeError("A passphrase is only valid for private keys")
        }
        return [parseRFC4716PublicKey(data)]
    }
    if (/^-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----/m.test(text)) {
        return PrivateKey.fromStringAll(text, passphrase)
    }
    if (/^-----BEGIN (?:RSA )?PUBLIC KEY-----/m.test(text)) {
        if (passphrase !== undefined) {
            throw new TypeError("A passphrase is only valid for private keys")
        }
        return [PublicKey.fromPEM(text)]
    }
    if (/^\s*(?:ssh-|ecdsa-)[^\s]+\s+[A-Za-z0-9+/]+=*(?:\s|$)/.test(text)) {
        if (passphrase !== undefined) {
            throw new TypeError("A passphrase is only valid for private keys")
        }
        return [PublicKey.parseString(text)]
    }
    if (passphrase !== undefined) {
        throw new TypeError("A passphrase is only valid for private keys")
    }
    if (Buffer.isBuffer(data)) return [PublicKey.parse(data)]
    return [PublicKey.parseString(data)]
}
