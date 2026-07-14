import assert from "assert"
import {
    readNextBuffer,
    readNextUint8,
    readNextUint32,
    serializeBuffer,
    serializeUint32,
} from "./Buffer.js"
import { decodeSSHName, encodeSSHName } from "./SSHName.js"
import { decodeSSHUTF8, encodeSSHUTF8 } from "./SSHText.js"

export const SSH_ED25519_SECURITY_KEY_ALGORITHM = "sk-ssh-ed25519@openssh.com"
export const SSH_ECDSA_SECURITY_KEY_ALGORITHM = "sk-ecdsa-sha2-nistp256@openssh.com"
export const SSH_WEBAUTHN_ECDSA_SECURITY_KEY_ALGORITHM =
    "webauthn-sk-ecdsa-sha2-nistp256@openssh.com"

export interface EncodedWebAuthnSignatureData {
    origin: string
    clientData: Buffer
    extensions: Buffer
}

export interface EncodedSecurityKeySignatureData {
    flags: number
    counter: number
    webAuthn?: EncodedWebAuthnSignatureData
}

export interface EncodedSignatureData {
    alg: string
    data: Buffer
    securityKey?: EncodedSecurityKeySignatureData
}

function isSecurityKeyAlgorithm(algorithm: string): boolean {
    return (
        algorithm === SSH_ED25519_SECURITY_KEY_ALGORITHM ||
        algorithm === SSH_ECDSA_SECURITY_KEY_ALGORITHM ||
        algorithm === SSH_WEBAUTHN_ECDSA_SECURITY_KEY_ALGORITHM
    )
}

function validateSecurityKeyData(data: EncodedSignatureData): void {
    const details = data.securityKey
    if (!isSecurityKeyAlgorithm(data.alg)) {
        assert(details === undefined, "Security-key metadata requires a security-key algorithm")
        return
    }
    assert(details, "Security-key signature metadata is required")
    assert(Number.isInteger(details.flags) && details.flags >= 0 && details.flags <= 0xff)
    assert(
        Number.isInteger(details.counter) && details.counter >= 0 && details.counter <= 0xffff_ffff,
    )
    const webAuthn = details.webAuthn
    if (data.alg !== SSH_WEBAUTHN_ECDSA_SECURITY_KEY_ALGORITHM) {
        assert(webAuthn === undefined, "WebAuthn metadata requires the WebAuthn algorithm")
        return
    }
    assert(webAuthn, "WebAuthn signature metadata is required")
    const origin = encodeSSHUTF8(webAuthn.origin, "WebAuthn signature origin")
    assert(!origin.includes(0), "WebAuthn signature origin must not contain NUL")
    assert(Buffer.isBuffer(webAuthn.clientData), "WebAuthn client data must be a buffer")
    assert(Buffer.isBuffer(webAuthn.extensions), "WebAuthn extensions must be a buffer")
}
export default class EncodedSignature {
    data: EncodedSignatureData
    constructor(data: EncodedSignatureData) {
        encodeSSHName(data.alg, "SSH signature algorithm")
        assert(Buffer.isBuffer(data.data), "SSH signature data must be a buffer")
        validateSecurityKeyData(data)
        this.data = {
            alg: data.alg,
            data: Buffer.from(data.data),
            ...(data.securityKey
                ? {
                      securityKey: {
                          flags: data.securityKey.flags,
                          counter: data.securityKey.counter,
                          ...(data.securityKey.webAuthn
                              ? {
                                    webAuthn: {
                                        origin: data.securityKey.webAuthn.origin,
                                        clientData: Buffer.from(
                                            data.securityKey.webAuthn.clientData,
                                        ),
                                        extensions: Buffer.from(
                                            data.securityKey.webAuthn.extensions,
                                        ),
                                    },
                                }
                              : {}),
                      },
                  }
                : {}),
        }
    }

    serialize(): Buffer {
        validateSecurityKeyData(this.data)
        const buffers: Buffer[] = []

        buffers.push(serializeBuffer(encodeSSHName(this.data.alg, "SSH signature algorithm")))
        buffers.push(serializeBuffer(this.data.data))
        if (this.data.securityKey) {
            buffers.push(
                Buffer.from([this.data.securityKey.flags]),
                serializeUint32(this.data.securityKey.counter),
            )
            const webAuthn = this.data.securityKey.webAuthn
            if (webAuthn) {
                buffers.push(
                    serializeBuffer(encodeSSHUTF8(webAuthn.origin, "WebAuthn signature origin")),
                    serializeBuffer(Buffer.from(webAuthn.clientData)),
                    serializeBuffer(Buffer.from(webAuthn.extensions)),
                )
            }
        }

        return Buffer.concat(buffers)
    }

    static parse(raw: Buffer): EncodedSignature {
        let name: Buffer
        ;[name, raw] = readNextBuffer(raw)

        const algorithm = decodeSSHName(name, "SSH signature algorithm")
        let data: Buffer
        ;[data, raw] = readNextBuffer(raw)

        let securityKey: EncodedSecurityKeySignatureData | undefined
        if (isSecurityKeyAlgorithm(algorithm)) {
            let flags: number
            let counter: number
            ;[flags, raw] = readNextUint8(raw)
            ;[counter, raw] = readNextUint32(raw)
            let webAuthn: EncodedWebAuthnSignatureData | undefined
            if (algorithm === SSH_WEBAUTHN_ECDSA_SECURITY_KEY_ALGORITHM) {
                let origin: Buffer
                let clientData: Buffer
                let extensions: Buffer
                ;[origin, raw] = readNextBuffer(raw)
                ;[clientData, raw] = readNextBuffer(raw)
                ;[extensions, raw] = readNextBuffer(raw)
                webAuthn = {
                    origin: decodeSSHUTF8(origin, "WebAuthn signature origin"),
                    clientData: Buffer.from(clientData),
                    extensions: Buffer.from(extensions),
                }
            }
            securityKey = { flags, counter, ...(webAuthn ? { webAuthn } : {}) }
        }

        assert(raw.length === 0)

        return new EncodedSignature({
            alg: algorithm,
            data,
            ...(securityKey ? { securityKey } : {}),
        })
    }
}
