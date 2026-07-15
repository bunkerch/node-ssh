import assert from "node:assert"
import { readNextBuffer, serializeBuffer } from "./Buffer.js"
import PublicKey from "./PublicKey.js"
import EncodedSignature from "./Signature.js"

export const HOST_KEYS_EXTENSION = "hostkeys"
export const HOST_KEYS_EXTENSION_VERSION = Buffer.from("0", "ascii")
export const HOST_KEYS_REQUEST = "hostkeys"
export const HOST_KEYS_PROOF_REQUEST = "hostkeys-prove"
export const HOST_KEYS_PROOF_DOMAIN = "hostkeys-prove-0"
export const LEGACY_HOST_KEYS_REQUEST = "hostkeys-00@openssh.com"
export const LEGACY_HOST_KEYS_PROOF_REQUEST = "hostkeys-prove-00@openssh.com"
export const MAX_HOST_KEYS_PER_REQUEST = 64

export type HostKeysProofDomain =
    | typeof HOST_KEYS_PROOF_DOMAIN
    | typeof LEGACY_HOST_KEYS_PROOF_REQUEST
export type RSASHA2SignatureAlgorithm = "rsa-sha2-256" | "rsa-sha2-512"

export function isRSAHostKey(publicKey: PublicKey): boolean {
    return (
        publicKey.supportsSignatureAlgorithm("ssh-rsa") &&
        publicKey.supportsSignatureAlgorithm("rsa-sha2-256") &&
        publicKey.supportsSignatureAlgorithm("rsa-sha2-512")
    )
}

export function createHostKeysProofMessage(
    proofDomain: HostKeysProofDomain,
    sessionId: Buffer,
    publicKey: PublicKey,
): Buffer {
    assert(sessionId.length > 0, "SSH host-key proof requires a session identifier")
    return Buffer.concat([
        serializeBuffer(Buffer.from(proofDomain, "ascii")),
        serializeBuffer(sessionId),
        serializeBuffer(publicKey.serialize()),
    ])
}

export function parseHostKeysProofResponse(
    sessionId: Buffer,
    publicKeys: readonly PublicKey[],
    response: Buffer,
    proofDomain: HostKeysProofDomain,
    rsaSignatureAlgorithm?: RSASHA2SignatureAlgorithm,
): readonly PublicKey[] {
    const verified: PublicKey[] = []
    let raw = response
    for (const publicKey of publicKeys) {
        let encoded: Buffer
        ;[encoded, raw] = readNextBuffer(raw)
        const signature = EncodedSignature.parse(encoded)
        if (
            isRSAHostKey(publicKey) &&
            (signature.data.alg === "ssh-rsa" ||
                (rsaSignatureAlgorithm !== undefined &&
                    signature.data.alg !== rsaSignatureAlgorithm))
        ) {
            continue
        }
        if (
            publicKey.verifySignature(
                createHostKeysProofMessage(proofDomain, sessionId, publicKey),
                signature,
            )
        ) {
            verified.push(publicKey)
        }
    }
    assert(raw.length === 0, "SSH host-key proof response contains extra signatures")
    return Object.freeze(verified)
}
