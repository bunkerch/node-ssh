import assert from "node:assert"
import { readNextBuffer, serializeBuffer } from "./Buffer.js"
import PublicKey from "./PublicKey.js"
import EncodedSignature from "./Signature.js"

const HOST_KEYS_PROOF_REQUEST = Buffer.from("hostkeys-prove-00@openssh.com", "ascii")

export function createHostKeysProofMessage(sessionId: Buffer, publicKey: PublicKey): Buffer {
    assert(sessionId.length > 0, "SSH host-key proof requires a session identifier")
    return Buffer.concat([
        serializeBuffer(HOST_KEYS_PROOF_REQUEST),
        serializeBuffer(sessionId),
        serializeBuffer(publicKey.serialize()),
    ])
}

export function parseHostKeysProofResponse(
    sessionId: Buffer,
    publicKeys: readonly PublicKey[],
    response: Buffer,
): readonly PublicKey[] {
    const verified: PublicKey[] = []
    let raw = response
    for (const publicKey of publicKeys) {
        let encoded: Buffer
        ;[encoded, raw] = readNextBuffer(raw)
        const signature = EncodedSignature.parse(encoded)
        if (
            publicKey.verifySignature(createHostKeysProofMessage(sessionId, publicKey), signature)
        ) {
            verified.push(publicKey)
        }
    }
    assert(raw.length === 0, "SSH host-key proof response contains extra signatures")
    return Object.freeze(verified)
}
