import crypto from "node:crypto"

import { MACAlgorithm } from "../../algorithms.js"

export default class HMACSHA2512 implements MACAlgorithm {
    static alg_name = "hmac-sha2-512"
    static key_length = 64
    static digest_length = 64
    static encrypt_then_mac = false

    static instantiate(key: Buffer): MACAlgorithm {
        return new HMACSHA2512(key)
    }

    private readonly key: Buffer
    private disposed = false

    constructor(key: Buffer) {
        this.key = Buffer.from(key)
    }

    computeMAC(sequenceNumber: number, packet: Buffer): Buffer {
        if (this.disposed) throw new Error("SSH HMAC-SHA2-512 is disposed")
        const sequence = Buffer.allocUnsafe(4)
        sequence.writeUInt32BE(sequenceNumber)

        const hmac = crypto.createHmac("sha512", this.key)
        hmac.update(sequence)
        hmac.update(packet)
        return hmac.digest()
    }

    dispose(): void {
        if (this.disposed) return
        this.disposed = true
        this.key.fill(0)
    }
}
