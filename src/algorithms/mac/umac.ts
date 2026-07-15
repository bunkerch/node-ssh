import { MACAlgorithm } from "../../algorithms.js"
import { UMAC, type UMACTagLength } from "../../utils/UMAC.js"

abstract class UMACAlgorithm implements MACAlgorithm {
    static alg_name: string
    static key_length = 16
    static digest_length: UMACTagLength
    static encrypt_then_mac = false

    private readonly umac: UMAC
    private lastSequenceNumber?: number
    private disposed = false
    protected constructor(key: Buffer, tagLength: UMACTagLength) {
        this.umac = new UMAC(key, tagLength)
    }

    computeMAC(sequenceNumber: number, packet: Buffer): Buffer {
        if (this.disposed) throw new Error("SSH UMAC is disposed")
        if (this.lastSequenceNumber !== undefined && sequenceNumber <= this.lastSequenceNumber) {
            throw new Error("SSH UMAC sequence number reuse requires rekeying")
        }
        this.lastSequenceNumber = sequenceNumber
        const nonce = Buffer.alloc(8)
        nonce.writeUInt32BE(sequenceNumber, 4)
        return this.umac.compute(packet, nonce)
    }

    dispose(): void {
        if (this.disposed) return
        this.disposed = true
        this.umac.dispose()
    }
}

export class UMAC64OpenSSH extends UMACAlgorithm {
    static alg_name = "umac-64@openssh.com"
    static key_length = 16
    static digest_length = 8 as const
    static encrypt_then_mac = false

    static instantiate(key: Buffer): MACAlgorithm {
        return new UMAC64OpenSSH(key)
    }

    constructor(key: Buffer) {
        super(key, UMAC64OpenSSH.digest_length)
    }
}

export class UMAC128OpenSSH extends UMACAlgorithm {
    static alg_name = "umac-128@openssh.com"
    static key_length = 16
    static digest_length = 16 as const
    static encrypt_then_mac = false

    static instantiate(key: Buffer): MACAlgorithm {
        return new UMAC128OpenSSH(key)
    }

    constructor(key: Buffer) {
        super(key, UMAC128OpenSSH.digest_length)
    }
}

export class UMAC64ETMOpenSSH extends UMAC64OpenSSH {
    static alg_name = "umac-64-etm@openssh.com"
    static encrypt_then_mac = true

    static instantiate(key: Buffer): MACAlgorithm {
        return new UMAC64ETMOpenSSH(key)
    }
}

export class UMAC128ETMOpenSSH extends UMAC128OpenSSH {
    static alg_name = "umac-128-etm@openssh.com"
    static encrypt_then_mac = true

    static instantiate(key: Buffer): MACAlgorithm {
        return new UMAC128ETMOpenSSH(key)
    }
}
