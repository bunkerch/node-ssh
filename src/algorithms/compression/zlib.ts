import { Deflate, Inflate, Z_PARTIAL_FLUSH, Z_SYNC_FLUSH } from "pako"
import type { PacketCompressor, PacketDecompressor } from "../../BinaryPacket.js"

export class SSHZlibCompressor implements PacketCompressor {
    private readonly stream = new Deflate({ level: 6, legacyHash: true })
    private output: Buffer[] = []

    constructor() {
        this.stream.onData = (chunk) => this.output.push(Buffer.from(chunk))
    }

    compress(payload: Buffer): Buffer {
        this.output = []
        if (!this.stream.push(payload, Z_PARTIAL_FLUSH) || this.stream.err !== 0) {
            throw new Error(`SSH zlib compression failed: ${this.stream.msg || this.stream.err}`)
        }
        return Buffer.concat(this.output)
    }
}

export class SSHZlibDecompressor implements PacketDecompressor {
    private readonly stream = new Inflate()
    private output: Buffer[] = []
    private outputLength = 0

    constructor(private readonly maximumPayloadSize: number) {
        this.stream.onData = (chunk) => {
            this.outputLength += chunk.length
            if (this.outputLength > this.maximumPayloadSize) {
                throw new Error(
                    `Decompressed SSH payload exceeds maximum ${this.maximumPayloadSize}`,
                )
            }
            this.output.push(Buffer.from(chunk))
        }
    }

    decompress(payload: Buffer): Buffer {
        this.output = []
        this.outputLength = 0
        if (!this.stream.push(payload, Z_SYNC_FLUSH) || this.stream.err !== 0) {
            throw new Error(`SSH zlib decompression failed: ${this.stream.msg || this.stream.err}`)
        }
        return Buffer.concat(this.output, this.outputLength)
    }
}
