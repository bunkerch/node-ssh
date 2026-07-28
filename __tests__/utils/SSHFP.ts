import { execFile } from "node:child_process"
import { mkdtemp, rm, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { promisify } from "node:util"

import {
    PublicKey,
    SSHFPAlgorithm,
    SSHFPFingerprintType,
    SSHFPRecord,
    verifySSHFP,
} from "../../src/index.js"

const execFileAsync = promisify(execFile)

// RSA, DSA, and ECDSA are RFC 6594 examples; Ed25519 is RFC 7479. The Ed448 key is
// RFC 8032's "Blank" public key in RFC 8709 framing, with its fixed SHA-256 digest.
const vectors = [
    {
        name: "RSA",
        algorithm: SSHFPAlgorithm.RSA,
        publicKey:
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDCUR4JOhxTinzq7QO3bQXW4jmPCCulFsnh8Yi7MKwpMnd96+T7uV7nEwy+6+GWYu98IxFJByIjFXX/a6BXDp3878wezH1DZ2tND/tu/eudz6ErpTFYmnVLyEDARYSzVBNQuIK1UDqvvB6KffJcyt78FpwW27euGkqEkam7GaurPRAgwXehDB/gMwRtXVRZ+13zYWkAmAY+5OAWVmdXuQVm5kjlvcNzto2H3m3nqJtD4J9L1lKPuSVVqwJr4/6hibXJkQEvWpUvdOAUw3frKpNwa932fXFk3ke4rsDjQ/W8GyleMtK3Tx8tE4z1wuowXtYe6Ba8q3LAPs/m2S4pUscx",
        sha1: "dd465c09cfa51fb45020cc83316fff21b9ec74ac",
        sha256: "b049f950d1397b8fee6a61e4d14a9acdc4721e084eff5460bbed80cfaa2ce2cb",
    },
    {
        name: "DSA",
        algorithm: SSHFPAlgorithm.DSA,
        publicKey:
            "ssh-dss AAAAB3NzaC1kc3MAAACBAPVFrc0U36gWaywbfJzjcv8ef13qAX4EJl8Na6xqvXh1t+aCJEdS7soRjtvK4KsNhk78DjdtnfhEhyFKHHNz3i6/c/s9lP0UjV7mRAo6nA7A3Gs6iQElb6O9Fqm6iVSC6bYWilTSB0tYencEEJUoaAua8YQF/uxRzPrReXxGqHnjAAAAFQDC9M/pli8VIVmEGOO0wC1TeUTN4wAAAIEAgA2Fbkbbeo0+u/qw8mQFOFWZpTaqNo7d7jov3majbh5LqEVD7yT3MS1GSGhjgvvhus/ehMTqzYbjTc0szUM9JnwT7xq15P2ZYDK98IVxrw31jMtsUUEmBqB4DUjTurtcaWmJ9LNaP1/k4bMo0/hotnOcOVnIPsTLBFWVvdNRxUAAAACAOZcDcK01NTM1qIIYbBqCffrwjQ+9PmsuSKI6nUzfS4NysXHkdbW5u5VxeXLcwWj5PGbRfoS2P3vwYAmakqgq502wigam18u9nAczUYl+2kOeOiIRrtSmLfpV7thLOAb8k1ESjIlkbn35jKmTcoMFRXbFmkKRTK8OEnWQ8AVg6w8=",
        sha1: "3b6ba6110f5ffcd29469fc1ec2ee25d61718badd",
        sha256: "f9b8a6a460639306f1b38910456a6ae1018a253c47ecec12db77d7a0878b4d83",
    },
    {
        name: "ECDSA",
        algorithm: SSHFPAlgorithm.ECDSA,
        publicKey:
            "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAD+9COUiX7WYgcvIOdI8+djdoFDVUTxNrcog8sSYdbIzeG+bYdsssvcyy/nRfVhXC5QBCk8IThqs7D4/lFxX5g=",
        sha1: "c64607a28c5300fec1180b6e417b922943cffcdd",
        sha256: "821eb6c1c98d9cc827ab7f456304c0f14785b7008d9e8646a8519de80849afc7",
    },
    {
        name: "Ed25519",
        algorithm: SSHFPAlgorithm.Ed25519,
        publicKey:
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGPKSUTyz1HwHReFVvD5obVsALAgJRNarH4TRpNePnAS",
        sha256: "a87f1b687ac0e57d2a081a2f282672334d90ed316d2b818ca9580ea384d92401",
    },
    {
        name: "Ed448",
        algorithm: SSHFPAlgorithm.Ed448,
        publicKey:
            "ssh-ed448 AAAACXNzaC1lZDQ0OAAAADlf10SbWbRh/Sznh+xhatRqHaE0JIWnDh+KDqddgOlneO3xJHabRscGG9Z4PfHlD2zR+hq+r+glYYA=",
        sha256: "d8d7fe1f64d91c7d1e35a6b97c813f7e598cf9303d38531b248c8430244625b7",
    },
] as const

describe("SSHFP records", () => {
    test.each(vectors)("$name matches fixed standard-based fingerprints", (vector) => {
        const publicKey = PublicKey.parseString(vector.publicKey)
        if ("sha1" in vector) {
            expect(SSHFPRecord.fromPublicKey(publicKey, SSHFPFingerprintType.SHA1).toString()).toBe(
                `${vector.algorithm} 1 ${vector.sha1}`,
            )
        }
        const record = SSHFPRecord.fromPublicKey(publicKey)
        expect(record.toString()).toBe(`${vector.algorithm} 2 ${vector.sha256}`)
        expect(record.serialize()).toEqual(
            Buffer.from(`0${vector.algorithm}02${vector.sha256}`, "hex"),
        )
    })

    test("parses binary and presentation RDATA without aliasing caller buffers", () => {
        const fingerprint = Buffer.alloc(32, 0x5a)
        const record = new SSHFPRecord(
            SSHFPAlgorithm.Ed448,
            SSHFPFingerprintType.SHA256,
            fingerprint,
        )
        fingerprint.fill(0)
        expect(record.fingerprint).toEqual(Buffer.alloc(32, 0x5a))

        const exposed = record.fingerprint
        exposed.fill(0)
        expect(record.fingerprint).toEqual(Buffer.alloc(32, 0x5a))
        expect(SSHFPRecord.parse(record.serialize()).toString()).toBe(record.toString())
        expect(SSHFPRecord.parseText(`  6  2  ${"5A".repeat(32)}  `).toString()).toBe(
            record.toString(),
        )
    })

    test("preserves unknown assigned fields for future-compatible DNS processing", () => {
        const record = SSHFPRecord.parse(Buffer.from([99, 77, 1, 2, 3]))
        expect(record.algorithm).toBe(99)
        expect(record.fingerprintType).toBe(77)
        expect(record.fingerprint).toEqual(Buffer.from([1, 2, 3]))
        expect(record.serialize()).toEqual(Buffer.from([99, 77, 1, 2, 3]))
    })

    test("rejects malformed, truncated, oversized, and contradictory records", () => {
        expect(() => SSHFPRecord.parse(Buffer.from([4, 2]))).toThrow("truncated")
        expect(() => SSHFPRecord.parse(Buffer.alloc(65_536))).toThrow("maximum")
        expect(() => SSHFPRecord.parse(Buffer.from([4, 2, 1]))).toThrow("requires 32 bytes")
        expect(() => SSHFPRecord.parseText("4 2 abc")).toThrow("complete octets")
        expect(() => SSHFPRecord.parseText(`4 99 ${"aa".repeat(65_534)}`)).toThrow("maximum")
        expect(() => SSHFPRecord.parseText("host.example SSHFP 4 2 aa")).toThrow(
            "presentation-format",
        )
        expect(() => new SSHFPRecord(-1, 2, Buffer.alloc(32))).toThrow("unsigned octet")
        expect(() => new SSHFPRecord(4, 256, Buffer.alloc(32))).toThrow("unsigned octet")
        expect(() => new SSHFPRecord(4, 99, Buffer.alloc(0))).toThrow("must not be empty")
    })

    test("prefers the complete SHA-256 set and never falls back after a mismatch", () => {
        const publicKey = PublicKey.parseString(vectors[0].publicKey)
        const sha1 = SSHFPRecord.fromPublicKey(publicKey, SSHFPFingerprintType.SHA1)
        const sha256 = SSHFPRecord.fromPublicKey(publicKey)
        const wrongSHA256 = new SSHFPRecord(
            SSHFPAlgorithm.RSA,
            SSHFPFingerprintType.SHA256,
            Buffer.alloc(32),
        )

        expect(verifySSHFP(publicKey, [sha1])).toBe("match")
        expect(verifySSHFP(publicKey, [sha1, wrongSHA256])).toBe("mismatch")
        expect(verifySSHFP(publicKey, [wrongSHA256, sha256])).toBe("match")
        expect(
            verifySSHFP(publicKey, [
                new SSHFPRecord(
                    SSHFPAlgorithm.Ed25519,
                    SSHFPFingerprintType.SHA256,
                    Buffer.alloc(32),
                ),
                new SSHFPRecord(SSHFPAlgorithm.RSA, 99, Buffer.from([1])),
            ]),
        ).toBe("no-supported-records")
    })

    test("does not invent SSHFP assignments for security-key identities", () => {
        const securityKey = PublicKey.parse(
            Buffer.from(
                "0000001a736b2d7373682d65643235353139406f70656e7373682e636f6d00000020d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a000000087373683a74657374",
                "hex",
            ),
        )
        expect(() => SSHFPRecord.fromPublicKey(securityKey)).toThrow("no supported SSHFP code")
        expect(verifySSHFP(securityKey, [])).toBe("no-supported-records")
    })

    test("matches the records generated by the system ssh-keygen", async () => {
        const directory = await mkdtemp(join(tmpdir(), "modernssh-sshfp-"))
        try {
            for (const vector of vectors) {
                if (vector.name === "Ed448") continue
                const path = join(directory, `${vector.name}.pub`)
                await writeFile(path, `${vector.publicKey}\n`, { mode: 0o600 })
                const { stdout } = await execFileAsync("ssh-keygen", [
                    "-r",
                    "host.example",
                    "-f",
                    path,
                ])
                const records = stdout
                    .trim()
                    .split("\n")
                    .map((line) => SSHFPRecord.parseText(line.split(" SSHFP ")[1]))
                const publicKey = PublicKey.parseString(vector.publicKey)
                expect(verifySSHFP(publicKey, records)).toBe("match")
                expect(records.map(String)).toContain(
                    SSHFPRecord.fromPublicKey(publicKey).toString(),
                )
            }
        } finally {
            await rm(directory, { recursive: true, force: true })
        }
    })
})
