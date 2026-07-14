import { execFile } from "node:child_process"
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { promisify } from "node:util"
import { generateKeyPair } from "../../src/KeyGeneration.js"
import PrivateKey, { SSHDSSPrivateKey } from "../../src/utils/PrivateKey.js"
import PublicKey, { SSHDSSPublicKey } from "../../src/utils/PublicKey.js"
import EncodedSignature from "../../src/utils/Signature.js"
import {
    rfc6979DSAParameters as parameters,
    rfc6979Mpint as mpint,
} from "../fixtures/DSAParameters.js"

const execFileAsync = promisify(execFile)

describe("RFC 4253 DSS keys", () => {
    test("signs the RFC 6979 DSA-1024/SHA-1 vector in fixed SSH encoding", () => {
        const publicKey = new PublicKey({
            alg: "ssh-dss",
            algorithm: new SSHDSSPublicKey(parameters),
        })
        const privateAlgorithm = new SSHDSSPrivateKey(parameters)
        const privateKey = new PrivateKey({
            alg: "ssh-dss",
            algorithm: privateAlgorithm,
            publicKey: privateAlgorithm.getPublicKey(),
        })
        const signature = new EncodedSignature({
            alg: "ssh-dss",
            data: Buffer.from(
                "2E1A0C2562B2912CAAF89186FB0F42001585DA5529EFB6B0AFF2D7A68EB70CA313022253B9A88DF5",
                "hex",
            ),
        })
        expect(privateKey.sign(Buffer.from("sample"))).toEqual(signature)
        expect(privateKey.sign(Buffer.from("sample"))).toEqual(signature)
        expect(publicKey.verifySignature(Buffer.from("sample"), signature)).toBe(true)
        expect(publicKey.verifySignature(Buffer.from("tampered"), signature)).toBe(false)
        expect(
            publicKey.verifySignature(
                Buffer.from("sample"),
                new EncodedSignature({ alg: "ssh-dss", data: signature.data.data.subarray(1) }),
            ),
        ).toBe(false)

        const fixedBlob = Buffer.concat([
            Buffer.from("000000077373682d647373", "hex"),
            Buffer.from("00000081", "hex"),
            parameters.p,
            Buffer.from("00000015", "hex"),
            parameters.q,
            Buffer.from("00000080", "hex"),
            parameters.g,
            Buffer.from("00000080", "hex"),
            parameters.y,
        ])
        expect(publicKey.serialize()).toEqual(fixedBlob)
        expect(PublicKey.parse(fixedBlob).equals(publicKey)).toBe(true)
    })

    test("signs, serializes, and validates matching private values", () => {
        const algorithm = new SSHDSSPrivateKey(parameters)
        const privateKey = new PrivateKey({
            alg: "ssh-dss",
            publicKey: algorithm.getPublicKey(),
            algorithm,
        })
        const message = Buffer.from("DSS private key")
        const signature = privateKey.sign(message)
        expect(signature.data.data).toHaveLength(40)
        expect(privateKey.data.publicKey.verifySignature(message, signature)).toBe(true)
        expect(() => privateKey.sign(message, "rsa-sha2-256")).toThrow(
            "Unsupported DSA signature algorithm",
        )
        const parsed = PrivateKey.fromString(privateKey.toString())
        expect(parsed.data.publicKey.equals(privateKey.data.publicKey)).toBe(true)
        expect(parsed.data.publicKey.verifySignature(message, parsed.sign(message))).toBe(true)
        expect(() => new SSHDSSPrivateKey({ ...parameters, x: mpint("01") })).toThrow(
            "do not match",
        )
    })

    test("imports OpenSSH and PEM containers and exports a key accepted by ssh-keygen", async () => {
        const directory = await mkdtemp(join(tmpdir(), "modernssh-dss-"))
        try {
            const keyPath = join(directory, "id_dsa")
            await execFileAsync("ssh-keygen", [
                "-q",
                "-t",
                "dsa",
                "-N",
                "",
                "-C",
                "legacy@example.test",
                "-f",
                keyPath,
            ])
            const expected = PublicKey.parseString(await readFile(`${keyPath}.pub`, "utf8"))
            const parsed = PrivateKey.fromString(await readFile(keyPath, "utf8"))
            expect(parsed.data.publicKey.equals(expected)).toBe(true)

            const exportedPath = join(directory, "exported")
            await writeFile(exportedPath, `${parsed.toString()}\n`, { mode: 0o600 })
            const { stdout: derived } = await execFileAsync("ssh-keygen", [
                "-y",
                "-f",
                exportedPath,
            ])
            expect(PublicKey.parseString(derived).equals(expected)).toBe(true)

            const encryptedPath = join(directory, "encrypted")
            await writeFile(
                encryptedPath,
                `${parsed.toString({ passphrase: "legacy-secret", rounds: 1 })}\n`,
                { mode: 0o600 },
            )
            const { stdout: decrypted } = await execFileAsync("ssh-keygen", [
                "-y",
                "-P",
                "legacy-secret",
                "-f",
                encryptedPath,
            ])
            expect(PublicKey.parseString(decrypted).equals(expected)).toBe(true)

            await execFileAsync("ssh-keygen", [
                "-p",
                "-q",
                "-m",
                "PEM",
                "-P",
                "",
                "-N",
                "",
                "-f",
                keyPath,
            ])
            const pem = PrivateKey.fromString(await readFile(keyPath, "utf8"))
            expect(pem.data.publicKey.equals(expected)).toBe(true)
            const { stdout: publicPEM } = await execFileAsync("ssh-keygen", [
                "-e",
                "-m",
                "PKCS8",
                "-f",
                `${keyPath}.pub`,
            ])
            expect(PublicKey.fromPEM(publicPEM).equals(expected)).toBe(true)
        } finally {
            await rm(directory, { recursive: true, force: true })
        }
    })

    test("generates only the fixed RFC 4253 size through the semantic API", async () => {
        const { stdout } = await execFileAsync("node", [
            "--input-type=module",
            "--eval",
            `
                import { generateKeyPair } from "./dist/index.js"
                const { privateKey, publicKey } = await generateKeyPair("dsa", {
                    comment: "legacy@example.test",
                })
                if (privateKey.data.alg !== "ssh-dss") process.exit(2)
                if (!publicKey.toString().endsWith(" legacy@example.test")) process.exit(3)
                if (!publicKey.equals(privateKey.data.publicKey)) process.exit(4)
                process.stdout.write(publicKey.data.alg)
            `,
        ])
        expect(stdout).toBe("ssh-dss")
        await expect(generateKeyPair("dsa", { bits: 2048 })).rejects.toThrow(
            "DSA key generation does not accept bits",
        )
    })

    test("rejects malformed parameters and non-canonical mpints", () => {
        expect(
            () =>
                new SSHDSSPublicKey({
                    ...parameters,
                    q: Buffer.concat([Buffer.from([0]), parameters.q]),
                }),
        ).toThrow("not a canonical mpint")
        expect(() => new SSHDSSPublicKey({ ...parameters, y: mpint("02") })).toThrow("subgroup")
    })
})
