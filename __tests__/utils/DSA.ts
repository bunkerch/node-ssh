import { execFile } from "node:child_process"
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { promisify } from "node:util"
import { generateKeyPair } from "../../src/KeyGeneration.js"
import PrivateKey, { SSHDSSPrivateKey } from "../../src/utils/PrivateKey.js"
import PublicKey, { SSHDSSPublicKey } from "../../src/utils/PublicKey.js"
import EncodedSignature from "../../src/utils/Signature.js"

const execFileAsync = promisify(execFile)

function mpint(hex: string): Buffer {
    const unsigned = Buffer.from(hex.replace(/\s/g, ""), "hex")
    return (unsigned[0] & 0x80) === 0 ? unsigned : Buffer.concat([Buffer.from([0]), unsigned])
}

const parameters = {
    p: mpint(`
        86F5CA03DCFEB225063FF830A0C769B9DD9D6153AD91D7CE27F787C43278B447
        E6533B86B18BED6E8A48B784A14C252C5BE0DBF60B86D6385BD2F12FB763ED88
        73ABFD3F5BA2E0A8C0A59082EAC056935E529DAF7C610467899C77ADEDFC846C
        881870B7B19B2B58F9BE0521A17002E3BDD6B86685EE90B3D9A1B02B782B1779
    `),
    q: mpint("996F967F6C8E388D9E28D01E205FBA957A5698B1"),
    g: mpint(`
        07B0F92546150B62514BB771E2A0C0CE387F03BDA6C56B505209FF25FD3C133D
        89BBCD97E904E09114D9A7DEFDEADFC9078EA544D2E401AEECC40BB9FBBF78FD
        87995A10A1C27CB7789B594BA7EFB5C4326A9FE59A070E136DB77175464ADCA4
        17BE5DCE2F40D10A46A3A3943F26AB7FD9C0398FF8C76EE0A56826A8A88F1DBD
    `),
    y: mpint(`
        5DF5E01DED31D0297E274E1691C192FE5868FEF9E19A84776454B100CF16F653
        92195A38B90523E2542EE61871C0440CB87C322FC4B4D2EC5E1E7EC766E1BE8D
        4CE935437DC11C3C8FD426338933EBFE739CB3465F4D3668C5E473508253B1E6
        82F65CBDC4FAE93C2EA212390E54905A86E2223170B44EAA7DA5DD9FFCFB7F3B
    `),
    x: mpint("411602CB19A6CCC34494D79D98EF1E7ED5AF25F7"),
}

describe("RFC 4253 DSS keys", () => {
    test("verifies the RFC 6979 DSA-1024/SHA-1 vector in fixed SSH encoding", () => {
        const publicKey = new PublicKey({
            alg: "ssh-dss",
            algorithm: new SSHDSSPublicKey(parameters),
        })
        const signature = new EncodedSignature({
            alg: "ssh-dss",
            data: Buffer.from(
                "2E1A0C2562B2912CAAF89186FB0F42001585DA5529EFB6B0AFF2D7A68EB70CA313022253B9A88DF5",
                "hex",
            ),
        })
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
