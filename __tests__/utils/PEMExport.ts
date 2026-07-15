import { execFile } from "node:child_process"
import { mkdtemp, rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { promisify } from "node:util"

const execFileAsync = promisify(execFile)

const cases = [
    { name: "ed25519", type: "ed25519" },
    { name: "ed448", type: "ed448" },
    { name: "rsa", type: "rsa", bits: 1024 },
    { name: "dsa", type: "dsa" },
    { name: "ecdsa-p256", type: "ecdsa", bits: 256 },
    { name: "ecdsa-p384", type: "ecdsa", bits: 384 },
    { name: "ecdsa-p521", type: "ecdsa", bits: 521 },
]

describe("portable PEM export", () => {
    test("round-trips every locally generated key family through SPKI and PKCS#8", async () => {
        const directory = await mkdtemp(join(tmpdir(), "modernssh-pem-export-"))
        try {
            const script = `
                import { writeFile } from "node:fs/promises"
                import { join } from "node:path"
                import { generateKeyPairSync } from "./dist/KeyGeneration.js"
                import PrivateKey from "./dist/utils/PrivateKey.js"
                import PublicKey from "./dist/utils/PublicKey.js"

                const directory = process.argv[1]
                const cases = ${JSON.stringify(cases)}
                for (const keyCase of cases) {
                    const { privateKey, publicKey } = generateKeyPairSync(keyCase.type, {
                        bits: keyCase.bits,
                    })
                    const publicPEM = publicKey.toPEM()
                    const privatePEM = privateKey.toPEM()
                    if (!publicPEM.startsWith("-----BEGIN PUBLIC KEY-----\\n")) process.exit(2)
                    if (!privatePEM.startsWith("-----BEGIN PRIVATE KEY-----\\n")) process.exit(3)
                    if (!PublicKey.fromPEM(publicPEM).equals(publicKey)) process.exit(4)
                    const parsedPrivate = PrivateKey.fromPEM(privatePEM)
                    if (!parsedPrivate.data.publicKey.equals(publicKey)) process.exit(5)
                    const message = Buffer.from("PEM export " + keyCase.name)
                    if (!parsedPrivate.data.publicKey.verifySignature(message, parsedPrivate.sign(message))) {
                        process.exit(6)
                    }
                    await writeFile(join(directory, keyCase.name + ".pub.pem"), publicPEM, {
                        mode: 0o600,
                    })
                    await writeFile(join(directory, keyCase.name + ".key.pem"), privatePEM, {
                        mode: 0o600,
                    })
                }
            `
            await execFileAsync("node", ["--input-type=module", "--eval", script, directory])

            for (const keyCase of cases) {
                const publicPath = join(directory, `${keyCase.name}.pub.pem`)
                const privatePath = join(directory, `${keyCase.name}.key.pem`)
                await execFileAsync("openssl", ["pkey", "-pubin", "-in", publicPath, "-noout"])
                await execFileAsync("openssl", ["pkey", "-in", privatePath, "-check", "-noout"])
            }
        } finally {
            await rm(directory, { recursive: true, force: true })
        }
    }, 20_000)
})
