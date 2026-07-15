import { spawn } from "node:child_process"
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"

import { describe, expect, test } from "bun:test"

import SSHSignature from "../../src/SSHSignature.js"
import PrivateKeyAgent from "../../src/publickey/PrivateKeyAgent.js"
import { serializeBuffer, serializeUint32 } from "../../src/utils/Buffer.js"
import PrivateKey from "../../src/utils/PrivateKey.js"
import PublicKey from "../../src/utils/PublicKey.js"

// Independently assembled with RFC 8032's first Ed25519 key and the documented SSHSIG layout.
const fixedSignature = `-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAg11qYAYKxCrfVS/7TyWQHOg7hcv
PapiMlrwIaaPcHURoAAAAEdGVzdAAAAAAAAAAGc2hhNTEyAAAAUwAAAAtzc2gtZWQyNTUx
OQAAAEASKU4yLQKfZVLzaVAndAcFo49+BBHuHmNXBcxn4MO644JOM12hKoL8C5NdNfG6Ff
Pk3ehwH7K1E2kaD/KM2H0B
-----END SSH SIGNATURE-----
`

interface ProcessResult {
    readonly stdout: string
    readonly stderr: string
}

function runWithInput(
    executable: string,
    args: readonly string[],
    input: Buffer,
): Promise<ProcessResult> {
    return new Promise((resolve, reject) => {
        const child = spawn(executable, args, { stdio: "pipe" })
        const stdout: Buffer[] = []
        const stderr: Buffer[] = []
        child.stdout.on("data", (data: Buffer) => stdout.push(Buffer.from(data)))
        child.stderr.on("data", (data: Buffer) => stderr.push(Buffer.from(data)))
        child.once("error", reject)
        child.once("close", (code, signal) => {
            const result = {
                stdout: Buffer.concat(stdout).toString("utf8"),
                stderr: Buffer.concat(stderr).toString("utf8"),
            }
            if (code === 0) resolve(result)
            else reject(new Error(`${executable} exited with ${code ?? signal}: ${result.stderr}`))
        })
        child.stdin.end(input)
    })
}

describe("detached SSH signatures", () => {
    test("parses and serializes an independently assembled fixed signature", () => {
        const parsed = SSHSignature.parse(fixedSignature)

        expect(parsed.version).toBe(1)
        expect(parsed.namespace).toEqual(Buffer.from("test"))
        expect(parsed.reserved).toEqual(Buffer.alloc(0))
        expect(parsed.hashAlgorithm).toBe("sha512")
        expect(parsed.publicKey.data.alg).toBe("ssh-ed25519")
        expect(parsed.signature.data.alg).toBe("ssh-ed25519")
        expect(parsed.verify(Buffer.from("SSHSIG fixed vector"), "test")).toBeTrue()
        expect(parsed.toString()).toBe(fixedSignature)
        expect(SSHSignature.parse(parsed.serialize()).toString()).toBe(fixedSignature)
    })

    test("binds verification to the message and expected namespace", () => {
        const privateKey = PrivateKey.generateSync("ssh-ed25519")
        const namespace = Buffer.from("artifact")
        const message = Buffer.from("release contents")
        const signature = SSHSignature.sign(message, privateKey, {
            namespace,
            hashAlgorithm: "sha256",
        })
        namespace.fill(0)

        expect(signature.hashAlgorithm).toBe("sha256")
        expect(signature.verify(message, "artifact")).toBeTrue()
        expect(signature.verify(Buffer.from("changed contents"), "artifact")).toBeFalse()
        expect(signature.verify(message, "another-domain")).toBeFalse()
        const exposedNamespace = signature.namespace
        exposedNamespace.fill(0)
        expect(signature.verify(message, "artifact")).toBeTrue()
    })

    test("owns data before awaiting an agent and verifies its answer", async () => {
        const privateKey = PrivateKey.generateSync("ssh-ed25519")
        const agent = new PrivateKeyAgent(privateKey)
        const message = Buffer.from("agent-backed contents")
        const expected = Buffer.from(message)

        const signing = SSHSignature.signWithAgent(message, agent, "0", {
            namespace: "artifact",
        })
        message.fill(0)
        const signature = await signing

        expect(signature.publicKey.equals(privateKey.data.publicKey)).toBeTrue()
        expect(signature.verify(expected, "artifact")).toBeTrue()
        expect(signature.verify(message, "artifact")).toBeFalse()

        class InvalidAgent extends PrivateKeyAgent {
            override async sign(id: string, _data: Buffer, algorithm?: string) {
                return super.sign(id, Buffer.from("wrong preimage"), algorithm)
            }
        }
        await expect(
            SSHSignature.signWithAgent(expected, new InvalidAgent(privateKey), "0", {
                namespace: "artifact",
            }),
        ).rejects.toThrow("invalid detached signature")

        const expectedPublicKey = PublicKey.parse(privateKey.data.publicKey.serialize())
        const replacement = PrivateKey.generateSync("ssh-ed25519").data.publicKey
        class MutatingAgent extends PrivateKeyAgent {
            override async sign(id: string, data: Buffer, algorithm?: string) {
                const result = await super.sign(id, data, algorithm)
                data.fill(0)
                privateKey.data.publicKey.data = { ...replacement.data }
                return result
            }
        }
        const isolated = await SSHSignature.signWithAgent(
            expected,
            new MutatingAgent(privateKey),
            "0",
            { namespace: "artifact" },
        )
        expect(isolated.publicKey.equals(expectedPublicKey)).toBeTrue()
        expect(isolated.verify(expected, "artifact")).toBeTrue()
    })

    test("validates signing options and agent public keys", async () => {
        const privateKey = PrivateKey.generateSync("ssh-ed25519")
        const agent = new PrivateKeyAgent(privateKey)
        const message = Buffer.from("validation")

        expect(() => SSHSignature.sign(message, privateKey, null as never)).toThrow(
            "SSH signature options must be an object",
        )
        await expect(
            SSHSignature.signWithAgent(message, agent, "0", null as never),
        ).rejects.toThrow("SSH signature options must be an object")

        class InvalidPublicKeyAgent extends PrivateKeyAgent {
            override async getPublicKey(): Promise<PublicKey> {
                return null as never
            }
        }
        await expect(
            SSHSignature.signWithAgent(message, new InvalidPublicKeyAgent(privateKey), "0", {
                namespace: "artifact",
            }),
        ).rejects.toThrow("agent returned an invalid public key")
    })

    test("rejects malformed armor and unsupported fields", () => {
        const binary = SSHSignature.parse(fixedSignature).serialize()
        const futureVersion = Buffer.from(binary)
        futureVersion.writeUInt32BE(2, 6)

        expect(() => SSHSignature.parse(futureVersion)).toThrow("Unsupported SSH signature")
        expect(() => SSHSignature.parse(Buffer.concat([binary, Buffer.from([0])]))).toThrow(
            "trailing data",
        )
        expect(() => SSHSignature.parse(fixedSignature.replace("U1NI", "U1N!"))).toThrow("base64")
        expect(() => SSHSignature.parse(fixedSignature.replace("BEGIN", "START"))).toThrow("header")
        expect(() =>
            SSHSignature.parse(Buffer.from([0xff, ...Buffer.from(fixedSignature)])),
        ).toThrow("ASCII")
        const privateKey = PrivateKey.generateSync("ssh-ed25519")
        expect(() => SSHSignature.sign(Buffer.alloc(0), privateKey, { namespace: "" })).toThrow(
            "must not be empty",
        )
        expect(() =>
            SSHSignature.sign(Buffer.alloc(0), privateKey, { namespace: Buffer.from([0]) }),
        ).toThrow("must not contain NUL")
        expect(() =>
            SSHSignature.sign(Buffer.alloc(0), privateKey, {
                namespace: "file",
                hashAlgorithm: "sha1" as never,
            }),
        ).toThrow("Unsupported SSH signature hash algorithm")

        const rsa = PrivateKey.generateSync("ssh-rsa")
        const rsaSHA1 = rsa.sign(Buffer.alloc(0), "ssh-rsa").serialize()
        const rsaSHA1Signature = Buffer.concat([
            Buffer.from("SSHSIG"),
            serializeUint32(1),
            serializeBuffer(rsa.data.publicKey.serialize()),
            serializeBuffer(Buffer.from("file")),
            serializeBuffer(Buffer.alloc(0)),
            serializeBuffer(Buffer.from("sha512")),
            serializeBuffer(rsaSHA1),
        ])
        expect(() => SSHSignature.parse(rsaSHA1Signature)).toThrow("require an RSA-SHA2 signature")

        const oversized = Buffer.alloc(1024 * 1024 + 1)
        Buffer.from("SSHSIG").copy(oversized)
        expect(() => SSHSignature.parse(oversized)).toThrow("maximum binary length")
    })

    test.each([
        ["ed25519", []],
        ["rsa", ["-b", "2048"]],
    ])("exchanges %s signatures with ssh-keygen", async (type, keyOptions) => {
        const directory = await mkdtemp(join(tmpdir(), "modernssh-sshsig-"))
        try {
            const keyPath = join(directory, "signer")
            const messagePath = join(directory, "message")
            const signaturePath = join(directory, "library.sig")
            const allowedSignersPath = join(directory, "allowed_signers")
            const message = Buffer.from(`detached ${type} signature\n`)
            await runWithInput(
                "ssh-keygen",
                ["-q", "-t", type, ...keyOptions, "-N", "", "-f", keyPath],
                Buffer.alloc(0),
            )
            const privateKey = PrivateKey.fromString(await readFile(keyPath, "utf8"))
            const publicKey = PublicKey.parseString(await readFile(`${keyPath}.pub`, "utf8"))
            const librarySignature = SSHSignature.sign(message, privateKey, {
                namespace: "file",
                hashAlgorithm: "sha256",
            })
            await writeFile(signaturePath, librarySignature.toString())
            await writeFile(allowedSignersPath, `signer@example.test ${publicKey.toString()}\n`)

            const verified = await runWithInput(
                "ssh-keygen",
                [
                    "-Y",
                    "verify",
                    "-f",
                    allowedSignersPath,
                    "-I",
                    "signer@example.test",
                    "-n",
                    "file",
                    "-s",
                    signaturePath,
                ],
                message,
            )
            expect(verified.stdout).toContain('Good "file" signature')

            await writeFile(messagePath, message)
            await runWithInput(
                "ssh-keygen",
                ["-Y", "sign", "-f", keyPath, "-n", "artifact", messagePath],
                Buffer.alloc(0),
            )
            const systemSignature = SSHSignature.parse(await readFile(`${messagePath}.sig`))
            expect(systemSignature.publicKey.equals(publicKey)).toBeTrue()
            expect(systemSignature.hashAlgorithm).toBe("sha512")
            expect(systemSignature.verify(message, "artifact")).toBeTrue()
            if (type === "rsa") expect(systemSignature.signature.data.alg).toBe("rsa-sha2-512")
        } finally {
            await rm(directory, { recursive: true, force: true })
        }
    })
})
