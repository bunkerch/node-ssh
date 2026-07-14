import { dirname, join, resolve } from "path"
import Agent, { AgentError, AgentType } from "./Agent.js"
import { homedir } from "os"
import { readFile, readdir } from "fs/promises"
import { existsSync } from "fs"
import PublicKey, { SSHCertificatePublicKey } from "../utils/PublicKey.js"
import assert from "assert"
import PrivateKey from "../utils/PrivateKey.js"
import EncodedSignature from "../utils/Signature.js"

export type DiskAgentPassphrase = string | Buffer
export interface DiskAgentOptions {
    passphrase?:
        | DiskAgentPassphrase
        | ((privateKeyPath: string) => DiskAgentPassphrase | Promise<DiskAgentPassphrase>)
    onInvalidPublicKey?: (error: DiskAgentError, publicKeyPath: string) => void | Promise<void>
}

export default class DiskAgent implements Agent<string> {
    type = AgentType.NonInteractive

    directory: string
    options: DiskAgentOptions
    constructor(directory: string = join(homedir(), ".ssh"), options: DiskAgentOptions = {}) {
        this.directory = resolve(directory)
        this.options = options
    }

    async sign(id: string, data: Buffer, algorithm?: string): Promise<EncodedSignature> {
        if (!Buffer.isBuffer(data)) throw new TypeError("Disk agent signing data must be a buffer")
        const message = Buffer.from(data)
        const path = resolve(id)

        // getPublicKey already checks if the id is correct
        const pub = await this.getPublicKey(path)
        const content = await readFile(path, "utf-8")

        const configuredPassphrase = this.options.passphrase
        const passphrase =
            typeof configuredPassphrase === "function"
                ? await configuredPassphrase(path)
                : configuredPassphrase
        const privateKey = PrivateKey.fromString(content, passphrase)

        // ensure public keys match before signing
        assert(
            (pub.data.algorithm instanceof SSHCertificatePublicKey
                ? pub.data.algorithm.publicKey
                : pub
            ).equals(privateKey.data.publicKey),
            new DiskAgentError("Stored public key does not match the private key's public key."),
        )

        return privateKey.sign(message, pub.signatureAlgorithmFor(algorithm ?? pub.data.alg))
    }

    async getPublicKeys(): Promise<[string, PublicKey][]> {
        if (!existsSync(this.directory)) {
            return []
        }
        const files = await readdir(this.directory, { withFileTypes: true })
        const keys: [string, PublicKey][] = []

        for (const file of files) {
            if (!file.isFile()) continue

            const privateKeyPath = join(this.directory, file.name)
            const certificatePath = `${privateKeyPath}-cert.pub`
            const publicKeyPath = existsSync(certificatePath)
                ? certificatePath
                : `${privateKeyPath}.pub`
            if (!existsSync(publicKeyPath)) continue

            // this is a private key
            // we can safely parse its public key
            try {
                const content = await readFile(publicKeyPath, "utf-8")
                const publicKey = PublicKey.parseString(content)

                keys.push([privateKeyPath, publicKey])
            } catch (cause) {
                const error = new DiskAgentError(`Could not load public key ${publicKeyPath}`, {
                    cause,
                })
                await this.options.onInvalidPublicKey?.(error, publicKeyPath)
            }
        }

        return keys
    }

    async getPublicKey(id: string): Promise<PublicKey> {
        const path = resolve(id)
        if (!existsSync(this.directory)) {
            throw new DiskAgentError("No keys found")
        }
        if (dirname(path) !== this.directory) {
            throw new DiskAgentError("Invalid key")
        }
        if (!existsSync(path)) {
            throw new DiskAgentError("Key not found")
        }

        const certificatePath = `${path}-cert.pub`
        const pubpath = existsSync(certificatePath) ? certificatePath : `${path}.pub`
        if (!existsSync(pubpath)) {
            throw new DiskAgentError("Public key not found")
        }

        try {
            return PublicKey.parseString(await readFile(pubpath, "utf-8"))
        } catch (cause) {
            throw new DiskAgentError(`Could not load public key ${pubpath}`, { cause })
        }
    }
}

export class DiskAgentError extends AgentError {
    name = "DiskAgentError"
}
