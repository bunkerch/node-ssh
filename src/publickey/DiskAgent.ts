import { dirname, join, normalize } from "path"
import Agent, { AgentType } from "./Agent.js"
import { homedir } from "os"
import { readFile, readdir } from "fs/promises"
import { existsSync } from "fs"
import PublicKey from "../utils/PublicKey.js"
import assert from "assert"
import PrivateKey from "../utils/PrivateKey.js"

export default class DiskAgent implements Agent<string> {
    type = AgentType.NonInteractive

    directory: string
    constructor(directory: string = join(homedir(), ".ssh")) {
        this.directory = directory
    }

    async sign(id: string, data: Buffer): Promise<Buffer> {
        const path = normalize(id)

        // getPublicKey already checks if the id is correct
        const pub = await this.getPublicKey(path)
        const content = await readFile(path, "utf-8")

        const privateKey = PrivateKey.fromString(content)

        // ensure public keys match before signing
        assert(pub.equals(privateKey.data.publicKey))

        return privateKey.sign(data)
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
            const publicKeyPath = `${privateKeyPath}.pub`
            if (!existsSync(publicKeyPath)) continue

            // this is a private key
            const publicKey = await readFile(publicKeyPath, "utf-8")
            const parts = publicKey.trim().split(" ")

            if (parts.length > 3 || parts.length < 2) continue
            const [alg, key, comment] = parts

            try {
                const publicKey = PublicKey.parse(Buffer.from(key, "base64"))
                assert(alg === publicKey.data.alg)

                if (comment) {
                    publicKey.data.comment = comment
                }

                keys.push([privateKeyPath, publicKey])
            } catch {}
        }

        return keys
    }

    async getPublicKey(id: string): Promise<PublicKey> {
        const path = normalize(id)
        if (!existsSync(this.directory)) {
            throw new Error("No keys found")
        }
        if (dirname(path) !== this.directory) {
            throw new Error("Invalid key")
        }
        if (!existsSync(path)) {
            throw new Error("Key not found")
        }

        const pubpath = `${path}.pub`
        if (!existsSync(pubpath)) {
            throw new Error("Public key not found")
        }

        const publicKey = await readFile(pubpath, "utf-8")
        const parts = publicKey.trim().split(" ")

        if (parts.length > 3 || parts.length < 2) {
            throw new Error("Invalid public key")
        }

        const [alg, key, comment] = parts
        const publicKeyData = PublicKey.parse(Buffer.from(key, "base64"))
        assert(alg === publicKeyData.data.alg)

        if (comment) {
            publicKeyData.data.comment = comment
        }

        return publicKeyData
    }
}
