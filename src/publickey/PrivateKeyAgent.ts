import Agent, { AgentError, AgentType } from "./Agent.js"
import type EncodedSignature from "../utils/Signature.js"
import type PrivateKey from "../utils/PrivateKey.js"
import type PublicKey from "../utils/PublicKey.js"

export default class PrivateKeyAgent extends Agent<string> {
    readonly type = AgentType.NonInteractive
    private readonly keys: readonly PrivateKey[]

    constructor(keys: PrivateKey | readonly PrivateKey[]) {
        super()
        this.keys = Object.freeze(Array.isArray(keys) ? [...keys] : [keys])
        if (this.keys.length === 0)
            throw new PrivateKeyAgentError("At least one private key is required")
    }

    async getPublicKeys(): Promise<[string, PublicKey][]> {
        return this.keys.map((key, index) => [String(index), key.data.publicKey])
    }

    async getPublicKey(id: string): Promise<PublicKey> {
        return this.key(id).data.publicKey
    }

    async sign(id: string, data: Buffer, algorithm?: string): Promise<EncodedSignature> {
        return this.key(id).sign(data, algorithm)
    }

    private key(id: string): PrivateKey {
        if (!/^(?:0|[1-9][0-9]*)$/.test(id)) {
            throw new PrivateKeyAgentError("Unknown private key identifier")
        }
        const index = Number(id)
        if (!Number.isSafeInteger(index) || index >= this.keys.length) {
            throw new PrivateKeyAgentError("Unknown private key identifier")
        }
        return this.keys[index]
    }
}

export class PrivateKeyAgentError extends AgentError {
    name = "PrivateKeyAgentError"
}
