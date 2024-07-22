import Agent, { AgentError, AgentType } from "./Agent.js"
import PublicKey from "../utils/PublicKey.js"

export default class NoneAgent implements Agent<never> {
    type = AgentType.NonInteractive

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    async sign(id: never, data: Buffer): Promise<Buffer> {
        throw new NoneAgentError("NoneAgent does not have signing capabilities")
    }

    async getPublicKeys(): Promise<never[]> {
        return []
    }

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    async getPublicKey(id: never): Promise<PublicKey> {
        throw new NoneAgentError("NoneAgent does not store any public key")
    }
}

export class NoneAgentError extends AgentError {
    name = "NoneAgentError"
}
