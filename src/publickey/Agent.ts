import PublicKey from "../utils/PublicKey.js"

export enum AgentType {
    Interactive,
    NonInteractive,
}

export default abstract class Agent<Id = string> {
    abstract type: AgentType

    abstract sign(id: Id, data: Buffer): Promise<Buffer>
    abstract getPublicKeys(): Promise<[Id, PublicKey][]>
    abstract getPublicKey(id: Id): Promise<PublicKey>
}

export class AgentError extends Error {
    name = "AgentError"
}
