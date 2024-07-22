import PublicKey from "../utils/PublicKey.js"
import EncodedSignature from "../utils/Signature.js"

export enum AgentType {
    Interactive,
    NonInteractive,
}

export default abstract class Agent<Id = string> {
    abstract type: AgentType

    abstract sign(id: Id, data: Buffer): Promise<EncodedSignature>
    abstract getPublicKeys(): Promise<[Id, PublicKey][]>
    abstract getPublicKey(id: Id): Promise<PublicKey>
}

export class AgentError extends Error {
    name = "AgentError"
}
