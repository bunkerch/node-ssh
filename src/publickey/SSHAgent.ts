import { existsSync } from "fs"
import PublicKey from "../utils/PublicKey.js"
import Agent, { AgentError, AgentType } from "./Agent.js"

export default class SSHAgent implements Agent<string> {
    type = AgentType.NonInteractive
    socketPath: string

    constructor(socketPath?: string) {
        socketPath ??= process.env.SSH_AUTH_SOCK

        if (!socketPath) {
            throw new SSHAgentError(
                `Could not find the ssh agent socket on this machine (with $SSH_AUTH_SOCK); Please specify the correct path manually in the \`new SSHAgent("/path/to/ssh/agent.sock")\` constructor`,
            )
        }

        if (!existsSync(socketPath)) {
            throw new SSHAgentError(
                `SSH Agent socket path does not exist (${JSON.stringify(socketPath)}); Please specify the correct path manually in the \`new SSHAgent("/path/to/ssh/agent.sock")\` constructor`,
            )
        }

        this.socketPath = socketPath
    }

    // TODO: Implement the SSH Agent protocol
    // it is way simpler than ssh. Perhaps another
    // library might be handy here ?

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    sign(id: string, data: Buffer): Promise<Buffer> {
        throw new SSHAgentError("Not implemented")
    }

    getPublicKeys(): Promise<[string, PublicKey][]> {
        throw new SSHAgentError("Not implemented")
    }

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    getPublicKey(id: string): Promise<PublicKey> {
        throw new SSHAgentError("Not implemented")
    }
}

export class SSHAgentError extends AgentError {
    name = "SSHAgentError"
}
