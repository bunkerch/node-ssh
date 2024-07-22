import { join } from "path"
import { AgentType } from "./Agent.js"
import { homedir } from "os"
import { existsSync, readdirSync } from "fs"
import SSHAgent, { SSHAgentError } from "./SSHAgent.js"

// this agent is a wrapper around SSHAgent that
// only autofills the socket path to 1Password's
// This also sets the Agent type to Interactive
export default class OnePasswordAgent extends SSHAgent {
    type = AgentType.Interactive

    constructor(agentSocketPath?: string) {
        if (!agentSocketPath) {
            switch (process.platform) {
                // macOS
                case "darwin": {
                    // socket should be located at:
                    // ~/Library/Group Containers/*.com.1password/t/agent.sock
                    const groupContainersDirectory = join(homedir(), "Library/Group Containers")
                    const folders = readdirSync(groupContainersDirectory, {
                        withFileTypes: true,
                    })
                        .filter((f) => f.isDirectory())
                        .map((f) => f.name)
                        .filter((f) => /^\w+\.com\.1password$/.test(f))

                    if (!folders.length) {
                        throw new OnePasswordAgentError(
                            `Could not find the 1Password agent socket on this machine; Please specify the correct path manually in the \`new OnePasswordAgent("/path/to/1password/agent.sock")\` constructor`,
                        )
                    }

                    const sockets = []
                    for (const folder of folders) {
                        const socketPath = join(groupContainersDirectory, folder, "t/agent.sock")
                        if (!existsSync(socketPath)) continue

                        sockets.push(socketPath)
                    }

                    if (!sockets.length) {
                        throw new OnePasswordAgentError(
                            `Could not find the 1Password agent socket on this machine; Please specify the correct path manually in the \`new OnePasswordAgent("/path/to/1password/agent.sock")\` constructor`,
                        )
                    }

                    if (sockets.length > 1) {
                        throw new OnePasswordAgentError(
                            `Found multiple 1Password socket; Please specify the correct path manually in the \`new OnePasswordAgent("/path/to/1password/agent.sock")\` constructor`,
                        )
                    }

                    agentSocketPath = sockets[0]
                    break
                }
                // linux
                case "linux": {
                    // socket should be located at:
                    // ~/.1password/agent.sock

                    const socketPath = join(homedir(), ".1password/agent.sock")
                    if (!existsSync(socketPath)) {
                        throw new OnePasswordAgentError(
                            `Could not find the 1Password agent socket on this machine; Please specify the correct path manually in the \`new OnePasswordAgent("/path/to/1password/agent.sock")\` constructor`,
                        )
                    }

                    agentSocketPath = socketPath
                    break
                }
                // TODO: Add support for other linux/windows ?
                default: {
                    throw new OnePasswordAgentError(
                        `Unsupported platform: ${process.platform}. Please specify the correct path manually in the \`new OnePasswordAgent("/path/to/1password/agent.sock")\` constructor`,
                    )
                }
            }
        }

        super(agentSocketPath)
    }
}

export class OnePasswordAgentError extends SSHAgentError {
    name = "OnePasswordAgentError"
}
