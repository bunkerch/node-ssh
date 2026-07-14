import { existsSync, readdirSync } from "node:fs"
import { homedir } from "node:os"
import { join } from "node:path"

import SSHAgent, { SSHAgentError } from "./SSHAgent.js"
import { AgentType } from "./Agent.js"

export class OnePasswordAgentError extends SSHAgentError {
    name = "OnePasswordAgentError"
}

const MANUAL_PATH_INSTRUCTION =
    'Pass the correct path to new OnePasswordAgent("/path/to/1password/agent.sock")'
const WINDOWS_OPENSSH_AGENT_PIPE = String.raw`\\.\pipe\openssh-ssh-agent`

export function discoverOnePasswordAgentSocket(
    platform: NodeJS.Platform = process.platform,
): string {
    switch (platform) {
        case "darwin": {
            const groupContainersDirectory = join(homedir(), "Library/Group Containers")
            let folders: string[]
            try {
                folders = readdirSync(groupContainersDirectory, { withFileTypes: true })
                    .filter((entry) => entry.isDirectory())
                    .map((entry) => entry.name)
                    .filter((name) => /^\w+\.com\.1password$/u.test(name))
            } catch (error) {
                throw new OnePasswordAgentError(
                    `Could not inspect the 1Password group containers. ${MANUAL_PATH_INSTRUCTION}`,
                    { cause: error },
                )
            }

            const sockets = folders
                .map((folder) => join(groupContainersDirectory, folder, "t/agent.sock"))
                .filter((socketPath) => existsSync(socketPath))
            if (sockets.length === 0) {
                throw new OnePasswordAgentError(
                    `Could not find the 1Password agent socket. ${MANUAL_PATH_INSTRUCTION}`,
                )
            }
            if (sockets.length > 1) {
                throw new OnePasswordAgentError(
                    `Found multiple 1Password agent sockets. ${MANUAL_PATH_INSTRUCTION}`,
                )
            }
            return sockets[0]!
        }
        case "linux": {
            const socketPath = join(homedir(), ".1password/agent.sock")
            if (!existsSync(socketPath)) {
                throw new OnePasswordAgentError(
                    `Could not find the 1Password agent socket. ${MANUAL_PATH_INSTRUCTION}`,
                )
            }
            return socketPath
        }
        case "win32":
            return WINDOWS_OPENSSH_AGENT_PIPE
        default:
            throw new OnePasswordAgentError(
                `Unsupported platform: ${platform}. ${MANUAL_PATH_INSTRUCTION}`,
            )
    }
}

export default class OnePasswordAgent extends SSHAgent {
    type = AgentType.Interactive

    constructor(agentSocketPath?: string) {
        super(agentSocketPath || discoverOnePasswordAgentSocket())
    }
}
