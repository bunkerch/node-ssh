import Agent from "./Agent.js"
import CygwinAgent from "./CygwinAgent.js"
import PageantAgent from "./PageantAgent.js"
import SSHAgent from "./SSHAgent.js"

const WINDOWS_NAMED_PIPE = /^[/\\][/\\]\.[/\\]pipe[/\\].+/u

/** Construct the socket-backed agent appropriate for the current platform and path. */
export function createSocketAgent(socketPath: string): Agent<string> {
    if (process.platform === "win32" && socketPath === "pageant") return new PageantAgent()
    if (process.platform === "win32" && !WINDOWS_NAMED_PIPE.test(socketPath)) {
        return new CygwinAgent(socketPath)
    }
    return new SSHAgent(socketPath)
}
