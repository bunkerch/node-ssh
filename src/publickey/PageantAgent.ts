import { AgentType } from "./Agent.js"
import { discoverPageantAgentSocket, PageantAgentError } from "./PageantDiscovery.js"
import SSHAgent from "./SSHAgent.js"

/** An agent client for Pageant's standard agent-protocol transport. */
export default class PageantAgent extends SSHAgent {
    override type = AgentType.Interactive

    constructor(socketPath = discoverPageantAgentSocket()) {
        super(socketPath)
    }
}

export { discoverPageantAgentSocket, PageantAgentError }
