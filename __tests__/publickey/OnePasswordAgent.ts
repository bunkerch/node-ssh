import OnePasswordAgent, {
    discoverOnePasswordAgentSocket,
} from "../../src/publickey/OnePasswordAgent.js"
import { AgentType } from "../../src/publickey/Agent.js"

describe("1Password agent discovery", () => {
    test("uses the documented system-wide Windows OpenSSH pipe", () => {
        expect(discoverOnePasswordAgentSocket("win32")).toBe(String.raw`\\.\pipe\openssh-ssh-agent`)
    })

    test("keeps an explicit path and interactive agent semantics", () => {
        const agent = new OnePasswordAgent("custom-agent.sock")

        expect(agent.socketPath).toBe("custom-agent.sock")
        expect(agent.type).toBe(AgentType.Interactive)
    })
})
