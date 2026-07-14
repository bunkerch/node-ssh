export const AGENT_FORWARDING_EXTENSION = "agent-forward"
export const AGENT_FORWARDING_EXTENSION_VERSION = Buffer.from("0", "ascii")

export const RFC9987_AGENT_REQUEST = "agent-req"
export const RFC9987_AGENT_CHANNEL = "agent-connect"
export const LEGACY_AGENT_REQUEST = "auth-agent-req@openssh.com"
export const LEGACY_AGENT_CHANNEL = "auth-agent@openssh.com"

export type AgentForwardingProtocol = "rfc9987" | "legacy"

export const authorizeAgentForwarding = Symbol("authorizeAgentForwarding")

export function agentRequestName(protocol: AgentForwardingProtocol): string {
    return protocol === "rfc9987" ? RFC9987_AGENT_REQUEST : LEGACY_AGENT_REQUEST
}

export function agentChannelType(protocol: AgentForwardingProtocol): string {
    return protocol === "rfc9987" ? RFC9987_AGENT_CHANNEL : LEGACY_AGENT_CHANNEL
}
