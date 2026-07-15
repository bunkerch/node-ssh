import type { ClientOptionsRequired } from "./Client.js"
import type { ServerOptionsRequired } from "./Server.js"

const clientConfigurations = new WeakMap<object, ClientOptionsRequired>()
const clientAuthenticationConfigurations = new WeakMap<object, ClientOptionsRequired>()
const serverConfigurations = new WeakMap<object, ServerOptionsRequired>()

export function registerClientConfiguration(
    owner: object,
    configuration: ClientOptionsRequired,
): void {
    if (clientConfigurations.has(owner)) throw new Error("SSH client configuration already exists")
    clientConfigurations.set(owner, configuration)
}

export function clientConfigurationFor(owner: object): ClientOptionsRequired {
    const configuration = clientConfigurations.get(owner)
    if (!configuration) throw new Error("SSH client configuration is unavailable")
    return configuration
}

export function clientAuthenticationConfigurationFor(owner: object): ClientOptionsRequired {
    return clientAuthenticationConfigurations.get(owner) ?? clientConfigurationFor(owner)
}

export function setClientAuthenticationConfiguration(
    owner: object,
    configuration: ClientOptionsRequired | undefined,
): void {
    if (configuration === undefined) clientAuthenticationConfigurations.delete(owner)
    else clientAuthenticationConfigurations.set(owner, configuration)
}

export function registerServerConfiguration(
    owner: object,
    configuration: ServerOptionsRequired,
): void {
    if (serverConfigurations.has(owner)) throw new Error("SSH server configuration already exists")
    serverConfigurations.set(owner, configuration)
}

export function serverConfigurationFor(owner: object): ServerOptionsRequired {
    const configuration = serverConfigurations.get(owner)
    if (!configuration) throw new Error("SSH server configuration is unavailable")
    return configuration
}
