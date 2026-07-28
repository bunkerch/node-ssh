import type { SSHExtension } from "./packets/ExtInfo.js"

export const GLOBAL_REQUESTS_OK_EXTENSION = "global-requests-ok"

export function globalRequestsOKExtension(): SSHExtension {
    return { name: GLOBAL_REQUESTS_OK_EXTENSION, value: Buffer.alloc(0) }
}

export function supportsGlobalRequests(extensions: readonly SSHExtension[]): boolean {
    return extensions.some(({ name }) => name === GLOBAL_REQUESTS_OK_EXTENSION)
}
