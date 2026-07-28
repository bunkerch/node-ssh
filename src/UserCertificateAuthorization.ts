import { BlockList, isIP } from "node:net"
import type ServerClient from "./ServerClient.js"
import type { SSHCertificateOption, SSHCertificatePublicKey } from "./utils/PublicKey.js"
import type EncodedSignature from "./utils/Signature.js"
import { readNextBuffer } from "./utils/Buffer.js"
import { decodeSSHUTF8 } from "./utils/SSHText.js"
import { matchesWildcardBytes } from "./utils/Wildcard.js"

export type UserCertificateFeature = "agent-forwarding" | "port-forwarding" | "pty" | "x11"

export interface UserCertificateAuthorization {
    readonly agentForwarding: boolean
    readonly portForwarding: boolean
    readonly pty: boolean
    readonly x11: boolean
    readonly forceCommand?: string
    readonly requireUserPresence: boolean
    readonly requireUserVerification: boolean
    readonly unhandledCriticalOptions: readonly string[]
}

const authorizationByClient = new WeakMap<ServerClient, Readonly<UserCertificateAuthorization>>()

const FLAG_EXTENSIONS = new Map<string, "agentForwarding" | "portForwarding" | "pty" | "x11">([
    ["permit-agent-forwarding", "agentForwarding"],
    ["permit-port-forwarding", "portForwarding"],
    ["permit-pty", "pty"],
    ["permit-X11-forwarding", "x11"],
])

const USER_PRESENCE = 0x01
const USER_VERIFICATION = 0x04

export function evaluateUserCertificateAuthorization(
    certificate: Pick<SSHCertificatePublicKey, "data">,
    remoteAddress: string | undefined,
): Readonly<UserCertificateAuthorization> | undefined {
    const securityKey = certificate.data.publicKey.data.alg.startsWith("sk-")
    const authorization: {
        agentForwarding: boolean
        portForwarding: boolean
        pty: boolean
        x11: boolean
        forceCommand?: string
        requireUserPresence: boolean
        requireUserVerification: boolean
        unhandledCriticalOptions: string[]
    } = {
        agentForwarding: false,
        portForwarding: false,
        pty: false,
        x11: false,
        requireUserPresence: securityKey,
        requireUserVerification: false,
        unhandledCriticalOptions: [],
    }

    for (const extension of certificate.data.extensions) {
        if (extension.name === "no-touch-required") {
            if (extension.data.length !== 0) return undefined
            if (securityKey) authorization.requireUserPresence = false
            continue
        }
        if (extension.name === "permit-user-rc") {
            if (extension.data.length !== 0) return undefined
            continue
        }
        const feature = FLAG_EXTENSIONS.get(extension.name)
        if (feature === undefined) continue
        if (extension.data.length !== 0) return undefined
        authorization[feature] = true
    }

    for (const option of certificate.data.criticalOptions) {
        switch (option.name) {
            case "force-command": {
                const command = nestedUTF8(option, "certificate force-command")
                if (command === undefined) return undefined
                authorization.forceCommand = command
                break
            }
            case "source-address": {
                const list = nestedUTF8(option, "certificate source-address")
                if (
                    list === undefined ||
                    remoteAddress === undefined ||
                    !sourceAddressMatches(list, remoteAddress)
                ) {
                    return undefined
                }
                break
            }
            case "verify-required":
                if (option.data.length !== 0 || !securityKey) return undefined
                authorization.requireUserVerification = true
                break
            default:
                authorization.unhandledCriticalOptions.push(option.name)
        }
    }

    return Object.freeze({
        ...authorization,
        unhandledCriticalOptions: Object.freeze([...authorization.unhandledCriticalOptions]),
    })
}

export function userCertificateSignaturePermitted(
    authorization: Readonly<UserCertificateAuthorization>,
    signature: EncodedSignature,
): boolean {
    const flags = signature.data.securityKey?.flags
    if (
        authorization.requireUserPresence &&
        (flags === undefined || (flags & USER_PRESENCE) === 0)
    ) {
        return false
    }
    if (
        authorization.requireUserVerification &&
        (flags === undefined || (flags & USER_VERIFICATION) === 0)
    ) {
        return false
    }
    return true
}

export function mergeUserCertificateAuthorization(
    current: Readonly<UserCertificateAuthorization> | undefined,
    next: Readonly<UserCertificateAuthorization>,
): Readonly<UserCertificateAuthorization> | undefined {
    if (current === undefined) return next
    if (
        current.forceCommand !== undefined &&
        next.forceCommand !== undefined &&
        current.forceCommand !== next.forceCommand
    ) {
        return undefined
    }
    return Object.freeze({
        agentForwarding: current.agentForwarding && next.agentForwarding,
        portForwarding: current.portForwarding && next.portForwarding,
        pty: current.pty && next.pty,
        x11: current.x11 && next.x11,
        forceCommand: current.forceCommand ?? next.forceCommand,
        requireUserPresence: current.requireUserPresence || next.requireUserPresence,
        requireUserVerification: current.requireUserVerification || next.requireUserVerification,
        unhandledCriticalOptions: Object.freeze([
            ...new Set([...current.unhandledCriticalOptions, ...next.unhandledCriticalOptions]),
        ]),
    })
}

export function userCertificateCriticalOptionsPermitted(
    authorization: Readonly<UserCertificateAuthorization>,
    handled: readonly string[] | undefined,
): boolean {
    if (
        handled !== undefined &&
        (!Array.isArray(handled) || handled.some((name) => typeof name !== "string"))
    ) {
        throw new TypeError("SSH handled certificate critical options must be an array of strings")
    }
    if (authorization.unhandledCriticalOptions.length === 0) return true
    if (handled === undefined) return false
    const acknowledged = new Set(handled)
    return authorization.unhandledCriticalOptions.every((name) => acknowledged.has(name))
}

export function userCertificatePermits(
    client: ServerClient,
    feature: UserCertificateFeature,
): boolean {
    const authorization = authorizationByClient.get(client)
    if (authorization === undefined) return true
    switch (feature) {
        case "agent-forwarding":
            return authorization.agentForwarding
        case "port-forwarding":
            return authorization.portForwarding
        case "pty":
            return authorization.pty
        case "x11":
            return authorization.x11
    }
}

export function userCertificateForceCommand(client: ServerClient): string | undefined {
    return authorizationByClient.get(client)?.forceCommand
}

export function setUserCertificateAuthorization(
    client: ServerClient,
    authorization: Readonly<UserCertificateAuthorization> | undefined,
): void {
    if (authorization === undefined) {
        authorizationByClient.delete(client)
    } else {
        authorizationByClient.set(client, authorization)
    }
}

function nestedUTF8(option: SSHCertificateOption, name: string): string | undefined {
    try {
        const [value, remaining] = readNextBuffer(option.data)
        if (remaining.length !== 0) return undefined
        const decoded = decodeSSHUTF8(value, name)
        return decoded.includes("\0") ? undefined : decoded
    } catch {
        return undefined
    }
}

function sourceAddressMatches(list: string, remoteAddress: string): boolean {
    const family = isIP(remoteAddress)
    if (family === 0 || list.includes("\0")) return false
    const entries = list.length === 0 ? [] : list.split(",")
    return entries.some((entry) => addressEntryMatches(entry, remoteAddress, family as 4 | 6))
}

function addressEntryMatches(entry: string, remoteAddress: string, family: 4 | 6): boolean {
    if (entry.length === 0 || entry.trim() !== entry) return false
    if (entry.includes("*") || entry.includes("?")) {
        return (
            /^[0-9A-Fa-f:.?*]+$/u.test(entry) &&
            matchesWildcardBytes(entry, remoteAddress, family === 6)
        )
    }

    const separator = entry.lastIndexOf("/")
    const address = separator === -1 ? entry : entry.slice(0, separator)
    if (isIP(address) !== family) return false
    try {
        const blockList = new BlockList()
        const type = family === 4 ? "ipv4" : "ipv6"
        if (separator === -1) {
            blockList.addAddress(address, type)
        } else {
            const prefixText = entry.slice(separator + 1)
            if (!/^(?:0|[1-9][0-9]*)$/u.test(prefixText)) return false
            const prefix = Number(prefixText)
            if (prefix > (family === 4 ? 32 : 128)) return false
            blockList.addSubnet(address, prefix, type)
        }
        return blockList.check(remoteAddress, type)
    } catch {
        return false
    }
}
