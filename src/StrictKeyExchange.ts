import { PacketNameToType, type PacketType } from "./constants.js"

export const STRICT_KEX_CLIENT_MARKERS = Object.freeze([
    "kex-strict-c",
    "kex-strict-c-v00@openssh.com",
])
export const STRICT_KEX_SERVER_MARKERS = Object.freeze([
    "kex-strict-s",
    "kex-strict-s-v00@openssh.com",
])

const STANDARD_CLIENT_MARKER = STRICT_KEX_CLIENT_MARKERS[0]!
const LEGACY_CLIENT_MARKER = STRICT_KEX_CLIENT_MARKERS[1]!
const STANDARD_SERVER_MARKER = STRICT_KEX_SERVER_MARKERS[0]!
const LEGACY_SERVER_MARKER = STRICT_KEX_SERVER_MARKERS[1]!

export function negotiatesStrictKeyExchange(
    clientAlgorithms: readonly string[],
    serverAlgorithms: readonly string[],
): boolean {
    return (
        (clientAlgorithms.includes(STANDARD_CLIENT_MARKER) &&
            serverAlgorithms.includes(STANDARD_SERVER_MARKER)) ||
        (clientAlgorithms.includes(LEGACY_CLIENT_MARKER) &&
            serverAlgorithms.includes(LEGACY_SERVER_MARKER))
    )
}

export function isStrictKeyExchangePacket(type: PacketType): boolean {
    return (
        type === PacketNameToType.SSH_MSG_KEXINIT ||
        type === PacketNameToType.SSH_MSG_NEWKEYS ||
        (type >= 30 && type <= 34)
    )
}
