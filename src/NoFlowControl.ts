import { ProtocolError } from "./packets/Disconnect.js"
import type { SSHExtension } from "./packets/ExtInfo.js"

export const NO_FLOW_CONTROL_EXTENSION = "no-flow-control"

export type NoFlowControlPreference = false | "preferred" | "supported"
export type NoFlowControlValue = "p" | "s"

export function normalizeNoFlowControlPreference(
    preference: NoFlowControlPreference | undefined,
): NoFlowControlPreference {
    if (preference === undefined || preference === false) return false
    if (preference === "preferred" || preference === "supported") return preference
    throw new TypeError('SSH no-flow-control must be false, "supported", or "preferred"')
}

export function noFlowControlValue(
    preference: NoFlowControlPreference,
): NoFlowControlValue | undefined {
    if (preference === false) return undefined
    return preference === "preferred" ? "p" : "s"
}

export function noFlowControlExtension(
    preference: NoFlowControlPreference,
): SSHExtension | undefined {
    const value = noFlowControlValue(preference)
    return value && { name: NO_FLOW_CONTROL_EXTENSION, value: Buffer.from(value, "ascii") }
}

export function findNoFlowControlValue(
    extensions: readonly SSHExtension[],
): NoFlowControlValue | undefined {
    const extension = extensions.find(({ name }) => name === NO_FLOW_CONTROL_EXTENSION)
    if (!extension) return undefined
    if (extension.value.equals(Buffer.from("p", "ascii"))) return "p"
    if (extension.value.equals(Buffer.from("s", "ascii"))) return "s"
    throw new ProtocolError('SSH no-flow-control extension value must be "p" or "s"')
}

export function negotiateNoFlowControl(
    localValue: NoFlowControlValue | undefined,
    peerExtensions: readonly SSHExtension[],
): boolean {
    if (localValue === undefined) return false
    const peerValue = findNoFlowControlValue(peerExtensions)
    return peerValue !== undefined && (localValue === "p" || peerValue === "p")
}
