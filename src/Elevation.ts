import { ProtocolError } from "./packets/Disconnect.js"
import type { SSHExtension } from "./packets/ExtInfo.js"

export const ELEVATION_EXTENSION = "elevation"

export type ElevationPreference = false | "default" | "elevated" | "unelevated"
export type ElevationRequest = Exclude<ElevationPreference, false>

export function normalizeElevationPreference(
    preference: ElevationPreference | undefined,
): ElevationPreference {
    if (preference === undefined || preference === false) return false
    if (preference === "default" || preference === "elevated" || preference === "unelevated") {
        return preference
    }
    throw new TypeError('SSH elevation must be false, "default", "elevated", or "unelevated"')
}

export function elevationExtension(preference: ElevationPreference): SSHExtension | undefined {
    if (preference === false) return undefined
    const value = preference === "elevated" ? "y" : preference === "unelevated" ? "n" : "d"
    return { name: ELEVATION_EXTENSION, value: Buffer.from(value, "ascii") }
}

export function findElevationRequest(
    extensions: readonly SSHExtension[],
): ElevationRequest | undefined {
    const extension = extensions.find(({ name }) => name === ELEVATION_EXTENSION)
    if (!extension) return undefined
    if (extension.value.equals(Buffer.from("y", "ascii"))) return "elevated"
    if (extension.value.equals(Buffer.from("n", "ascii"))) return "unelevated"
    if (extension.value.equals(Buffer.from("d", "ascii"))) return "default"
    throw new ProtocolError('SSH elevation extension value must be "y", "n", or "d"')
}
