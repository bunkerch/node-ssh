import { KeyExchangeError } from "./algorithms/kex/key-exchange.js"
import { ProtocolError } from "./packets/Disconnect.js"
import type { SSHExtension } from "./packets/ExtInfo.js"
import { readNextNameList, serializeNameList } from "./utils/NameList.js"

export const DELAY_COMPRESSION_EXTENSION = "delay-compression"

export interface DelayCompressionOffers {
    readonly clientToServer: readonly string[]
    readonly serverToClient: readonly string[]
}

export type DelayCompressionAlgorithm = "none" | "zlib"
export interface DelayCompressionOptions {
    readonly clientToServer: readonly DelayCompressionAlgorithm[]
    readonly serverToClient: readonly DelayCompressionAlgorithm[]
}
export type DelayCompressionConfiguration = boolean | DelayCompressionOptions
export type NormalizedDelayCompression = false | Readonly<DelayCompressionOptions>

export interface NegotiatedDelayCompression {
    readonly clientToServer: DelayCompressionAlgorithm
    readonly serverToClient: DelayCompressionAlgorithm
}

function copyOffers(offers: DelayCompressionOffers): Readonly<DelayCompressionOffers> {
    return Object.freeze({
        clientToServer: Object.freeze([...offers.clientToServer]),
        serverToClient: Object.freeze([...offers.serverToClient]),
    })
}

function validateOffers(offers: DelayCompressionOffers): void {
    if (
        offers.clientToServer.includes("zlib@openssh.com") ||
        offers.serverToClient.includes("zlib@openssh.com")
    ) {
        throw new ProtocolError(
            "SSH delay-compression cannot include an algorithm with its own delay semantics",
        )
    }
}

function normalizeAlgorithms(
    algorithms: unknown,
    direction: string,
): readonly DelayCompressionAlgorithm[] {
    if (!Array.isArray(algorithms)) {
        throw new TypeError(`SSH delay-compression ${direction} algorithms must be an array`)
    }
    if (algorithms.length === 0) {
        throw new TypeError(`SSH delay-compression ${direction} algorithms must not be empty`)
    }
    for (const algorithm of algorithms) {
        if (algorithm === "zlib@openssh.com") {
            throw new TypeError(
                "SSH delay-compression cannot include an algorithm with its own delay semantics",
            )
        }
        if (algorithm !== "none" && algorithm !== "zlib") {
            throw new TypeError(`Unsupported SSH delay-compression algorithm: ${String(algorithm)}`)
        }
    }
    return Object.freeze([...algorithms] as DelayCompressionAlgorithm[])
}

export function normalizeDelayCompression(
    configuration: DelayCompressionConfiguration | undefined,
): NormalizedDelayCompression {
    if (configuration === undefined || configuration === false) return false
    if (configuration === true) {
        return copyOffers({
            clientToServer: ["zlib", "none"],
            serverToClient: ["zlib", "none"],
        }) as Readonly<DelayCompressionOptions>
    }
    if (typeof configuration !== "object" || configuration === null) {
        throw new TypeError("SSH delay-compression configuration must be a boolean or options")
    }
    return Object.freeze({
        clientToServer: normalizeAlgorithms(configuration.clientToServer, "client-to-server"),
        serverToClient: normalizeAlgorithms(configuration.serverToClient, "server-to-client"),
    })
}

export function parseDelayCompressionValue(value: Buffer): Readonly<DelayCompressionOffers> {
    try {
        let clientToServer: string[]
        let serverToClient: string[]
        ;[clientToServer, value] = readNextNameList(value)
        ;[serverToClient, value] = readNextNameList(value)
        if (value.length !== 0) {
            throw new ProtocolError("Unexpected data after SSH delay-compression name-lists")
        }
        const offers = copyOffers({ clientToServer, serverToClient })
        validateOffers(offers)
        return offers
    } catch (error) {
        if (error instanceof ProtocolError) throw error
        throw new ProtocolError("Invalid SSH delay-compression extension value")
    }
}

export function delayCompressionExtension(offers: DelayCompressionOptions): SSHExtension {
    const normalized = normalizeDelayCompression(offers)
    if (normalized === false) throw new TypeError("SSH delay-compression offers are required")
    return {
        name: DELAY_COMPRESSION_EXTENSION,
        value: Buffer.concat([
            serializeNameList([...normalized.clientToServer]),
            serializeNameList([...normalized.serverToClient]),
        ]),
    }
}

export function findDelayCompressionOffers(
    extensions: readonly SSHExtension[],
): Readonly<DelayCompressionOffers> | undefined {
    const extension = extensions.find(({ name }) => name === DELAY_COMPRESSION_EXTENSION)
    return extension && parseDelayCompressionValue(extension.value)
}

function firstMutual(
    preferred: readonly string[],
    offered: readonly string[],
): DelayCompressionAlgorithm | undefined {
    for (const name of preferred) {
        if (!offered.includes(name)) continue
        if (name === "none" || name === "zlib") return name
    }
    return undefined
}

export function negotiateDelayCompression(
    client: DelayCompressionOffers | undefined,
    server: DelayCompressionOffers | undefined,
): Readonly<NegotiatedDelayCompression> | undefined {
    if (!client || !server) return undefined
    const clientToServer = firstMutual(client.clientToServer, server.clientToServer)
    const serverToClient = firstMutual(client.serverToClient, server.serverToClient)
    if (!clientToServer || !serverToClient) {
        throw new KeyExchangeError("No mutual SSH delay-compression algorithm")
    }
    return Object.freeze({ clientToServer, serverToClient })
}
