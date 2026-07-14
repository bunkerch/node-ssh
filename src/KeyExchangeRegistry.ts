import assert from "node:assert"

import type { KexAlgorithmFactory } from "./algorithms.js"

const registries = new WeakMap<object, ReadonlyMap<string, KexAlgorithmFactory>>()

export function registerKeyExchanges(
    owner: object,
    entries: Iterable<readonly [string, KexAlgorithmFactory]>,
): ReadonlyMap<string, KexAlgorithmFactory> {
    const registry = new Map(entries)
    registries.set(owner, registry)
    return registry
}

export function keyExchangesFor(owner: object): ReadonlyMap<string, KexAlgorithmFactory> {
    const registry = registries.get(owner)
    assert(registry, "SSH key-exchange registry is unavailable")
    return registry
}
