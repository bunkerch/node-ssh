export type AlgorithmMatcher = string | RegExp

export interface AlgorithmListChanges {
    append?: AlgorithmMatcher | readonly AlgorithmMatcher[]
    prepend?: AlgorithmMatcher | readonly AlgorithmMatcher[]
    remove?: AlgorithmMatcher | readonly AlgorithmMatcher[]
}

export type ClientAlgorithmList = readonly string[] | AlgorithmListChanges

export interface ClientAlgorithmOptions {
    kex?: ClientAlgorithmList
    serverHostKey?: ClientAlgorithmList
    cipher?: ClientAlgorithmList
    hmac?: ClientAlgorithmList
    compress?: ClientAlgorithmList
}

export interface ServerAlgorithmOptions {
    kex?: readonly string[]
    serverHostKey?: readonly string[]
    cipher?: readonly string[]
    hmac?: readonly string[]
    compress?: readonly string[]
}

export interface ResolvedAlgorithmOptions {
    kex: readonly string[]
    serverHostKey: readonly string[]
    cipher: readonly string[]
    hmac: readonly string[]
    compress: readonly string[]
}

export interface NegotiatedDirectionAlgorithms {
    cipher: string
    mac: string
    compress: string
    lang: string
}

export interface NegotiatedAlgorithms {
    kex: string
    srvHostKey: string
    cs: NegotiatedDirectionAlgorithms
    sc: NegotiatedDirectionAlgorithms
}

export function resolveClientAlgorithmOptions(
    options: ClientAlgorithmOptions | undefined,
    catalog: ResolvedAlgorithmOptions,
    defaults: ResolvedAlgorithmOptions = catalog,
): ResolvedAlgorithmOptions {
    return Object.freeze({
        kex: resolveList(options?.kex, catalog.kex, defaults.kex),
        serverHostKey: resolveList(
            options?.serverHostKey,
            catalog.serverHostKey,
            defaults.serverHostKey,
        ),
        cipher: resolveList(options?.cipher, catalog.cipher, defaults.cipher),
        hmac: resolveList(options?.hmac, catalog.hmac, defaults.hmac),
        compress: resolveList(options?.compress, catalog.compress, defaults.compress),
    })
}

export function resolveServerAlgorithmOptions(
    options: ServerAlgorithmOptions | undefined,
    catalog: ResolvedAlgorithmOptions,
    defaults: ResolvedAlgorithmOptions = catalog,
): ResolvedAlgorithmOptions {
    return Object.freeze({
        kex: resolveExactList(options?.kex, catalog.kex, defaults.kex),
        serverHostKey: resolveExactList(
            options?.serverHostKey,
            catalog.serverHostKey,
            defaults.serverHostKey,
        ),
        cipher: resolveExactList(options?.cipher, catalog.cipher, defaults.cipher),
        hmac: resolveExactList(options?.hmac, catalog.hmac, defaults.hmac),
        compress: resolveExactList(options?.compress, catalog.compress, defaults.compress),
    })
}

function resolveList(
    configured: ClientAlgorithmList | undefined,
    supported: readonly string[],
    defaults: readonly string[],
): readonly string[] {
    validateDefaults(defaults, supported)
    if (Array.isArray(configured)) return resolveExactList(configured, supported, defaults)
    if (!configured) return Object.freeze([...defaults])

    let result = [...defaults]
    for (const [operation, configuredMatchers] of Object.entries(configured)) {
        if (operation !== "remove" && operation !== "prepend" && operation !== "append") {
            throw new Error(`Invalid SSH algorithm list operation: ${operation}`)
        }
        const matchers = Array.isArray(configuredMatchers)
            ? configuredMatchers
            : [configuredMatchers]
        if (operation === "remove") {
            result = result.filter((name) => !matchers.some((matcher) => matches(matcher, name)))
            continue
        }
        for (const matcher of matchers) {
            if (typeof matcher === "string" && matcher.length > 0 && !supported.includes(matcher)) {
                throw new Error(`Unsupported algorithm: ${matcher}`)
            }
        }
        const additions = supported.filter(
            (name) => matchers.some((matcher) => matches(matcher, name)) && !result.includes(name),
        )
        if (operation === "prepend") result.unshift(...additions)
        else if (operation === "append") result.push(...additions)
    }
    if (result.length === 0) throw new Error("SSH algorithm list must not be empty")
    return Object.freeze(result)
}

function resolveExactList(
    configured: readonly string[] | undefined,
    supported: readonly string[],
    defaults: readonly string[],
): readonly string[] {
    validateDefaults(defaults, supported)
    if (!configured) return Object.freeze([...defaults])
    if (configured.length === 0) throw new Error("SSH algorithm list must not be empty")
    for (const name of configured) {
        if (!supported.includes(name)) throw new Error(`Unsupported algorithm: ${name}`)
    }
    return Object.freeze([...configured])
}

function validateDefaults(defaults: readonly string[], supported: readonly string[]): void {
    if (defaults.length === 0 || defaults.some((name) => !supported.includes(name))) {
        throw new Error("Invalid SSH default algorithm list")
    }
}

function matches(matcher: AlgorithmMatcher, name: string): boolean {
    if (typeof matcher === "string") return matcher === name
    matcher.lastIndex = 0
    return matcher.test(name)
}
