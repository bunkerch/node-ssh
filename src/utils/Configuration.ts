/** Runtime guard for option bags whose fields are read as configuration. */
export function isPlainConfigurationObject(value: unknown): boolean {
    if (typeof value !== "object" || value === null || Array.isArray(value)) return false
    const prototype = Object.getPrototypeOf(value)
    return prototype === Object.prototype || prototype === null
}
